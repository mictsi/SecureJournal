using System.ComponentModel.DataAnnotations;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public sealed partial class SecureJournalAppService
{
    private sealed record AttachmentPayload(Guid AttachmentId, Guid EntryId, string FileName, string Sha256, byte[] Content);

    private IReadOnlyList<JournalAttachmentRecord> PrepareAttachments(Guid entryId, IReadOnlyList<JournalAttachmentUpload>? uploads)
    {
        if (uploads is null || uploads.Count == 0) return Array.Empty<JournalAttachmentRecord>();
        if (uploads.Count > AttachmentLimits.MaxFilesPerEntry)
            throw new ValidationException($"Attach up to {AttachmentLimits.MaxFilesPerEntry} files per entry.");
        long total = 0;
        foreach (var upload in uploads)
        {
            if (upload?.Content is null || upload.Content.LongLength > AttachmentLimits.MaxFileBytes)
                throw new ValidationException($"Each file must be {AttachmentLimits.MaxFileBytes / (1024 * 1024)} MiB or smaller.");
            total += upload.Content.LongLength;
        }
        if (total > AttachmentLimits.MaxTotalBytes)
            throw new ValidationException("Files for one entry must total 20 MiB or less.");

        return uploads.Select(upload =>
        {
            var id = Guid.NewGuid();
            var name = SafeAttachmentFileName(upload.FileName);
            var sha256 = Convert.ToHexString(SHA256.HashData(upload.Content));
            // Bind IDs, name and checksum inside authenticated encryption. Swapping
            // ciphertext between rows cannot silently attach another entry's file.
            var payload = new AttachmentPayload(id, entryId, name, sha256, upload.Content);
            return new JournalAttachmentRecord(id, entryId, _attachmentEncryptor.Encrypt(name), upload.Content.LongLength,
                sha256, _attachmentEncryptor.Encrypt(JsonSerializer.Serialize(payload)));
        }).ToList();
    }

    internal static string SafeAttachmentFileName(string? input)
    {
        var name = (input ?? string.Empty).Replace('\\', '/').Split('/').Last();
        name = new string(name.Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_' or ' ' ? c : '_').ToArray());
        name = name.Trim(' ', '.');
        if (name.Length > 120) name = name[..120].TrimEnd(' ', '.');
        if (string.IsNullOrEmpty(name)) name = "attachment";
        var stem = name.Split('.')[0];
        if (new[] { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" }.Contains(stem, StringComparer.OrdinalIgnoreCase))
            name = "file-" + name;
        return name;
    }

    private IReadOnlyList<JournalEntryView> MapJournalEntriesWithAttachments(IReadOnlyList<JournalEntryRecord> records)
    {
        var attachments = _sqliteStore.LoadJournalAttachmentMetadata(records.Select(r => r.RecordId).ToArray())
            .ToLookup(a => a.EntryId);
        return records.Select(record => _recordViewMapper.MapJournalEntry(record, _projects) with
        {
            Attachments = attachments[record.RecordId].Select(MapAttachment).ToList()
        }).ToList();
    }

    private JournalAttachmentView MapAttachment(JournalAttachmentRecord record)
        => new(record.AttachmentId, record.EntryId, SafeAttachmentFileName(_attachmentEncryptor.Decrypt(record.FileNameCiphertext)), record.SizeBytes, record.Sha256);

    private JournalEntryRecord RequireAttachmentAccess(AppUser actor, Guid entryId)
    {
        var entry = _journalEntries.FirstOrDefault(e => e.RecordId == entryId);
        if (entry is null || IsAuditorOnly(actor) || !GetReadableProjectIds(actor).Contains(entry.ProjectId)
            || (entry.IsSoftDeleted && !CanSeeSoftDeletedEntries(actor)))
            throw new UnauthorizedAccessException("This file is unavailable or you do not have access to it.");
        return entry;
    }

    public IReadOnlyList<JournalAttachmentView> GetJournalAttachments(Guid entryId)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            RequireAttachmentAccess(actor, entryId);
            return _sqliteStore.LoadJournalAttachmentMetadata(entryId).Select(MapAttachment).ToList();
        }
    }

    public JournalAttachmentDownload DownloadJournalAttachment(Guid attachmentId)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            var attachment = _sqliteStore.LoadJournalAttachment(attachmentId, includeContent: false)
                ?? throw new UnauthorizedAccessException("This file is unavailable or you do not have access to it.");
            JournalEntryRecord entry;
            try { entry = RequireAttachmentAccess(actor, attachment.EntryId); }
            catch (UnauthorizedAccessException)
            {
                AppendAudit(actor, AuditActionType.AccessDenied, AuditEntityType.Attachment, attachmentId.ToString(), null,
                    AuditOutcome.Denied, "Attachment download denied.");
                throw;
            }
            var stored = _sqliteStore.LoadJournalAttachment(attachmentId)
                ?? throw new InvalidOperationException("This file is no longer available.");
            if (stored.EntryId != attachment.EntryId) throw new CryptographicException("Attachment entry mismatch.");
            var file = DecryptAttachment(stored);
            AppendAudit(actor, AuditActionType.Read, AuditEntityType.Attachment, attachmentId.ToString(), entry.ProjectId,
                AuditOutcome.Success, $"File downloaded from journal entry {entry.RecordId:D} ({attachment.SizeBytes} bytes).");
            return file;
        }
    }

    private JournalAttachmentDownload DecryptAttachment(JournalAttachmentRecord record)
    {
        if (record.SizeBytes < 0 || record.SizeBytes > AttachmentLimits.MaxFileBytes
            || record.ContentCiphertext.Length > AttachmentLimits.MaxFileBytes * 3)
            throw new InvalidOperationException("The stored file exceeds the supported size limit.");
        var payload = JsonSerializer.Deserialize<AttachmentPayload>(_attachmentEncryptor.Decrypt(record.ContentCiphertext));
        if (payload is null || payload.Content is null || payload.AttachmentId != record.AttachmentId || payload.EntryId != record.EntryId
            || payload.Content.LongLength != record.SizeBytes || payload.Sha256 != record.Sha256
            || payload.FileName != _attachmentEncryptor.Decrypt(record.FileNameCiphertext)
            || Convert.ToHexString(SHA256.HashData(payload.Content)) != record.Sha256)
            throw new CryptographicException("The stored file failed its integrity check.");
        return new JournalAttachmentDownload(SafeAttachmentFileName(payload.FileName), payload.Content);
    }

    private static bool MatchesExportFilter(JournalEntryRecord entry, JournalExportFilter filter)
        => (!filter.ProjectId.HasValue || entry.ProjectId == filter.ProjectId.Value)
            && (!filter.FromUtc.HasValue || entry.CreatedAtUtc >= filter.FromUtc.Value)
            && (!filter.ToUtc.HasValue || entry.CreatedAtUtc <= filter.ToUtc.Value)
            && (filter.IncludeSoftDeleted || !entry.IsSoftDeleted);

    private ExportFileResult ExportJournalArchive(JournalExportRequest request, IReadOnlyList<JournalEntryView> rows, AppUser actor)
    {
        var metadata = rows.SelectMany(r => r.Attachments).ToList();
        if (metadata.Count > AttachmentLimits.MaxExportFiles || metadata.Any(a => a.SizeBytes < 0 || a.SizeBytes > AttachmentLimits.MaxFileBytes)
            || metadata.Sum(a => a.SizeBytes) > AttachmentLimits.MaxExportBytes)
            throw new ValidationException("File exports are limited to 50 MiB and 1,000 files. Choose a smaller date range or one project.");
        var content = request.Format == ExportFormat.Csv
            ? _exportFormatter.BuildJournalCsv(request.Filter, rows)
            : _exportFormatter.BuildJournalJson(request.Filter, rows);
        if (Encoding.UTF8.GetByteCount(content) > 10 * 1024 * 1024)
            throw new ValidationException("The journal text in this export exceeds 10 MiB. Choose a smaller date range or one project.");

        using var output = new MemoryStream();
        var manifest = new List<object>();
        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            var journalPath = request.Format == ExportFormat.Csv ? "journal.csv" : "journal.json";
            using (var writer = new StreamWriter(archive.CreateEntry(journalPath).Open(), new UTF8Encoding(false))) writer.Write(content);
            foreach (var file in metadata)
            {
                var record = _sqliteStore.LoadJournalAttachment(file.AttachmentId)
                    ?? throw new InvalidOperationException("A file changed while preparing the export. Please try again.");
                if (record.EntryId != file.EntryId) throw new CryptographicException("Attachment entry mismatch.");
                var download = DecryptAttachment(record);
                var path = $"attachments/{file.EntryId:N}/{file.AttachmentId:N}-{download.FileName}";
                using (var destination = archive.CreateEntry(path, CompressionLevel.NoCompression).Open()) destination.Write(download.Content);
                manifest.Add(new { file.AttachmentId, file.EntryId, FileName = download.FileName, file.SizeBytes, file.Sha256, Path = path });
            }
            using var manifestWriter = new StreamWriter(archive.CreateEntry("manifest.json").Open(), new UTF8Encoding(false));
            manifestWriter.Write(JsonSerializer.Serialize(new
            {
                Version = 1, JournalFile = journalPath, EntryCount = rows.Count, AttachmentCount = metadata.Count,
                Notice = "This archive contains decrypted journal data and files. Store it securely.", Files = manifest
            }, new JsonSerializerOptions { WriteIndented = true }));
        }
        AppendAudit(actor, AuditActionType.Export, AuditEntityType.Export, null, request.Filter.ProjectId, AuditOutcome.Success,
            $"Journal ZIP export generated ({request.Format}) with {rows.Count} entries and {metadata.Count} files.");
        return new ExportFileResult($"journal-export-{DateTime.UtcNow:yyyyMMdd-HHmmss}.zip", "application/zip", string.Empty, rows.Count,
            $"Journal archive with {rows.Count} entries and {metadata.Count} files.") { ContentBytes = output.ToArray() };
    }
}
