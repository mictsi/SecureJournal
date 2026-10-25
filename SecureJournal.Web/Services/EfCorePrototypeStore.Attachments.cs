using Microsoft.EntityFrameworkCore;
using SecureJournal.Core.Domain;
using SecureJournal.Web.Infrastructure.Persistence;

namespace SecureJournal.Web.Services;

public sealed partial class EfCorePrototypeStore
{
    private static void EnsureAttachmentSchema(SecureJournalAppDbContext db)
    {
        // EnsureCreated does not add tables to an existing database. Apply this
        // additive upgrade on all supported relational providers explicitly.
        if (db.Database.IsSqlServer())
        {
            db.Database.ExecuteSqlRaw("""
                IF OBJECT_ID('journal_attachments', 'U') IS NULL
                BEGIN
                    CREATE TABLE journal_attachments (
                        attachment_id uniqueidentifier NOT NULL PRIMARY KEY,
                        entry_id uniqueidentifier NOT NULL REFERENCES journal_entries(record_id) ON DELETE CASCADE,
                        file_name_ciphertext nvarchar(max) NOT NULL,
                        size_bytes bigint NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 5242880),
                        sha256 nvarchar(64) NOT NULL,
                        content_ciphertext nvarchar(max) NOT NULL
                    );
                END
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix_journal_attachments_entry_id' AND object_id = OBJECT_ID('journal_attachments'))
                    CREATE INDEX ix_journal_attachments_entry_id ON journal_attachments(entry_id);
                """);
        }
        else if (db.Database.IsNpgsql())
        {
            db.Database.ExecuteSqlRaw("""
                CREATE TABLE IF NOT EXISTS journal_attachments (
                    attachment_id uuid NOT NULL PRIMARY KEY,
                    entry_id uuid NOT NULL REFERENCES journal_entries(record_id) ON DELETE CASCADE,
                    file_name_ciphertext text NOT NULL,
                    size_bytes bigint NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 5242880),
                    sha256 varchar(64) NOT NULL,
                    content_ciphertext text NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_journal_attachments_entry_id ON journal_attachments(entry_id);
                """);
        }
        else if (db.Database.IsSqlite())
        {
            db.Database.ExecuteSqlRaw("""
                CREATE TABLE IF NOT EXISTS journal_attachments (
                    attachment_id TEXT NOT NULL PRIMARY KEY,
                    entry_id TEXT NOT NULL REFERENCES journal_entries(record_id) ON DELETE CASCADE,
                    file_name_ciphertext TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 5242880),
                    sha256 TEXT NOT NULL,
                    content_ciphertext TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_journal_attachments_entry_id ON journal_attachments(entry_id);
                """);
        }
    }

    public IReadOnlyList<JournalAttachmentRecord> LoadJournalAttachmentMetadata(Guid entryId)
        => LoadJournalAttachmentMetadata(new[] { entryId });

    public IReadOnlyList<JournalAttachmentRecord> LoadJournalAttachmentMetadata(IReadOnlyCollection<Guid> entryIds)
    {
        if (entryIds.Count == 0) return Array.Empty<JournalAttachmentRecord>();
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var records = new List<JournalAttachmentRecord>();
        foreach (var batch in entryIds.Distinct().Chunk(500))
        {
            records.AddRange(db.JournalAttachments.AsNoTracking().Where(a => batch.Contains(a.EntryId)).OrderBy(a => a.AttachmentId)
                .Select(a => new JournalAttachmentRecord(a.AttachmentId, a.EntryId, a.FileNameCiphertext, a.SizeBytes, a.Sha256, ""))
                .ToList());
        }
        return records;
    }

    public JournalAttachmentRecord? LoadJournalAttachment(Guid attachmentId, bool includeContent = true)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.JournalAttachments.AsNoTracking().Where(a => a.AttachmentId == attachmentId)
            .Select(a => new JournalAttachmentRecord(a.AttachmentId, a.EntryId, a.FileNameCiphertext, a.SizeBytes, a.Sha256, includeContent ? a.ContentCiphertext : ""))
            .SingleOrDefault();
    }

    public void CreateJournalEntryWithAttachments(JournalEntryRecord record, IReadOnlyList<JournalAttachmentRecord> attachments, IReadOnlyList<AuditLogRecord> audits)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var entry = new JournalEntryEntity { RecordId = record.RecordId };
        Map(entry, record);
        db.JournalEntries.Add(entry);
        db.JournalAttachments.AddRange(attachments.Select(a => new JournalAttachmentEntity
        {
            AttachmentId = a.AttachmentId, EntryId = a.EntryId, FileNameCiphertext = a.FileNameCiphertext,
            SizeBytes = a.SizeBytes, Sha256 = a.Sha256, ContentCiphertext = a.ContentCiphertext
        }));
        db.AuditLogs.AddRange(audits.Select(a => new AuditLogEntity
        {
            AuditId = a.AuditId, TimestampUtc = a.TimestampUtc.ToUniversalTime(), ActorUserId = a.ActorUserId,
            ActorUsername = a.ActorUsername, Action = (int)a.Action, EntityType = (int)a.EntityType,
            EntityId = a.EntityId, ProjectId = a.ProjectId, Outcome = (int)a.Outcome,
            DetailsCiphertext = a.DetailsCiphertext, DetailsChecksum = a.DetailsChecksum
        }));
        // One SaveChanges is a transaction: an upload/audit failure cannot leave a partial entry.
        db.SaveChanges();
    }
}
