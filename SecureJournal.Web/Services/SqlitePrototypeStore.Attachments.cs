using Microsoft.Data.Sqlite;
using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public sealed partial class SqlitePrototypeStore
{
    // This additive, idempotent upgrade also runs for databases created by older versions.
    private static void EnsureAttachmentSchema(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS journal_attachments (
                attachment_id TEXT NOT NULL PRIMARY KEY,
                entry_id TEXT NOT NULL REFERENCES journal_entries(record_id) ON DELETE CASCADE,
                file_name_ciphertext TEXT NOT NULL,
                size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 5242880),
                sha256 TEXT NOT NULL,
                content_ciphertext TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_journal_attachments_entry_id ON journal_attachments(entry_id);
            """;
        command.ExecuteNonQuery();
    }

    public IReadOnlyList<JournalAttachmentRecord> LoadJournalAttachmentMetadata(Guid entryId)
        => LoadJournalAttachmentMetadata(new[] { entryId });

    public IReadOnlyList<JournalAttachmentRecord> LoadJournalAttachmentMetadata(IReadOnlyCollection<Guid> entryIds)
    {
        if (entryIds.Count == 0) return Array.Empty<JournalAttachmentRecord>();
        Initialize();
        using var connection = OpenConnectionInternal();
        var records = new List<JournalAttachmentRecord>();
        // Keep each query below even older SQLite parameter limits. Reuse one
        // connection for the whole list and never select encrypted file bodies.
        foreach (var batch in entryIds.Distinct().Chunk(500))
        {
            using var command = connection.CreateCommand();
            var parameters = batch.Select((_, i) => $"$entry{i}").ToArray();
            command.CommandText = $"SELECT attachment_id, entry_id, file_name_ciphertext, size_bytes, sha256 FROM journal_attachments WHERE entry_id IN ({string.Join(",", parameters)}) ORDER BY attachment_id;";
            for (var i = 0; i < batch.Length; i++) command.Parameters.AddWithValue(parameters[i], batch[i].ToString("D"));
            using var reader = command.ExecuteReader();
            while (reader.Read()) records.Add(ReadAttachment(reader, includeContent: false));
        }
        return records;
    }

    public JournalAttachmentRecord? LoadJournalAttachment(Guid attachmentId, bool includeContent = true)
    {
        Initialize();
        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText = includeContent
            ? "SELECT attachment_id, entry_id, file_name_ciphertext, size_bytes, sha256, content_ciphertext FROM journal_attachments WHERE attachment_id = $id;"
            : "SELECT attachment_id, entry_id, file_name_ciphertext, size_bytes, sha256 FROM journal_attachments WHERE attachment_id = $id;";
        command.Parameters.AddWithValue("$id", attachmentId.ToString("D"));
        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadAttachment(reader, includeContent) : null;
    }

    private static JournalAttachmentRecord ReadAttachment(SqliteDataReader reader, bool includeContent)
        => new(Guid.Parse(reader.GetString(0)), Guid.Parse(reader.GetString(1)), reader.GetString(2),
            reader.GetInt64(3), reader.GetString(4), includeContent ? reader.GetString(5) : string.Empty);

    public void CreateJournalEntryWithAttachments(JournalEntryRecord record, IReadOnlyList<JournalAttachmentRecord> attachments, IReadOnlyList<AuditLogRecord> audits)
    {
        Initialize();
        using var connection = OpenConnectionInternal();
        using var transaction = connection.BeginTransaction();
        WriteJournalEntry(connection, transaction, record);
        foreach (var attachment in attachments)
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO journal_attachments(attachment_id, entry_id, file_name_ciphertext, size_bytes, sha256, content_ciphertext)
                VALUES($id, $entry_id, $name, $size, $sha256, $content);
                """;
            command.Parameters.AddWithValue("$id", attachment.AttachmentId.ToString("D"));
            command.Parameters.AddWithValue("$entry_id", attachment.EntryId.ToString("D"));
            command.Parameters.AddWithValue("$name", attachment.FileNameCiphertext);
            command.Parameters.AddWithValue("$size", attachment.SizeBytes);
            command.Parameters.AddWithValue("$sha256", attachment.Sha256);
            command.Parameters.AddWithValue("$content", attachment.ContentCiphertext);
            command.ExecuteNonQuery();
        }
        foreach (var audit in audits) WriteAuditLog(connection, transaction, audit);
        transaction.Commit();
    }
}
