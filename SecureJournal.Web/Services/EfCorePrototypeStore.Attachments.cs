using Microsoft.EntityFrameworkCore;
using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;
using SecureJournal.Web.Infrastructure.Persistence;

namespace SecureJournal.Web.Services;

public sealed partial class EfCorePrototypeStore
{
    private static void EnsureAttachmentSchema(SecureJournalAppDbContext db)
    {
        // EnsureCreated does not update existing tables. Keep the old encrypted
        // rows intact while raising the database-enforced per-file limit.
        if (db.Database.IsSqlServer())
        {
            // Only the compiled numeric size limit is interpolated into this DDL.
            var upgradeSql = $"""
                SET XACT_ABORT ON;
                BEGIN TRY
                BEGIN TRANSACTION;
                IF OBJECT_ID('journal_attachments', 'U') IS NULL
                BEGIN
                    CREATE TABLE journal_attachments (
                        attachment_id uniqueidentifier NOT NULL PRIMARY KEY,
                        entry_id uniqueidentifier NOT NULL REFERENCES journal_entries(record_id) ON DELETE CASCADE,
                        file_name_ciphertext nvarchar(max) NOT NULL,
                        size_bytes bigint NOT NULL CONSTRAINT CK_journal_attachments_size CHECK (size_bytes >= 0 AND size_bytes <= {AttachmentLimits.MaxFileBytes}),
                        sha256 nvarchar(64) NOT NULL,
                        content_ciphertext nvarchar(max) NOT NULL
                    );
                END
                DECLARE @constraintName sysname, @definition nvarchar(max), @sql nvarchar(max);
                DECLARE legacyAttachmentLimits CURSOR LOCAL FAST_FORWARD FOR
                    SELECT name, definition FROM sys.check_constraints
                    WHERE parent_object_id = OBJECT_ID('journal_attachments')
                      AND definition LIKE '%size_bytes%' AND definition LIKE '%5242880%';
                OPEN legacyAttachmentLimits;
                FETCH NEXT FROM legacyAttachmentLimits INTO @constraintName, @definition;
                WHILE @@FETCH_STATUS = 0
                BEGIN
                    SET @sql = N'ALTER TABLE journal_attachments DROP CONSTRAINT ' + QUOTENAME(@constraintName)
                        + N'; ALTER TABLE journal_attachments WITH CHECK ADD CONSTRAINT ' + QUOTENAME(@constraintName)
                        + N' CHECK ' + REPLACE(@definition, '5242880', '{AttachmentLimits.MaxFileBytes}') + N';';
                    EXEC sp_executesql @sql;
                    FETCH NEXT FROM legacyAttachmentLimits INTO @constraintName, @definition;
                END
                CLOSE legacyAttachmentLimits;
                DEALLOCATE legacyAttachmentLimits;
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix_journal_attachments_entry_id' AND object_id = OBJECT_ID('journal_attachments'))
                    CREATE INDEX ix_journal_attachments_entry_id ON journal_attachments(entry_id);
                COMMIT TRANSACTION;
                END TRY
                BEGIN CATCH
                    IF XACT_STATE() <> 0 ROLLBACK TRANSACTION;
                    THROW;
                END CATCH;
                """;
            db.Database.ExecuteSqlRaw(upgradeSql);
        }
        else if (db.Database.IsNpgsql())
        {
            // Only the compiled numeric size limit is interpolated into this DDL.
            var upgradeSql = $"""
                DO $attachment_upgrade$
                DECLARE legacy_limit record;
                BEGIN
                CREATE TABLE IF NOT EXISTS journal_attachments (
                    attachment_id uuid NOT NULL PRIMARY KEY,
                    entry_id uuid NOT NULL REFERENCES journal_entries(record_id) ON DELETE CASCADE,
                    file_name_ciphertext text NOT NULL,
                    size_bytes bigint NOT NULL CONSTRAINT "CK_journal_attachments_size" CHECK (size_bytes >= 0 AND size_bytes <= {AttachmentLimits.MaxFileBytes}),
                    sha256 varchar(64) NOT NULL,
                    content_ciphertext text NOT NULL
                );
                FOR legacy_limit IN
                    SELECT conname, pg_get_constraintdef(oid) AS definition FROM pg_constraint
                    WHERE conrelid = 'journal_attachments'::regclass AND contype = 'c'
                      AND pg_get_constraintdef(oid) LIKE '%size_bytes%' AND pg_get_constraintdef(oid) LIKE '%5242880%'
                LOOP
                    EXECUTE format('ALTER TABLE journal_attachments DROP CONSTRAINT %I', legacy_limit.conname);
                    EXECUTE format('ALTER TABLE journal_attachments ADD CONSTRAINT %I %s', legacy_limit.conname,
                        replace(legacy_limit.definition, '5242880', '{AttachmentLimits.MaxFileBytes}'));
                END LOOP;
                CREATE INDEX IF NOT EXISTS ix_journal_attachments_entry_id ON journal_attachments(entry_id);
                END;
                $attachment_upgrade$;
                """;
            db.Database.ExecuteSqlRaw(upgradeSql);
        }
        else if (db.Database.IsSqlite())
        {
            JournalAttachmentSchema.EnsureSqlite(db.Database.GetDbConnection());
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
