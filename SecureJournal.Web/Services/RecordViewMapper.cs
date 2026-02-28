using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;

namespace SecureJournal.Web.Services;

public sealed class RecordViewMapper : IRecordViewMapper
{
    private readonly IJournalFieldEncryptor _journalEncryptor;
    private readonly IAuditFieldEncryptor _auditEncryptor;

    public RecordViewMapper(IJournalFieldEncryptor journalEncryptor, IAuditFieldEncryptor auditEncryptor)
    {
        _journalEncryptor = journalEncryptor;
        _auditEncryptor = auditEncryptor;
    }

    public JournalEntryView MapJournalEntry(JournalEntryRecord record, IReadOnlyCollection<Project> projects)
    {
        var project = projects.First(p => p.ProjectId == record.ProjectId);
        return new JournalEntryView(
            RecordId: record.RecordId,
            ProjectId: record.ProjectId,
            ProjectCode: project.Code,
            ProjectName: project.Name,
            CreatedAtUtc: record.CreatedAtUtc,
            CreatedBy: record.CreatedByUsername,
            Subject: _journalEncryptor.Decrypt(record.SubjectCiphertext),
            Description: _journalEncryptor.Decrypt(record.DescriptionCiphertext),
            Notes: _journalEncryptor.Decrypt(record.NotesCiphertext),
            IsSoftDeleted: record.IsSoftDeleted,
            DeletedAtUtc: record.SoftDelete?.DeletedAtUtc,
            DeletedBy: record.SoftDelete?.DeletedByUsername,
            DeleteReason: record.SoftDelete?.Reason,
            FullRecordChecksum: record.FullRecordChecksum);
    }

    public AuditLogView MapAuditLog(
        AuditLogRecord record,
        IReadOnlyCollection<Project> projects,
        IReadOnlyCollection<JournalEntryRecord> journalEntries)
    {
        var project = record.ProjectId.HasValue
            ? projects.FirstOrDefault(p => p.ProjectId == record.ProjectId.Value)
            : null;

        return new AuditLogView(
            AuditId: record.AuditId,
            TimestampUtc: record.TimestampUtc,
            ActorUsername: record.ActorUsername,
            Action: record.Action,
            EntityType: record.EntityType,
            EntityId: record.EntityId,
            ProjectId: record.ProjectId,
            ProjectCode: project?.Code,
            Outcome: record.Outcome,
            Details: _auditEncryptor.Decrypt(record.DetailsCiphertext),
            DetailsChecksum: record.DetailsChecksum,
            RelatedJournalEntry: TryMapRelatedJournalEntry(record, projects, journalEntries));
    }

    private AuditRelatedJournalEntryView? TryMapRelatedJournalEntry(
        AuditLogRecord auditRecord,
        IReadOnlyCollection<Project> projects,
        IReadOnlyCollection<JournalEntryRecord> journalEntries)
    {
        if (auditRecord.EntityType != AuditEntityType.JournalEntry ||
            !Guid.TryParse(auditRecord.EntityId, out var recordId))
        {
            return null;
        }

        var journalRecord = journalEntries.FirstOrDefault(j => j.RecordId == recordId);
        if (journalRecord is null)
        {
            return null;
        }

        var project = projects.FirstOrDefault(p => p.ProjectId == journalRecord.ProjectId);
        return new AuditRelatedJournalEntryView(
            RecordId: journalRecord.RecordId,
            ProjectCode: project?.Code ?? "(unknown)",
            CreatedAtUtc: journalRecord.CreatedAtUtc,
            CreatedBy: journalRecord.CreatedByUsername,
            Subject: _journalEncryptor.Decrypt(journalRecord.SubjectCiphertext),
            Description: _journalEncryptor.Decrypt(journalRecord.DescriptionCiphertext),
            Notes: _journalEncryptor.Decrypt(journalRecord.NotesCiphertext),
            IsSoftDeleted: journalRecord.IsSoftDeleted);
    }
}
