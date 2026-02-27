using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public interface IRecordViewMapper
{
    JournalEntryView MapJournalEntry(JournalEntryRecord record, IReadOnlyCollection<Project> projects);

    AuditLogView MapAuditLog(
        AuditLogRecord record,
        IReadOnlyCollection<Project> projects,
        IReadOnlyCollection<JournalEntryRecord> journalEntries);
}
