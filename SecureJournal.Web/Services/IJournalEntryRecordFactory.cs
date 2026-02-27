using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public interface IJournalEntryRecordFactory
{
    JournalEntryRecord Create(
        Guid projectId,
        Guid createdByUserId,
        string createdByUsername,
        DateTime createdAtUtc,
        string action,
        string subject,
        string description,
        string notes,
        string result);
}
