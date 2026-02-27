using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public interface IAuditLogRecordFactory
{
    AuditLogRecord Create(
        AppUser? actor,
        AuditActionType action,
        AuditEntityType entityType,
        string? entityId,
        Guid? projectId,
        AuditOutcome outcome,
        string details);
}
