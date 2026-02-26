namespace SecureJournal.Core.Domain;

public sealed record AuditLogRecord(
    Guid AuditId,
    DateTime TimestampUtc,
    Guid? ActorUserId,
    string ActorUsername,
    AuditActionType Action,
    AuditEntityType EntityType,
    string? EntityId,
    Guid? ProjectId,
    AuditOutcome Outcome,
    string DetailsCiphertext,
    string DetailsChecksum);
