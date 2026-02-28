using SecureJournal.Core.Domain;

namespace SecureJournal.Core.Application;

public sealed record UserContext(
    Guid UserId,
    string Username,
    string DisplayName,
    AppRole Role,
    IReadOnlyList<Guid> GroupIds);

public sealed record ProjectOverview(
    Guid ProjectId,
    string Code,
    string Name,
    string Description,
    string ProjectOwnerName,
    string ProjectEmail,
    string ProjectPhone,
    string ProjectOwner,
    string Department,
    IReadOnlyList<string> AssignedGroups,
    bool HasAccessForCurrentUser);

public sealed record GroupOverview(
    Guid GroupId,
    string Name,
    string Description,
    IReadOnlyList<string> Members,
    IReadOnlyList<string> ProjectCodes);

public sealed record UserOverview(
    Guid UserId,
    string Username,
    string DisplayName,
    AppRole Role,
    bool IsLocalAccount,
    IReadOnlyList<string> Groups,
    IReadOnlyList<AppRole> Roles,
    bool IsDisabled = false);

public sealed record JournalEntryView(
    Guid RecordId,
    Guid ProjectId,
    string ProjectCode,
    string ProjectName,
    DateTime CreatedAtUtc,
    string CreatedBy,
    string Action,
    string Subject,
    string Description,
    string Notes,
    bool IsSoftDeleted,
    DateTime? DeletedAtUtc,
    string? DeletedBy,
    string? DeleteReason,
    string FullRecordChecksum);

public sealed record AuditRelatedJournalEntryView(
    Guid RecordId,
    string ProjectCode,
    DateTime CreatedAtUtc,
    string CreatedBy,
    string Action,
    string Subject,
    string Description,
    string Notes,
    bool IsSoftDeleted);

public sealed record AuditLogView(
    Guid AuditId,
    DateTime TimestampUtc,
    string ActorUsername,
    AuditActionType Action,
    AuditEntityType EntityType,
    string? EntityId,
    Guid? ProjectId,
    string? ProjectCode,
    AuditOutcome Outcome,
    string Details,
    string DetailsChecksum,
    AuditRelatedJournalEntryView? RelatedJournalEntry);

public sealed record AuditChecksumValidationResult(
    Guid AuditId,
    bool IsValid,
    string StoredChecksum,
    string ComputedChecksum,
    string Message);

public sealed record DashboardSummary(
    int TotalProjects,
    int AccessibleProjects,
    int VisibleJournalEntries,
    int SoftDeletedEntriesVisible,
    int AuditEventsVisible,
    int Users,
    int Groups);
