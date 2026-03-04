namespace SecureJournal.Core.Domain;

public sealed record Project(
    Guid ProjectId,
    string Code,
    string Name,
    string Description,
    string ProjectEmail,
    string ProjectPhone,
    string ProjectOwner,
    string Department,
    bool IsDisabled = false,
    bool IsSoftDeleted = false,
    DateTime? DeletedAtUtc = null,
    DateTime? ScheduledDeletionAtUtc = null);
