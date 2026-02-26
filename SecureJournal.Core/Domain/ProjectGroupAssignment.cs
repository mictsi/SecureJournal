namespace SecureJournal.Core.Domain;

public sealed record ProjectGroupAssignment(
    Guid ProjectId,
    Guid GroupId);
