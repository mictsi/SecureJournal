namespace SecureJournal.Core.Domain;

public sealed record Project(
    Guid ProjectId,
    string Code,
    string Name,
    string Description,
    string ProjectEmail,
    string ProjectPhone,
    string ProjectOwner,
    string Department);
