namespace SecureJournal.Core.Domain;

public sealed record Group(
    Guid GroupId,
    string Name,
    string Description);
