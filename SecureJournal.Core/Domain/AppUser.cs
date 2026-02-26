namespace SecureJournal.Core.Domain;

public sealed record AppUser(
    Guid UserId,
    string Username,
    string DisplayName,
    AppRole Role,
    bool IsLocalAccount);
