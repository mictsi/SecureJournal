namespace SecureJournal.Core.Domain;

public sealed record SoftDeleteMetadata(
    DateTime DeletedAtUtc,
    Guid DeletedByUserId,
    string DeletedByUsername,
    string Reason);
