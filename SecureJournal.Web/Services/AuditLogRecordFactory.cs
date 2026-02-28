using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;
using SecureJournal.Core.Validation;

namespace SecureJournal.Web.Services;

public sealed class AuditLogRecordFactory : IAuditLogRecordFactory
{
    private readonly IAuditFieldEncryptor _encryptor;
    private readonly IChecksumService _checksum;

    public AuditLogRecordFactory(IAuditFieldEncryptor encryptor, IChecksumService checksum)
    {
        _encryptor = encryptor;
        _checksum = checksum;
    }

    public AuditLogRecord Create(
        AppUser? actor,
        AuditActionType action,
        AuditEntityType entityType,
        string? entityId,
        Guid? projectId,
        AuditOutcome outcome,
        string details)
    {
        var normalizedDetails = InputNormalizer.Normalize(details);
        var timestampUtc = DateTime.UtcNow;
        var actorUsername = actor?.Username ?? "system";
        var checksumMaterial = AuditChecksumMaterialBuilder.Build(
            timestampUtc,
            actorUsername,
            action,
            entityType,
            entityId,
            projectId,
            outcome,
            normalizedDetails);

        return new AuditLogRecord(
            AuditId: Guid.NewGuid(),
            TimestampUtc: timestampUtc,
            ActorUserId: actor?.UserId,
            ActorUsername: actorUsername,
            Action: action,
            EntityType: entityType,
            EntityId: entityId,
            ProjectId: projectId,
            Outcome: outcome,
            DetailsCiphertext: _encryptor.Encrypt(normalizedDetails),
            DetailsChecksum: _checksum.ComputeHex(checksumMaterial));
    }
}
