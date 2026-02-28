using System.Globalization;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Validation;

namespace SecureJournal.Core.Security;

public static class AuditChecksumMaterialBuilder
{
    private const char Separator = '\u001F';

    public static string Build(
        DateTime timestampUtc,
        string actorUsername,
        AuditActionType action,
        AuditEntityType entityType,
        string? entityId,
        Guid? projectId,
        AuditOutcome outcome,
        string details)
    {
        return string.Join(Separator, new[]
        {
            timestampUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            InputNormalizer.Normalize(actorUsername),
            action.ToString(),
            entityType.ToString(),
            InputNormalizer.Normalize(entityId),
            projectId?.ToString("D", CultureInfo.InvariantCulture) ?? string.Empty,
            outcome.ToString(),
            InputNormalizer.Normalize(details)
        });
    }
}
