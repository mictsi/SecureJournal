using SecureJournal.Core.Domain;

namespace SecureJournal.Core.Application;

public sealed class AuditSearchFilter
{
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
    public string? ActorUsername { get; set; }
    public Guid? ProjectId { get; set; }
    public AuditActionType? Action { get; set; }
    public AuditEntityType? EntityType { get; set; }
    public AuditOutcome? Outcome { get; set; }
}
