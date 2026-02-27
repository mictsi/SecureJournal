using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public sealed class PrototypeSharedState
{
    public object SyncRoot { get; } = new();

    public bool IsInitialized { get; set; }

    public List<Project> Projects { get; } = new();
    public List<Group> Groups { get; } = new();
    public List<ProjectGroupAssignment> ProjectGroups { get; } = new();
    public List<AppUser> Users { get; } = new();
    public Dictionary<Guid, HashSet<AppRole>> UserRoles { get; } = new();
    public Dictionary<Guid, HashSet<Guid>> UserGroups { get; } = new();
    public Dictionary<Guid, string> LocalPasswordHashes { get; } = new();
    public List<JournalEntryRecord> JournalEntries { get; } = new();
    public List<AuditLogRecord> AuditLogs { get; } = new();
}
