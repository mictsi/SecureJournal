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

    // Version counters used by in-memory read caches for deterministic invalidation.
    public long UsersVersion { get; set; }
    public long ProjectsVersion { get; set; }
    public long GroupsVersion { get; set; }
    public long MembershipsVersion { get; set; }
    public long JournalsVersion { get; set; }

    public Dictionary<Guid, ReadableProjectIdsCacheEntry> ReadableProjectIdsCache { get; } = new();
}

public sealed class ReadableProjectIdsCacheEntry
{
    public long UsersVersion { get; init; }
    public long ProjectsVersion { get; init; }
    public long MembershipsVersion { get; init; }
    public HashSet<Guid> ProjectIds { get; init; } = new();
}
