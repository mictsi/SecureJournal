using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public interface IPrototypeDataStore
{
    void Initialize();
    IReadOnlyList<StoredUserRow> LoadUsers();
    IReadOnlyList<StoredProjectRow> LoadProjects();
    IReadOnlyList<StoredGroupRow> LoadGroups();
    IReadOnlyList<StoredUserGroupRow> LoadUserGroups();
    IReadOnlyList<StoredProjectGroupRow> LoadProjectGroups();
    IReadOnlyList<JournalEntryRecord> LoadJournalEntries();
    IReadOnlyList<AuditLogRecord> LoadAuditLogs();
    void UpsertJournalEntry(JournalEntryRecord record);
    void UpsertUser(StoredUserRow user);
    void UpsertProject(StoredProjectRow project);
    void UpsertGroup(StoredGroupRow group);
    void AddUserToGroup(Guid userId, Guid groupId);
    void AddGroupToProject(Guid projectId, Guid groupId);
    void InsertAuditLog(AuditLogRecord record);
}
