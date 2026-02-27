using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public interface IPrototypeDataStore
{
    void Initialize();
    IReadOnlyList<StoredUserRow> LoadUsers();
    IReadOnlyList<StoredUserRoleRow> LoadUserRoles();
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
    void AddUserRole(Guid userId, AppRole role);
    void RemoveUserRole(Guid userId, AppRole role);
    void AddUserToGroup(Guid userId, Guid groupId);
    void RemoveUserFromGroup(Guid userId, Guid groupId);
    void AddGroupToProject(Guid projectId, Guid groupId);
    void InsertAuditLog(AuditLogRecord record);
}
