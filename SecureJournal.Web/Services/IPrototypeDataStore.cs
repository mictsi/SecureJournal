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
    StorePagedResult<StoredProjectRow> QueryProjects(StoreListQuery query, IReadOnlyCollection<Guid>? visibleProjectIds = null);
    StorePagedResult<StoredUserRow> QueryUsers(StoreListQuery query);
    StorePagedResult<StoredGroupRow> QueryGroups(StoreListQuery query);
    StorePagedResult<StoredGroupAccessRow> QueryProjectGroups(Guid projectId, StoreListQuery query);
    StorePagedResult<StoredGroupAccessRow> QueryUserGroups(Guid userId, StoreListQuery query);
    IReadOnlyList<StoredProjectGroupNameRow> LoadProjectGroupNamesForProjects(IReadOnlyCollection<Guid> projectIds);
    IReadOnlyList<StoredUserGroupNameRow> LoadUserGroupNamesForUsers(IReadOnlyCollection<Guid> userIds);
    IReadOnlyList<StoredUserRoleRow> LoadUserRolesForUsers(IReadOnlyCollection<Guid> userIds);
    IReadOnlyList<StoredGroupMemberNameRow> LoadGroupMemberNames(IReadOnlyCollection<Guid> groupIds);
    IReadOnlyList<StoredGroupProjectCodeRow> LoadGroupProjectCodes(IReadOnlyCollection<Guid> groupIds);
    IReadOnlyList<JournalEntryRecord> LoadJournalEntries();
    IReadOnlyList<AuditLogRecord> LoadAuditLogs();
    void UpsertJournalEntry(JournalEntryRecord record);
    void UpsertUser(StoredUserRow user);
    void UpsertProject(StoredProjectRow project);
    void UpsertGroup(StoredGroupRow group);
    void RemoveGroup(Guid groupId);
    void RemoveUser(Guid userId);
    void AddUserRole(Guid userId, AppRole role);
    void RemoveUserRole(Guid userId, AppRole role);
    void AddUserToGroup(Guid userId, Guid groupId);
    void RemoveUserFromGroup(Guid userId, Guid groupId);
    void AddGroupToProject(Guid projectId, Guid groupId);
    void RemoveGroupFromProject(Guid projectId, Guid groupId);
    void InsertAuditLog(AuditLogRecord record);
}
