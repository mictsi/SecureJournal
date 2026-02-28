using SecureJournal.Core.Domain;

namespace SecureJournal.Core.Application;

public interface ISecureJournalAppService
{
    bool HasCurrentUser();
    Task<bool> HasCurrentUserAsync(CancellationToken cancellationToken = default);
    UserContext GetCurrentUser();
    Task<UserContext> GetCurrentUserAsync(CancellationToken cancellationToken = default);
    void SetCurrentUser(Guid userId);
    void LogoutCurrentUser();
    Task LogoutCurrentUserAsync(CancellationToken cancellationToken = default);
    LoginResult TryLocalLogin(string username, string password);
    Task<LoginResult> TryLocalLoginAsync(string username, string password, CancellationToken cancellationToken = default);
    int GetLocalPasswordMinLength();
    IReadOnlyList<UserContext> GetAvailableUsers();
    DashboardSummary GetDashboardSummary();
    IReadOnlyList<ProjectOverview> GetProjects();
    PagedResult<ProjectOverview> GetProjects(ProjectListQuery request);
    IReadOnlyList<GroupOverview> GetGroups();
    PagedResult<GroupOverview> GetGroups(GroupListQuery request);
    PagedResult<GroupAccessRow> GetProjectGroupAccess(ProjectGroupAccessQuery request);
    IReadOnlyList<UserOverview> GetUsers();
    PagedResult<UserOverview> GetUsers(UserListQuery request);
    PagedResult<GroupAccessRow> GetUserGroups(UserGroupMembershipQuery request);
    ProjectOverview CreateProject(CreateProjectRequest request);
    ProjectOverview UpdateProject(UpdateProjectRequest request);
    GroupOverview CreateGroup(CreateGroupRequest request);
    bool DeleteGroup(Guid groupId);
    UserOverview CreateUser(CreateUserRequest request);
    Task<UserOverview> CreateUserAsync(CreateUserRequest request, CancellationToken cancellationToken = default);
    bool AddUserToRole(UserRoleMembershipRequest request);
    bool RemoveUserFromRole(UserRoleMembershipRequest request);
    bool AssignUserToGroup(AssignUserToGroupRequest request);
    bool RemoveUserFromGroup(AssignUserToGroupRequest request);
    Task<bool> EnableUserAsync(Guid userId, CancellationToken cancellationToken = default);
    bool EnableUser(Guid userId);
    Task<bool> DisableUserAsync(Guid userId, CancellationToken cancellationToken = default);
    bool DisableUser(Guid userId);
    Task<bool> DeleteUserAsync(Guid userId, CancellationToken cancellationToken = default);
    bool DeleteUser(Guid userId);
    bool AssignGroupToProject(AssignGroupToProjectRequest request);
    bool RemoveGroupFromProject(AssignGroupToProjectRequest request);
    PasswordChangeResult ChangeCurrentUserPassword(ChangePasswordRequest request);
    Task<PasswordChangeResult> ChangeCurrentUserPasswordAsync(ChangePasswordRequest request, CancellationToken cancellationToken = default);
    PasswordChangeResult ResetLocalUserPassword(AdminResetPasswordRequest request);
    Task<PasswordChangeResult> ResetLocalUserPasswordAsync(AdminResetPasswordRequest request, CancellationToken cancellationToken = default);
    IReadOnlyList<JournalEntryView> GetJournalEntries(Guid? projectId = null, bool includeSoftDeleted = false);
    JournalEntryView CreateJournalEntry(CreateJournalEntryRequest request);
    bool SoftDeleteJournalEntry(Guid recordId, string? reason = null);
    IReadOnlyList<AuditLogView> SearchAuditLogs(AuditSearchFilter filter);
    AuditChecksumValidationResult ValidateAuditLogChecksum(Guid auditId);
    ExportFileResult ExportJournalEntries(JournalExportRequest request);
    ExportFileResult ExportAuditLogs(AuditExportRequest request);
}
