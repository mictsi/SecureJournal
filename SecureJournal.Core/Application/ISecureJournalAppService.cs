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
    IReadOnlyList<GroupOverview> GetGroups();
    IReadOnlyList<UserOverview> GetUsers();
    ProjectOverview CreateProject(CreateProjectRequest request);
    GroupOverview CreateGroup(CreateGroupRequest request);
    UserOverview CreateUser(CreateUserRequest request);
    Task<UserOverview> CreateUserAsync(CreateUserRequest request, CancellationToken cancellationToken = default);
    bool AssignUserToGroup(AssignUserToGroupRequest request);
    bool AssignGroupToProject(AssignGroupToProjectRequest request);
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
