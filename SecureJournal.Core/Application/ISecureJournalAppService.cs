using SecureJournal.Core.Domain;

namespace SecureJournal.Core.Application;

public interface ISecureJournalAppService
{
    bool HasCurrentUser();
    UserContext GetCurrentUser();
    void SetCurrentUser(Guid userId);
    void LogoutCurrentUser();
    LoginResult TryLocalLogin(string username, string password);
    int GetLocalPasswordMinLength();
    IReadOnlyList<UserContext> GetAvailableUsers();
    DashboardSummary GetDashboardSummary();
    IReadOnlyList<ProjectOverview> GetProjects();
    IReadOnlyList<GroupOverview> GetGroups();
    IReadOnlyList<UserOverview> GetUsers();
    ProjectOverview CreateProject(CreateProjectRequest request);
    GroupOverview CreateGroup(CreateGroupRequest request);
    UserOverview CreateUser(CreateUserRequest request);
    bool AssignUserToGroup(AssignUserToGroupRequest request);
    bool AssignGroupToProject(AssignGroupToProjectRequest request);
    PasswordChangeResult ChangeCurrentUserPassword(ChangePasswordRequest request);
    PasswordChangeResult ResetLocalUserPassword(AdminResetPasswordRequest request);
    IReadOnlyList<JournalEntryView> GetJournalEntries(Guid? projectId = null, bool includeSoftDeleted = false);
    JournalEntryView CreateJournalEntry(CreateJournalEntryRequest request);
    bool SoftDeleteJournalEntry(Guid recordId, string? reason = null);
    IReadOnlyList<AuditLogView> SearchAuditLogs(AuditSearchFilter filter);
    AuditChecksumValidationResult ValidateAuditLogChecksum(Guid auditId);
    ExportFileResult ExportJournalEntries(JournalExportRequest request);
    ExportFileResult ExportAuditLogs(AuditExportRequest request);
}
