using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;
using SecureJournal.Core.Validation;
using SecureJournal.Web.Infrastructure.Identity;

namespace SecureJournal.Web.Services;

public sealed class InMemorySecureJournalAppService : ISecureJournalAppService
{
    private readonly IChecksumService _checksumService;
    private readonly IJournalFieldEncryptor _journalEncryptor;
    private readonly IAuditFieldEncryptor _auditEncryptor;
    private readonly IPrototypeDataStore _sqliteStore;
    private readonly ILogger<InMemorySecureJournalAppService> _logger;
    private readonly PasswordHasher<AppUser> _passwordHasher = new();
    private readonly BootstrapAdminSettings _bootstrapAdmin;
    private readonly SecuritySettings _securitySettings;
    private readonly PrototypeSharedState _shared;
    private readonly IHttpContextAccessor? _httpContextAccessor;
    private readonly PrototypeSessionRegistry? _sessionRegistry;
    private readonly AuthenticationStateProvider? _authenticationStateProvider;
    private readonly SignInManager<SecureJournalIdentityUser>? _identitySignInManager;
    private readonly UserManager<SecureJournalIdentityUser>? _identityUserManager;
    private readonly bool _enableAspNetIdentity;
    private readonly bool _enableOidc;

    private object _sync => _shared.SyncRoot;
    private List<Project> _projects => _shared.Projects;
    private List<Group> _groups => _shared.Groups;
    private List<ProjectGroupAssignment> _projectGroups => _shared.ProjectGroups;
    private List<AppUser> _users => _shared.Users;
    private Dictionary<Guid, HashSet<Guid>> _userGroups => _shared.UserGroups;
    private Dictionary<Guid, string> _localPasswordHashes => _shared.LocalPasswordHashes;
    private List<JournalEntryRecord> _journalEntries => _shared.JournalEntries;
    private List<AuditLogRecord> _auditLogs => _shared.AuditLogs;

    private Guid _currentUserId;

    public InMemorySecureJournalAppService(
        IChecksumService checksumService,
        IJournalFieldEncryptor journalEncryptor,
        IAuditFieldEncryptor auditEncryptor,
        IPrototypeDataStore sqliteStore,
        PrototypeSharedState shared,
        IConfiguration configuration,
        ILogger<InMemorySecureJournalAppService> logger,
        IHttpContextAccessor? httpContextAccessor = null,
        PrototypeSessionRegistry? sessionRegistry = null,
        AuthenticationStateProvider? authenticationStateProvider = null,
        SignInManager<SecureJournalIdentityUser>? identitySignInManager = null,
        UserManager<SecureJournalIdentityUser>? identityUserManager = null)
    {
        _checksumService = checksumService;
        _journalEncryptor = journalEncryptor;
        _auditEncryptor = auditEncryptor;
        _sqliteStore = sqliteStore;
        _shared = shared;
        _logger = logger;
        _securitySettings = SecuritySettings.FromConfiguration(configuration);
        _bootstrapAdmin = BootstrapAdminSettings.FromConfiguration(configuration);
        _httpContextAccessor = httpContextAccessor;
        _sessionRegistry = sessionRegistry;
        _authenticationStateProvider = authenticationStateProvider;
        _identitySignInManager = identitySignInManager;
        _identityUserManager = identityUserManager;
        _enableAspNetIdentity = bool.TryParse(configuration["Authentication:EnableAspNetIdentity"], out var enableIdentity) && enableIdentity;
        _enableOidc = bool.TryParse(configuration["Authentication:EnableOidc"], out var enableOidc) && enableOidc;

        lock (_sync)
        {
            if (!_shared.IsInitialized)
            {
                Seed();
                _shared.IsInitialized = true;
            }
        }
    }

    public bool HasCurrentUser()
    {
        lock (_sync)
        {
            if (_enableAspNetIdentity && TryGetCurrentPrincipal(out var principal))
            {
                return TryResolveOrProvisionUserFromPrincipal(principal, out _);
            }

            TryRestoreCurrentUserFromCookie();
            return _users.Any(u => u.UserId == _currentUserId);
        }
    }

    public UserContext GetCurrentUser()
    {
        lock (_sync)
        {
            if (_enableAspNetIdentity && TryGetCurrentPrincipal(out var principal))
            {
                if (TryResolveOrProvisionUserFromPrincipal(principal, out var resolved))
                {
                    return ToUserContext(resolved);
                }

                throw new UnauthorizedAccessException("Authentication is required.");
            }

            TryRestoreCurrentUserFromCookie();
            return ToUserContext(GetCurrentUserInternal());
        }
    }

    public void SetCurrentUser(Guid userId)
    {
        lock (_sync)
        {
            var nextUser = _users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            var previousUser = _users.FirstOrDefault(u => u.UserId == _currentUserId);
            if (previousUser?.UserId == nextUser.UserId)
            {
                return;
            }

            _currentUserId = nextUser.UserId;
            if (previousUser is not null)
            {
                _logger.LogInformation(
                    "Current user switched from {PreviousUsername} ({PreviousRole}) to {NextUsername} ({NextRole})",
                    previousUser.Username,
                    previousUser.Role,
                    nextUser.Username,
                    nextUser.Role);

                AppendAudit(
                    previousUser,
                    AuditActionType.Logout,
                    AuditEntityType.Authentication,
                    entityId: previousUser.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Success,
                    $"User '{previousUser.Username}' logged out.");
            }
            else
            {
                _logger.LogInformation(
                    "Current user set to {NextUsername} ({NextRole})",
                    nextUser.Username,
                    nextUser.Role);
            }

            AppendAudit(
                nextUser,
                AuditActionType.Login,
                AuditEntityType.Authentication,
                entityId: nextUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{nextUser.Username}' logged in.");
        }
    }

    public void LogoutCurrentUser()
    {
        lock (_sync)
        {
            if (_enableAspNetIdentity && TryGetCurrentPrincipal(out var principal))
            {
                if (TryResolveOrProvisionUserFromPrincipal(principal, out var currentIdentityUser))
                {
                    _logger.LogInformation("Identity user logged out: {Username}", currentIdentityUser.Username);
                    AppendAudit(
                        currentIdentityUser,
                        AuditActionType.Logout,
                        AuditEntityType.Authentication,
                        entityId: currentIdentityUser.UserId.ToString(),
                        projectId: null,
                        AuditOutcome.Success,
                        $"User '{currentIdentityUser.Username}' logged out.");
                }

                if (_identitySignInManager is not null)
                {
                    _identitySignInManager.SignOutAsync().GetAwaiter().GetResult();
                }

                return;
            }

            TryRestoreCurrentUserFromCookie();
            var currentUser = _users.FirstOrDefault(u => u.UserId == _currentUserId);
            if (currentUser is null)
            {
                return;
            }

            _currentUserId = Guid.Empty;
            _logger.LogInformation("Current user logged out: {Username}", currentUser.Username);

            AppendAudit(
                currentUser,
                AuditActionType.Logout,
                AuditEntityType.Authentication,
                entityId: currentUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{currentUser.Username}' logged out.");
        }
    }

    public LoginResult TryLocalLogin(string username, string password)
    {
        lock (_sync)
        {
            var normalizedUsername = InputNormalizer.NormalizeRequired(username, nameof(username), 100).ToLowerInvariant();
            _logger.LogInformation("Local login attempt for username {Username}", normalizedUsername);

            if (_enableAspNetIdentity)
            {
                return TryLocalLoginWithIdentity(normalizedUsername, password ?? string.Empty);
            }

            var localUser = _users.FirstOrDefault(u =>
                u.IsLocalAccount &&
                string.Equals(u.Username, normalizedUsername, StringComparison.OrdinalIgnoreCase));

            if (localUser is null || !_localPasswordHashes.TryGetValue(localUser.UserId, out var passwordHash))
            {
                AppendAudit(
                    actor: null,
                    AuditActionType.Login,
                    AuditEntityType.Authentication,
                    entityId: null,
                    projectId: null,
                    AuditOutcome.Failure,
                    $"Failed local login attempt for username '{normalizedUsername}'.");
                return new LoginResult(false, "Invalid username or password.", null);
            }

            var verification = _passwordHasher.VerifyHashedPassword(localUser, passwordHash, password ?? string.Empty);
            if (verification is PasswordVerificationResult.Failed)
            {
                _logger.LogWarning("Local login failed for user {Username}: invalid password", localUser.Username);
                AppendAudit(
                    actor: localUser,
                    AuditActionType.Login,
                    AuditEntityType.Authentication,
                    entityId: localUser.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    $"Failed local login attempt for user '{localUser.Username}'.");
                return new LoginResult(false, "Invalid username or password.", null);
            }

            SetCurrentUser(localUser.UserId);
            _logger.LogInformation("Local login succeeded for user {Username}", localUser.Username);
            return new LoginResult(true, $"Logged in as {localUser.DisplayName}.", ToUserContext(localUser));
        }
    }

    public int GetLocalPasswordMinLength()
    {
        lock (_sync)
        {
            return _securitySettings.LocalPasswordMinLength;
        }
    }

    public IReadOnlyList<UserContext> GetAvailableUsers()
    {
        lock (_sync)
        {
            return _users
                .OrderBy(u => u.DisplayName, StringComparer.OrdinalIgnoreCase)
                .Select(ToUserContext)
                .ToList();
        }
    }

    public DashboardSummary GetDashboardSummary()
    {
        lock (_sync)
        {
            var currentUser = GetCurrentUserInternal();
            var readableProjectIds = GetReadableProjectIds(currentUser);
            var visibleEntries = currentUser.Role == AppRole.Auditor
                ? new List<JournalEntryRecord>()
                : _journalEntries
                    .Where(e => readableProjectIds.Contains(e.ProjectId))
                    .Where(e => !e.IsSoftDeleted || CanSeeSoftDeletedEntries(currentUser))
                    .ToList();

            var visibleAuditCount = currentUser.Role is AppRole.Administrator or AppRole.Auditor
                ? _auditLogs.Count
                : 0;

            return new DashboardSummary(
                TotalProjects: _projects.Count,
                AccessibleProjects: readableProjectIds.Count,
                VisibleJournalEntries: visibleEntries.Count,
                SoftDeletedEntriesVisible: visibleEntries.Count(e => e.IsSoftDeleted),
                AuditEventsVisible: visibleAuditCount,
                Users: _users.Count,
                Groups: _groups.Count);
        }
    }

    public IReadOnlyList<ProjectOverview> GetProjects()
    {
        lock (_sync)
        {
            var currentUser = GetCurrentUserInternal();
            var readableProjectIds = GetReadableProjectIds(currentUser);

            var query = _projects
                .Where(p => currentUser.Role is AppRole.Administrator or AppRole.Auditor || readableProjectIds.Contains(p.ProjectId))
                .OrderBy(p => p.Code, StringComparer.OrdinalIgnoreCase)
                .Select(project => new ProjectOverview(
                    project.ProjectId,
                    project.Code,
                    project.Name,
                    project.Description,
                    GetAssignedGroupNames(project.ProjectId),
                    readableProjectIds.Contains(project.ProjectId)))
                .ToList();

            return query;
        }
    }

    public IReadOnlyList<GroupOverview> GetGroups()
    {
        lock (_sync)
        {
            var currentUser = GetCurrentUserInternal();
            if (currentUser.Role != AppRole.Administrator)
            {
                return Array.Empty<GroupOverview>();
            }

            return _groups
                .OrderBy(g => g.Name, StringComparer.OrdinalIgnoreCase)
                .Select(group => new GroupOverview(
                    group.GroupId,
                    group.Name,
                    _users.Where(u => IsUserInGroup(u.UserId, group.GroupId))
                          .Select(u => u.DisplayName)
                          .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                          .ToList(),
                    _projectGroups.Where(pg => pg.GroupId == group.GroupId)
                                  .Join(_projects, pg => pg.ProjectId, p => p.ProjectId, (_, p) => p.Code)
                                  .OrderBy(c => c, StringComparer.OrdinalIgnoreCase)
                                  .ToList()))
                .ToList();
        }
    }

    public IReadOnlyList<UserOverview> GetUsers()
    {
        lock (_sync)
        {
            var currentUser = GetCurrentUserInternal();
            if (currentUser.Role != AppRole.Administrator)
            {
                return Array.Empty<UserOverview>();
            }

            return _users
                .OrderBy(u => u.DisplayName, StringComparer.OrdinalIgnoreCase)
                .Select(user => new UserOverview(
                    user.UserId,
                    user.Username,
                    user.DisplayName,
                    user.Role,
                    user.IsLocalAccount,
                    GetUserGroupNames(user.UserId)))
                .ToList();
        }
    }

    public ProjectOverview CreateProject(CreateProjectRequest request)
    {
        lock (_sync)
        {
            var actor = RequireAdmin();
            ValidateAdminRequest(request);

            var requestedCode = InputNormalizer.NormalizeOptional(request.Code, 20);
            var code = string.IsNullOrWhiteSpace(requestedCode)
                ? GenerateUniqueProjectCode()
                : requestedCode.ToUpperInvariant();
            var name = InputNormalizer.NormalizeRequired(request.Name, nameof(request.Name), 100);
            var description = InputNormalizer.NormalizeOptional(request.Description, 500);

            if (_projects.Any(p => string.Equals(p.Code, code, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"A project with code '{code}' already exists.");
            }

            var project = new Project(Guid.NewGuid(), code, name, description);
            _projects.Add(project);
            _sqliteStore.UpsertProject(new StoredProjectRow(project.ProjectId, project.Code, project.Name, project.Description));
            _logger.LogInformation(
                "Project created by {ActorUsername}: {ProjectCode} ({ProjectId})",
                actor.Username,
                project.Code,
                project.ProjectId);

            AppendAudit(
                actor,
                AuditActionType.Create,
                AuditEntityType.Project,
                entityId: project.ProjectId.ToString(),
                projectId: project.ProjectId,
                AuditOutcome.Success,
                $"Project '{project.Code}' created.");

            return new ProjectOverview(
                project.ProjectId,
                project.Code,
                project.Name,
                project.Description,
                AssignedGroups: Array.Empty<string>(),
                HasAccessForCurrentUser: true);
        }
    }

    public UserOverview CreateUser(CreateUserRequest request)
    {
        lock (_sync)
        {
            var actor = RequireAdmin();
            ValidateAdminRequest(request);

            var username = InputNormalizer.NormalizeRequired(request.Username, nameof(request.Username), 100).ToLowerInvariant();
            var displayName = InputNormalizer.NormalizeRequired(request.DisplayName, nameof(request.DisplayName), 100);

            if (_users.Any(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"A user with username '{username}' already exists.");
            }

            if (request.IsLocalAccount && string.IsNullOrWhiteSpace(request.LocalPassword))
            {
                throw new InvalidOperationException("Local account password is required.");
            }

            var user = new AppUser(Guid.NewGuid(), username, displayName, request.Role, request.IsLocalAccount);
            _users.Add(user);
            _userGroups[user.UserId] = new HashSet<Guid>();

            string? passwordHash = null;
            if (request.IsLocalAccount)
            {
                EnsurePasswordMeetsPolicy(request.LocalPassword, "Local account password");
                if (_enableAspNetIdentity)
                {
                    CreateOrUpdateIdentityLocalUser(user, request.LocalPassword ?? string.Empty);
                }
                else
                {
                    passwordHash = _passwordHasher.HashPassword(user, request.LocalPassword ?? string.Empty);
                    _localPasswordHashes[user.UserId] = passwordHash;
                }
            }
            else if (_enableAspNetIdentity)
            {
                EnsureIdentityExternalUser(user);
            }

            _sqliteStore.UpsertUser(new StoredUserRow(
                user.UserId,
                user.Username,
                user.DisplayName,
                user.Role,
                user.IsLocalAccount,
                passwordHash));
            _logger.LogInformation(
                "User created by {ActorUsername}: {Username} ({Role}) Local={IsLocal}",
                actor.Username,
                user.Username,
                user.Role,
                user.IsLocalAccount);

            AppendAudit(
                actor,
                AuditActionType.Create,
                AuditEntityType.User,
                entityId: user.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{user.Username}' created with role '{user.Role}' (Local={user.IsLocalAccount}).");

            return new UserOverview(
                user.UserId,
                user.Username,
                user.DisplayName,
                user.Role,
                user.IsLocalAccount,
                Groups: Array.Empty<string>());
        }
    }

    public GroupOverview CreateGroup(CreateGroupRequest request)
    {
        lock (_sync)
        {
            var actor = RequireAdmin();
            ValidateAdminRequest(request);

            var name = InputNormalizer.NormalizeRequired(request.Name, nameof(request.Name), 100);
            if (_groups.Any(g => string.Equals(g.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"A group named '{name}' already exists.");
            }

            var group = new Group(Guid.NewGuid(), name);
            _groups.Add(group);
            _sqliteStore.UpsertGroup(new StoredGroupRow(group.GroupId, group.Name));
            _logger.LogInformation(
                "Group created by {ActorUsername}: {GroupName} ({GroupId})",
                actor.Username,
                group.Name,
                group.GroupId);

            AppendAudit(
                actor,
                AuditActionType.Create,
                AuditEntityType.Group,
                entityId: group.GroupId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"Group '{group.Name}' created.");

            return new GroupOverview(
                group.GroupId,
                group.Name,
                Members: Array.Empty<string>(),
                ProjectCodes: Array.Empty<string>());
        }
    }

    public bool AssignUserToGroup(AssignUserToGroupRequest request)
    {
        lock (_sync)
        {
            var actor = RequireAdmin();

            if (request.UserId == Guid.Empty || request.GroupId == Guid.Empty)
            {
                throw new InvalidOperationException("User and group are required.");
            }

            var user = _users.FirstOrDefault(u => u.UserId == request.UserId)
                ?? throw new InvalidOperationException("Selected user was not found.");
            var group = _groups.FirstOrDefault(g => g.GroupId == request.GroupId)
                ?? throw new InvalidOperationException("Selected group was not found.");

            if (!_userGroups.TryGetValue(user.UserId, out var memberships))
            {
                memberships = new HashSet<Guid>();
                _userGroups[user.UserId] = memberships;
            }

            var added = memberships.Add(group.GroupId);
            if (!added)
            {
                return false;
            }

            _sqliteStore.AddUserToGroup(user.UserId, group.GroupId);
            _logger.LogInformation(
                "User-to-group assignment by {ActorUsername}: {Username} -> {GroupName}",
                actor.Username,
                user.Username,
                group.Name);

            AppendAudit(
                actor,
                AuditActionType.Assign,
                AuditEntityType.Permission,
                entityId: user.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{user.Username}' assigned to group '{group.Name}'.");

            return true;
        }
    }

    public bool AssignGroupToProject(AssignGroupToProjectRequest request)
    {
        lock (_sync)
        {
            var actor = RequireAdmin();

            if (request.ProjectId == Guid.Empty || request.GroupId == Guid.Empty)
            {
                throw new InvalidOperationException("Project and group are required.");
            }

            var project = _projects.FirstOrDefault(p => p.ProjectId == request.ProjectId)
                ?? throw new InvalidOperationException("Selected project was not found.");
            var group = _groups.FirstOrDefault(g => g.GroupId == request.GroupId)
                ?? throw new InvalidOperationException("Selected group was not found.");

            if (_projectGroups.Any(pg => pg.ProjectId == project.ProjectId && pg.GroupId == group.GroupId))
            {
                return false;
            }

            _projectGroups.Add(new ProjectGroupAssignment(project.ProjectId, group.GroupId));
            _sqliteStore.AddGroupToProject(project.ProjectId, group.GroupId);
            _logger.LogInformation(
                "Group-to-project assignment by {ActorUsername}: {GroupName} -> {ProjectCode}",
                actor.Username,
                group.Name,
                project.Code);

            AppendAudit(
                actor,
                AuditActionType.Assign,
                AuditEntityType.Permission,
                entityId: group.GroupId.ToString(),
                projectId: project.ProjectId,
                AuditOutcome.Success,
                $"Group '{group.Name}' assigned to project '{project.Code}'.");

            return true;
        }
    }

    public PasswordChangeResult ChangeCurrentUserPassword(ChangePasswordRequest request)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            _logger.LogInformation("Password change requested for current user {Username}", actor.Username);

            var validationContext = new ValidationContext(request);
            Validator.ValidateObject(request, validationContext, validateAllProperties: true);

            if (!actor.IsLocalAccount)
            {
                AppendAudit(
                    actor,
                    AuditActionType.Update,
                    AuditEntityType.Authentication,
                    entityId: actor.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Denied,
                    "Password change attempted for non-local account.");
                return new PasswordChangeResult(false, "Password changes are available only for local accounts.");
            }

            if (_enableAspNetIdentity)
            {
                return ChangeCurrentUserPasswordWithIdentity(actor, request);
            }

            if (!_localPasswordHashes.TryGetValue(actor.UserId, out var existingHash))
            {
                AppendAudit(
                    actor,
                    AuditActionType.Update,
                    AuditEntityType.Authentication,
                    entityId: actor.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    "Password change failed because no local password hash was found.");
                return new PasswordChangeResult(false, "Current account does not have a local password configured.");
            }

            var currentPassword = request.CurrentPassword ?? string.Empty;
            var newPassword = request.NewPassword ?? string.Empty;

            var verification = _passwordHasher.VerifyHashedPassword(actor, existingHash, currentPassword);
            if (verification is PasswordVerificationResult.Failed)
            {
                _logger.LogWarning("Password change failed for user {Username}: current password mismatch", actor.Username);
                AppendAudit(
                    actor,
                    AuditActionType.Update,
                    AuditEntityType.Authentication,
                    entityId: actor.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    "Password change failed because the current password did not match.");
                return new PasswordChangeResult(false, "Current password is incorrect.");
            }

            if (string.IsNullOrWhiteSpace(newPassword))
            {
                return new PasswordChangeResult(false, "New password is required.");
            }

            if (TryGetPasswordPolicyViolationMessage(newPassword, "New password") is { } passwordPolicyError)
            {
                return new PasswordChangeResult(false, passwordPolicyError);
            }

            if (string.Equals(currentPassword, newPassword, StringComparison.Ordinal))
            {
                return new PasswordChangeResult(false, "New password must be different from the current password.");
            }

            var newHash = _passwordHasher.HashPassword(actor, newPassword);
            _localPasswordHashes[actor.UserId] = newHash;
            _sqliteStore.UpsertUser(new StoredUserRow(
                actor.UserId,
                actor.Username,
                actor.DisplayName,
                actor.Role,
                actor.IsLocalAccount,
                newHash));
            _logger.LogInformation("Password change succeeded for user {Username}", actor.Username);

            AppendAudit(
                actor,
                AuditActionType.Update,
                AuditEntityType.Authentication,
                entityId: actor.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                "Local password changed for current user.");

            return new PasswordChangeResult(true, "Password changed successfully.");
        }
    }

    public PasswordChangeResult ResetLocalUserPassword(AdminResetPasswordRequest request)
    {
        lock (_sync)
        {
            var actor = RequireAdmin();
            ValidateAdminRequest(request);

            if (request.UserId == Guid.Empty)
            {
                return new PasswordChangeResult(false, "A user must be selected.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == request.UserId);
            if (targetUser is null)
            {
                return new PasswordChangeResult(false, "Selected user was not found.");
            }

            if (!targetUser.IsLocalAccount)
            {
                AppendAudit(
                    actor,
                    AuditActionType.Update,
                    AuditEntityType.Authentication,
                    entityId: targetUser.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Denied,
                    $"Administrator '{actor.Username}' attempted password reset for non-local user '{targetUser.Username}'.");
                return new PasswordChangeResult(false, "Password reset is available only for local accounts.");
            }

            EnsurePasswordMeetsPolicy(request.NewPassword, "Reset password");

            if (_enableAspNetIdentity)
            {
                return ResetLocalUserPasswordWithIdentity(actor, targetUser, request.NewPassword);
            }

            var newHash = _passwordHasher.HashPassword(targetUser, request.NewPassword);
            _localPasswordHashes[targetUser.UserId] = newHash;
            _sqliteStore.UpsertUser(new StoredUserRow(
                targetUser.UserId,
                targetUser.Username,
                targetUser.DisplayName,
                targetUser.Role,
                targetUser.IsLocalAccount,
                newHash));

            _logger.LogInformation(
                "Password reset by admin {ActorUsername} for user {TargetUsername}",
                actor.Username,
                targetUser.Username);

            AppendAudit(
                actor,
                AuditActionType.Update,
                AuditEntityType.Authentication,
                entityId: targetUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"Administrator '{actor.Username}' reset local password for user '{targetUser.Username}'.");

            return new PasswordChangeResult(true, $"Password reset for '{targetUser.Username}'.");
        }
    }

    public IReadOnlyList<JournalEntryView> GetJournalEntries(Guid? projectId = null, bool includeSoftDeleted = false)
    {
        lock (_sync)
        {
            var currentUser = GetCurrentUserInternal();
            if (currentUser.Role == AppRole.Auditor)
            {
                AppendAudit(
                    currentUser,
                    AuditActionType.Read,
                    AuditEntityType.JournalEntry,
                    entityId: null,
                    projectId: projectId,
                    AuditOutcome.Denied,
                    "Auditor attempted to read journal entries directly.");
                throw new UnauthorizedAccessException("Auditors can access audit logs only and cannot read journal entries.");
            }

            var readableProjectIds = GetReadableProjectIds(currentUser);

            if (projectId.HasValue && !readableProjectIds.Contains(projectId.Value))
            {
                return Array.Empty<JournalEntryView>();
            }

            var canSeeSoftDeleted = includeSoftDeleted && CanSeeSoftDeletedEntries(currentUser);

            return _journalEntries
                .Where(e => readableProjectIds.Contains(e.ProjectId))
                .Where(e => !projectId.HasValue || e.ProjectId == projectId.Value)
                .Where(e => !e.IsSoftDeleted || canSeeSoftDeleted)
                .OrderByDescending(e => e.CreatedAtUtc)
                .Select(MapJournalEntry)
                .ToList();
        }
    }

    public JournalEntryView CreateJournalEntry(CreateJournalEntryRequest request)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            var now = DateTime.UtcNow;

            ValidateRequest(request);

            if (actor.Role == AppRole.Auditor)
            {
                AppendAudit(
                    actor,
                    AuditActionType.Create,
                    AuditEntityType.JournalEntry,
                    entityId: null,
                    projectId: request.ProjectId,
                    AuditOutcome.Denied,
                    "Auditor attempted to create a journal entry.");
                throw new UnauthorizedAccessException("Auditors cannot create journal entries.");
            }

            var project = _projects.FirstOrDefault(p => p.ProjectId == request.ProjectId)
                ?? throw new InvalidOperationException("Selected project was not found.");

            if (!CanAccessProject(actor, project.ProjectId))
            {
                AppendAudit(
                    actor,
                    AuditActionType.Create,
                    AuditEntityType.JournalEntry,
                    entityId: null,
                    projectId: request.ProjectId,
                    AuditOutcome.Denied,
                    $"User '{actor.Username}' attempted to create a journal entry in unauthorized project '{project.Code}'.");
                throw new UnauthorizedAccessException("You do not have access to the selected project.");
            }

            var action = InputNormalizer.NormalizeRequired(request.Action, nameof(request.Action), FieldLimits.CategoryMax);
            var subject = InputNormalizer.NormalizeRequired(request.Subject, nameof(request.Subject), FieldLimits.SubjectMax);
            var description = InputNormalizer.NormalizeRequired(request.Description, nameof(request.Description), FieldLimits.DescriptionMax);
            var notes = InputNormalizer.NormalizeOptional(request.Notes, FieldLimits.NotesMax);
            var result = string.Empty;

            var record = new JournalEntryRecord
            {
                RecordId = Guid.NewGuid(),
                ProjectId = project.ProjectId,
                CreatedAtUtc = now,
                CreatedByUserId = actor.UserId,
                CreatedByUsername = actor.Username,
                CategoryCiphertext = _journalEncryptor.Encrypt(action),
                SubjectCiphertext = _journalEncryptor.Encrypt(subject),
                DescriptionCiphertext = _journalEncryptor.Encrypt(description),
                NotesCiphertext = _journalEncryptor.Encrypt(notes),
                ResultCiphertext = _journalEncryptor.Encrypt(result),
                CategoryChecksum = _checksumService.ComputeHex(action),
                SubjectChecksum = _checksumService.ComputeHex(subject),
                DescriptionChecksum = _checksumService.ComputeHex(description),
                NotesChecksum = _checksumService.ComputeHex(notes),
                ResultChecksum = _checksumService.ComputeHex(result),
                FullRecordChecksum = _checksumService.ComputeHex(BuildFullRecordChecksumMaterial(
                    project.ProjectId,
                    actor.UserId,
                    now,
                    action,
                    subject,
                    description,
                    notes,
                    result))
            };

            _journalEntries.Add(record);
            _sqliteStore.UpsertJournalEntry(record);

            AppendAudit(
                actor,
                AuditActionType.Create,
                AuditEntityType.JournalEntry,
                entityId: record.RecordId.ToString(),
                projectId: project.ProjectId,
                AuditOutcome.Success,
                $"Journal entry created in project '{project.Code}' with action '{action}' and subject '{subject}'.");

            return MapJournalEntry(record);
        }
    }

    public bool SoftDeleteJournalEntry(Guid recordId, string? reason = null)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            var entry = _journalEntries.FirstOrDefault(e => e.RecordId == recordId);
            if (entry is null)
            {
                return false;
            }

            if (actor.Role == AppRole.Auditor)
            {
                AppendAudit(
                    actor,
                    AuditActionType.Delete,
                    AuditEntityType.JournalEntry,
                    entityId: recordId.ToString(),
                    projectId: entry.ProjectId,
                    AuditOutcome.Denied,
                    "Auditor attempted to soft-delete a journal entry.");
                throw new UnauthorizedAccessException("Auditors cannot delete journal entries.");
            }

            if (!CanAccessProject(actor, entry.ProjectId))
            {
                AppendAudit(
                    actor,
                    AuditActionType.Delete,
                    AuditEntityType.JournalEntry,
                    entityId: recordId.ToString(),
                    projectId: entry.ProjectId,
                    AuditOutcome.Denied,
                    "User attempted to soft-delete a journal entry in an unauthorized project.");
                throw new UnauthorizedAccessException("You do not have access to this journal entry.");
            }

            if (entry.IsSoftDeleted)
            {
                return false;
            }

            var normalizedReason = InputNormalizer.NormalizeOptional(reason, FieldLimits.DescriptionMax);
            if (string.IsNullOrWhiteSpace(normalizedReason))
            {
                normalizedReason = "Soft-deleted from prototype UI.";
            }

            entry.MarkSoftDeleted(new SoftDeleteMetadata(
                DeletedAtUtc: DateTime.UtcNow,
                DeletedByUserId: actor.UserId,
                DeletedByUsername: actor.Username,
                Reason: normalizedReason));
            _sqliteStore.UpsertJournalEntry(entry);

            AppendAudit(
                actor,
                AuditActionType.Delete,
                AuditEntityType.JournalEntry,
                entityId: entry.RecordId.ToString(),
                projectId: entry.ProjectId,
                AuditOutcome.Success,
                $"Journal entry soft-deleted. Reason: {normalizedReason}");

            return true;
        }
    }

    public IReadOnlyList<AuditLogView> SearchAuditLogs(AuditSearchFilter filter)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            if (actor.Role is not (AppRole.Administrator or AppRole.Auditor))
            {
                AppendAudit(
                    actor,
                    AuditActionType.Read,
                    AuditEntityType.JournalEntry,
                    entityId: null,
                    projectId: null,
                    AuditOutcome.Denied,
                    "Project user attempted to access audit log search.");
                throw new UnauthorizedAccessException("Audit logs are only available to administrators and auditors.");
            }

            var query = _auditLogs.AsEnumerable();

            if (filter.FromUtc.HasValue)
            {
                query = query.Where(a => a.TimestampUtc >= filter.FromUtc.Value);
            }

            if (filter.ToUtc.HasValue)
            {
                query = query.Where(a => a.TimestampUtc <= filter.ToUtc.Value);
            }

            if (!string.IsNullOrWhiteSpace(filter.ActorUsername))
            {
                query = query.Where(a => a.ActorUsername.Contains(filter.ActorUsername, StringComparison.OrdinalIgnoreCase));
            }

            if (filter.ProjectId.HasValue)
            {
                query = query.Where(a => a.ProjectId == filter.ProjectId.Value);
            }

            if (filter.Action.HasValue)
            {
                query = query.Where(a => a.Action == filter.Action.Value);
            }

            if (filter.EntityType.HasValue)
            {
                query = query.Where(a => a.EntityType == filter.EntityType.Value);
            }

            if (filter.Outcome.HasValue)
            {
                query = query.Where(a => a.Outcome == filter.Outcome.Value);
            }

            return query
                .OrderByDescending(a => a.TimestampUtc)
                .Select(MapAuditLog)
                .ToList();
        }
    }

    public AuditChecksumValidationResult ValidateAuditLogChecksum(Guid auditId)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            if (actor.Role is not (AppRole.Administrator or AppRole.Auditor))
            {
                AppendAudit(
                    actor,
                    AuditActionType.Read,
                    AuditEntityType.JournalEntry,
                    entityId: auditId == Guid.Empty ? null : auditId.ToString(),
                    projectId: null,
                    AuditOutcome.Denied,
                    "Project user attempted to validate an audit log checksum.");
                throw new UnauthorizedAccessException("Audit log checksum validation is only available to administrators and auditors.");
            }

            if (auditId == Guid.Empty)
            {
                throw new InvalidOperationException("Audit id is required.");
            }

            var record = _auditLogs.FirstOrDefault(a => a.AuditId == auditId)
                ?? throw new InvalidOperationException("Audit log entry was not found.");

            var details = _auditEncryptor.Decrypt(record.DetailsCiphertext);
            var computed = _checksumService.ComputeHex(details);
            var isValid = string.Equals(computed, record.DetailsChecksum, StringComparison.OrdinalIgnoreCase);

            AppendAudit(
                actor,
                AuditActionType.Read,
                AuditEntityType.Export,
                entityId: record.AuditId.ToString(),
                projectId: record.ProjectId,
                isValid ? AuditOutcome.Success : AuditOutcome.Failure,
                isValid
                    ? $"Audit checksum validated for audit '{record.AuditId}'."
                    : $"Audit checksum mismatch detected for audit '{record.AuditId}'.");

            return new AuditChecksumValidationResult(
                AuditId: record.AuditId,
                IsValid: isValid,
                StoredChecksum: record.DetailsChecksum,
                ComputedChecksum: computed,
                Message: isValid ? "Checksum is valid." : "Checksum mismatch detected.");
        }
    }

    public ExportFileResult ExportJournalEntries(JournalExportRequest request)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            if (actor.Role != AppRole.Administrator)
            {
                AppendAudit(
                    actor,
                    AuditActionType.Export,
                    AuditEntityType.Export,
                    entityId: null,
                    projectId: request.Filter.ProjectId,
                    AuditOutcome.Denied,
                    "User attempted to export journal entries without administrator permission.");
                throw new UnauthorizedAccessException("Only administrators can export journal entries.");
            }

            var rows = GetJournalEntriesForExportInternal(request.Filter)
                .OrderByDescending(e => e.CreatedAtUtc)
                .ToList();

            var fileName = $"journal-export-{DateTime.UtcNow:yyyyMMdd-HHmmss}.{(request.Format == ExportFormat.Csv ? "csv" : "json")}";
            var content = request.Format == ExportFormat.Csv
                ? BuildJournalCsv(request.Filter, rows)
                : BuildJournalJson(request.Filter, rows);

            AppendAudit(
                actor,
                AuditActionType.Export,
                AuditEntityType.Export,
                entityId: null,
                projectId: request.Filter.ProjectId,
                AuditOutcome.Success,
                $"Journal export generated ({request.Format}) with {rows.Count} row(s).");

            return new ExportFileResult(
                FileName: fileName,
                ContentType: request.Format == ExportFormat.Csv ? "text/csv" : "application/json",
                ContentText: content,
                RowCount: rows.Count,
                Summary: $"Journal export ({request.Format}) with {rows.Count} row(s).");
        }
    }

    public ExportFileResult ExportAuditLogs(AuditExportRequest request)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            if (actor.Role is not (AppRole.Administrator or AppRole.Auditor))
            {
                AppendAudit(
                    actor,
                    AuditActionType.Export,
                    AuditEntityType.Export,
                    entityId: null,
                    projectId: request.Filter.ProjectId,
                    AuditOutcome.Denied,
                    "User attempted to export audit logs without permission.");
                throw new UnauthorizedAccessException("Only administrators and auditors can export audit logs.");
            }

            var rows = SearchAuditLogs(request.Filter).ToList();
            var fileName = $"audit-export-{DateTime.UtcNow:yyyyMMdd-HHmmss}.{(request.Format == ExportFormat.Csv ? "csv" : "json")}";
            var content = request.Format == ExportFormat.Csv
                ? BuildAuditCsv(request.Filter, rows)
                : BuildAuditJson(request.Filter, rows);

            AppendAudit(
                actor,
                AuditActionType.Export,
                AuditEntityType.Export,
                entityId: null,
                projectId: request.Filter.ProjectId,
                AuditOutcome.Success,
                $"Audit export generated ({request.Format}) with {rows.Count} row(s).");

            return new ExportFileResult(
                FileName: fileName,
                ContentType: request.Format == ExportFormat.Csv ? "text/csv" : "application/json",
                ContentText: content,
                RowCount: rows.Count,
                Summary: $"Audit export ({request.Format}) with {rows.Count} row(s).");
        }
    }

    private void Seed()
    {
        _sqliteStore.Initialize();
        _logger.LogInformation("Initializing prototype app service state from SQLite store");

        var storedUsers = _sqliteStore.LoadUsers();
        foreach (var stored in storedUsers)
        {
            var user = new AppUser(
                stored.UserId,
                stored.Username,
                stored.DisplayName,
                stored.Role,
                stored.IsLocalAccount);

            _users.Add(user);
            _userGroups[user.UserId] = new HashSet<Guid>();

            if (stored.IsLocalAccount && !string.IsNullOrWhiteSpace(stored.PasswordHash))
            {
                _localPasswordHashes[user.UserId] = stored.PasswordHash;
            }
        }

        foreach (var storedProject in _sqliteStore.LoadProjects())
        {
            _projects.Add(new Project(
                storedProject.ProjectId,
                storedProject.Code,
                storedProject.Name,
                storedProject.Description));
        }

        foreach (var storedGroup in _sqliteStore.LoadGroups())
        {
            _groups.Add(new Group(
                storedGroup.GroupId,
                storedGroup.Name));
        }

        var knownUserIds = _users.Select(u => u.UserId).ToHashSet();
        var knownGroupIds = _groups.Select(g => g.GroupId).ToHashSet();
        var knownProjectIds = _projects.Select(p => p.ProjectId).ToHashSet();

        foreach (var storedUserGroup in _sqliteStore.LoadUserGroups())
        {
            if (!knownUserIds.Contains(storedUserGroup.UserId) || !knownGroupIds.Contains(storedUserGroup.GroupId))
            {
                continue;
            }

            if (!_userGroups.TryGetValue(storedUserGroup.UserId, out var memberships))
            {
                memberships = new HashSet<Guid>();
                _userGroups[storedUserGroup.UserId] = memberships;
            }

            memberships.Add(storedUserGroup.GroupId);
        }

        foreach (var storedProjectGroup in _sqliteStore.LoadProjectGroups())
        {
            if (!knownProjectIds.Contains(storedProjectGroup.ProjectId) || !knownGroupIds.Contains(storedProjectGroup.GroupId))
            {
                continue;
            }

            if (_projectGroups.Any(pg => pg.ProjectId == storedProjectGroup.ProjectId && pg.GroupId == storedProjectGroup.GroupId))
            {
                continue;
            }

            _projectGroups.Add(new ProjectGroupAssignment(
                storedProjectGroup.ProjectId,
                storedProjectGroup.GroupId));
        }

        _journalEntries.AddRange(_sqliteStore.LoadJournalEntries().Where(e => knownProjectIds.Contains(e.ProjectId)));
        _auditLogs.AddRange(_sqliteStore.LoadAuditLogs().Where(a => !a.ProjectId.HasValue || knownProjectIds.Contains(a.ProjectId.Value)));
        _logger.LogInformation(
            "Loaded state from SQLite: Users={Users}, Projects={Projects}, Groups={Groups}, Journals={Journals}, Audits={Audits}",
            _users.Count,
            _projects.Count,
            _groups.Count,
            _journalEntries.Count,
            _auditLogs.Count);

        EnsureBootstrapAdminConfiguredAccount();
        _currentUserId = Guid.Empty;
        _logger.LogInformation("No authenticated user session is active at startup.");
    }

    private JournalEntryRecord SeedJournalEntry(
        AppUser actor,
        Project project,
        DateTime createdAtUtc,
        string category,
        string subject,
        string description,
        string notes,
        string result)
    {
        var normalizedCategory = InputNormalizer.NormalizeRequired(category, nameof(category), FieldLimits.CategoryMax);
        var normalizedSubject = InputNormalizer.NormalizeRequired(subject, nameof(subject), FieldLimits.SubjectMax);
        var normalizedDescription = InputNormalizer.NormalizeRequired(description, nameof(description), FieldLimits.DescriptionMax);
        var normalizedNotes = InputNormalizer.NormalizeOptional(notes, FieldLimits.NotesMax);
        var normalizedResult = InputNormalizer.NormalizeOptional(result, FieldLimits.ResultMax);

        var record = new JournalEntryRecord
        {
            RecordId = Guid.NewGuid(),
            ProjectId = project.ProjectId,
            CreatedAtUtc = createdAtUtc,
            CreatedByUserId = actor.UserId,
            CreatedByUsername = actor.Username,
            CategoryCiphertext = _journalEncryptor.Encrypt(normalizedCategory),
            SubjectCiphertext = _journalEncryptor.Encrypt(normalizedSubject),
            DescriptionCiphertext = _journalEncryptor.Encrypt(normalizedDescription),
            NotesCiphertext = _journalEncryptor.Encrypt(normalizedNotes),
            ResultCiphertext = _journalEncryptor.Encrypt(normalizedResult),
            CategoryChecksum = _checksumService.ComputeHex(normalizedCategory),
            SubjectChecksum = _checksumService.ComputeHex(normalizedSubject),
            DescriptionChecksum = _checksumService.ComputeHex(normalizedDescription),
            NotesChecksum = _checksumService.ComputeHex(normalizedNotes),
            ResultChecksum = _checksumService.ComputeHex(normalizedResult),
            FullRecordChecksum = _checksumService.ComputeHex(BuildFullRecordChecksumMaterial(
                project.ProjectId,
                actor.UserId,
                createdAtUtc,
                normalizedCategory,
                normalizedSubject,
                normalizedDescription,
                normalizedNotes,
                normalizedResult))
        };

        _journalEntries.Add(record);
        _sqliteStore.UpsertJournalEntry(record);
        AppendAudit(actor, AuditActionType.Create, AuditEntityType.JournalEntry, record.RecordId.ToString(), project.ProjectId, AuditOutcome.Success, $"Seed entry created in project '{project.Code}'.");
        return record;
    }

    private static string BuildFullRecordChecksumMaterial(
        Guid projectId,
        Guid createdByUserId,
        DateTime createdAtUtc,
        string category,
        string subject,
        string description,
        string notes,
        string result)
        => string.Join('\u001F', new[]
        {
            projectId.ToString("D"),
            createdByUserId.ToString("D"),
            createdAtUtc.ToUniversalTime().ToString("O"),
            category,
            subject,
            description,
            notes,
            result
        });

    private void ValidateRequest(CreateJournalEntryRequest request)
    {
        var validationContext = new ValidationContext(request);
        Validator.ValidateObject(request, validationContext, validateAllProperties: true);

        if (request.ProjectId == Guid.Empty)
        {
            throw new ValidationException("Project is required.");
        }
    }

    private JournalEntryView MapJournalEntry(JournalEntryRecord record)
    {
        var project = _projects.First(p => p.ProjectId == record.ProjectId);
        return new JournalEntryView(
            RecordId: record.RecordId,
            ProjectId: record.ProjectId,
            ProjectCode: project.Code,
            ProjectName: project.Name,
            CreatedAtUtc: record.CreatedAtUtc,
            CreatedBy: record.CreatedByUsername,
            Action: _journalEncryptor.Decrypt(record.CategoryCiphertext),
            Subject: _journalEncryptor.Decrypt(record.SubjectCiphertext),
            Description: _journalEncryptor.Decrypt(record.DescriptionCiphertext),
            Notes: _journalEncryptor.Decrypt(record.NotesCiphertext),
            IsSoftDeleted: record.IsSoftDeleted,
            DeletedAtUtc: record.SoftDelete?.DeletedAtUtc,
            DeletedBy: record.SoftDelete?.DeletedByUsername,
            DeleteReason: record.SoftDelete?.Reason,
            FullRecordChecksum: record.FullRecordChecksum);
    }

    private AuditLogView MapAuditLog(AuditLogRecord record)
    {
        var project = record.ProjectId.HasValue
            ? _projects.FirstOrDefault(p => p.ProjectId == record.ProjectId.Value)
            : null;

        return new AuditLogView(
            AuditId: record.AuditId,
            TimestampUtc: record.TimestampUtc,
            ActorUsername: record.ActorUsername,
            Action: record.Action,
            EntityType: record.EntityType,
            EntityId: record.EntityId,
            ProjectId: record.ProjectId,
            ProjectCode: project?.Code,
            Outcome: record.Outcome,
            Details: _auditEncryptor.Decrypt(record.DetailsCiphertext),
            DetailsChecksum: record.DetailsChecksum,
            RelatedJournalEntry: TryMapRelatedJournalEntry(record));
    }

    private AuditRelatedJournalEntryView? TryMapRelatedJournalEntry(AuditLogRecord auditRecord)
    {
        if (auditRecord.EntityType != AuditEntityType.JournalEntry ||
            !Guid.TryParse(auditRecord.EntityId, out var recordId))
        {
            return null;
        }

        var journalRecord = _journalEntries.FirstOrDefault(j => j.RecordId == recordId);
        if (journalRecord is null)
        {
            return null;
        }

        var project = _projects.FirstOrDefault(p => p.ProjectId == journalRecord.ProjectId);
        var action = _journalEncryptor.Decrypt(journalRecord.CategoryCiphertext);
        var subject = _journalEncryptor.Decrypt(journalRecord.SubjectCiphertext);
        var description = _journalEncryptor.Decrypt(journalRecord.DescriptionCiphertext);
        var notes = _journalEncryptor.Decrypt(journalRecord.NotesCiphertext);

        return new AuditRelatedJournalEntryView(
            RecordId: journalRecord.RecordId,
            ProjectCode: project?.Code ?? "(unknown)",
            CreatedAtUtc: journalRecord.CreatedAtUtc,
            CreatedBy: journalRecord.CreatedByUsername,
            Action: action,
            Subject: subject,
            Description: description,
            Notes: notes,
            IsSoftDeleted: journalRecord.IsSoftDeleted);
    }

    private void AppendAudit(
        AppUser? actor,
        AuditActionType action,
        AuditEntityType entityType,
        string? entityId,
        Guid? projectId,
        AuditOutcome outcome,
        string details)
    {
        var normalizedDetails = InputNormalizer.Normalize(details);

        var auditRecord = new AuditLogRecord(
            AuditId: Guid.NewGuid(),
            TimestampUtc: DateTime.UtcNow,
            ActorUserId: actor?.UserId,
            ActorUsername: actor?.Username ?? "system",
            Action: action,
            EntityType: entityType,
            EntityId: entityId,
            ProjectId: projectId,
            Outcome: outcome,
            DetailsCiphertext: _auditEncryptor.Encrypt(normalizedDetails),
            DetailsChecksum: _checksumService.ComputeHex(normalizedDetails));

        _auditLogs.Add(auditRecord);
        _sqliteStore.InsertAuditLog(auditRecord);
    }

    private IReadOnlyList<JournalEntryView> GetJournalEntriesForExportInternal(JournalExportFilter filter)
    {
        var rows = _journalEntries
            .Where(e => !filter.ProjectId.HasValue || e.ProjectId == filter.ProjectId.Value)
            .Where(e => !filter.FromUtc.HasValue || e.CreatedAtUtc >= filter.FromUtc.Value)
            .Where(e => !filter.ToUtc.HasValue || e.CreatedAtUtc <= filter.ToUtc.Value)
            .Where(e => filter.IncludeSoftDeleted || !e.IsSoftDeleted)
            .Select(MapJournalEntry)
            .ToList();

        return rows;
    }

    private string BuildJournalCsv(JournalExportFilter filter, IReadOnlyList<JournalEntryView> rows)
    {
        var sb = new StringBuilder();
        AppendCsvMetadata(sb, "JournalEntries", filter.ProjectId, filter.FromUtc, filter.ToUtc, filter.IncludeSoftDeleted);
        sb.AppendLine("RecordId,CreatedAtUtc,CreatedBy,ProjectCode,ProjectName,Action,Subject,Description,Notes,IsSoftDeleted,DeletedAtUtc,DeletedBy,DeleteReason,FullRecordChecksum");

        foreach (var row in rows)
        {
            sb.AppendLine(string.Join(',',
                Csv(row.RecordId),
                Csv(row.CreatedAtUtc.ToString("O")),
                Csv(row.CreatedBy),
                Csv(row.ProjectCode),
                Csv(row.ProjectName),
                Csv(row.Action),
                Csv(row.Subject),
                Csv(row.Description),
                Csv(row.Notes),
                Csv(row.IsSoftDeleted),
                Csv(row.DeletedAtUtc?.ToString("O") ?? string.Empty),
                Csv(row.DeletedBy ?? string.Empty),
                Csv(row.DeleteReason ?? string.Empty),
                Csv(row.FullRecordChecksum)));
        }

        return sb.ToString();
    }

    private string BuildJournalJson(JournalExportFilter filter, IReadOnlyList<JournalEntryView> rows)
    {
        var payload = new
        {
            exportType = "JournalEntries",
            exportedAtUtc = DateTime.UtcNow,
            filter = new
            {
                filter.ProjectId,
                filter.FromUtc,
                filter.ToUtc,
                filter.IncludeSoftDeleted
            },
            rowCount = rows.Count,
            rows
        };

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    private string BuildAuditCsv(AuditSearchFilter filter, IReadOnlyList<AuditLogView> rows)
    {
        var sb = new StringBuilder();
        AppendCsvMetadata(sb, "AuditLogs", filter.ProjectId, filter.FromUtc, filter.ToUtc, includeSoftDeleted: null);
        if (!string.IsNullOrWhiteSpace(filter.ActorUsername))
        {
            sb.AppendLine($"# ActorUsername={CsvString(filter.ActorUsername)}");
        }

        if (filter.Action.HasValue)
        {
            sb.AppendLine($"# Action={filter.Action.Value}");
        }

        if (filter.EntityType.HasValue)
        {
            sb.AppendLine($"# EntityType={filter.EntityType.Value}");
        }

        if (filter.Outcome.HasValue)
        {
            sb.AppendLine($"# Outcome={filter.Outcome.Value}");
        }

        sb.AppendLine("AuditId,TimestampUtc,ActorUsername,Action,EntityType,EntityId,ProjectId,ProjectCode,Outcome,Details,DetailsChecksum");

        foreach (var row in rows)
        {
            sb.AppendLine(string.Join(',',
                Csv(row.AuditId),
                Csv(row.TimestampUtc.ToString("O")),
                Csv(row.ActorUsername),
                Csv(row.Action),
                Csv(row.EntityType),
                Csv(row.EntityId ?? string.Empty),
                Csv(row.ProjectId?.ToString() ?? string.Empty),
                Csv(row.ProjectCode ?? string.Empty),
                Csv(row.Outcome),
                Csv(row.Details),
                Csv(row.DetailsChecksum)));
        }

        return sb.ToString();
    }

    private string BuildAuditJson(AuditSearchFilter filter, IReadOnlyList<AuditLogView> rows)
    {
        var payload = new
        {
            exportType = "AuditLogs",
            exportedAtUtc = DateTime.UtcNow,
            filter = new
            {
                filter.FromUtc,
                filter.ToUtc,
                filter.ActorUsername,
                filter.ProjectId,
                filter.Action,
                filter.EntityType,
                filter.Outcome
            },
            rowCount = rows.Count,
            rows
        };

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    private static void AppendCsvMetadata(
        StringBuilder sb,
        string exportType,
        Guid? projectId,
        DateTime? fromUtc,
        DateTime? toUtc,
        bool? includeSoftDeleted)
    {
        sb.AppendLine($"# ExportType={exportType}");
        sb.AppendLine($"# ExportedAtUtc={DateTime.UtcNow:O}");
        sb.AppendLine($"# ProjectId={(projectId?.ToString() ?? "Any")}");
        sb.AppendLine($"# FromUtc={(fromUtc?.ToString("O") ?? "Any")}");
        sb.AppendLine($"# ToUtc={(toUtc?.ToString("O") ?? "Any")}");
        if (includeSoftDeleted.HasValue)
        {
            sb.AppendLine($"# IncludeSoftDeleted={includeSoftDeleted.Value}");
        }
    }

    private static string Csv(object? value)
        => CsvString(value?.ToString() ?? string.Empty);

    private static string CsvString(string value)
    {
        var escaped = value.Replace("\"", "\"\"", StringComparison.Ordinal);
        return $"\"{escaped}\"";
    }

    private AppUser RequireAdmin()
    {
        var actor = GetCurrentUserInternal();
        if (actor.Role != AppRole.Administrator)
        {
            throw new UnauthorizedAccessException("Administrator role is required for this operation.");
        }

        return actor;
    }

    private static void ValidateAdminRequest(object request)
    {
        var validationContext = new ValidationContext(request);
        Validator.ValidateObject(request, validationContext, validateAllProperties: true);
    }

    private UserContext ToUserContext(AppUser user)
        => new(
            user.UserId,
            user.Username,
            user.DisplayName,
            user.Role,
            _userGroups.TryGetValue(user.UserId, out var groups) ? groups.Order().ToList() : Array.Empty<Guid>());

    private AppUser GetCurrentUserInternal()
    {
        if (_enableAspNetIdentity && TryGetCurrentPrincipal(out var principal))
        {
            if (TryResolveOrProvisionUserFromPrincipal(principal, out var principalUser))
            {
                return principalUser;
            }
        }

        TryRestoreCurrentUserFromCookie();
        return _users.FirstOrDefault(u => u.UserId == _currentUserId)
           ?? throw new UnauthorizedAccessException("Authentication is required.");
    }

    private void TryRestoreCurrentUserFromCookie()
    {
        if (_enableAspNetIdentity)
        {
            return;
        }

        if (_currentUserId != Guid.Empty || _httpContextAccessor is null || _sessionRegistry is null)
        {
            return;
        }

        var context = _httpContextAccessor.HttpContext;
        if (context is null)
        {
            return;
        }

        if (!context.Request.Cookies.TryGetValue(_securitySettings.SessionCookieName, out var sessionToken) ||
            string.IsNullOrWhiteSpace(sessionToken))
        {
            return;
        }

        if (!_sessionRegistry.TryGetUserId(sessionToken, out var userId))
        {
            return;
        }

        var sessionUser = _users.FirstOrDefault(u => u.UserId == userId);
        if (sessionUser is null)
        {
            _sessionRegistry.Remove(sessionToken);
            return;
        }

        _currentUserId = sessionUser.UserId;
        _logger.LogInformation("Current user restored from session cookie for username {Username}", sessionUser.Username);
    }

    private LoginResult TryLocalLoginWithIdentity(string normalizedUsername, string password)
    {
        if (_identitySignInManager is null || _identityUserManager is null)
        {
            return new LoginResult(false, "ASP.NET Identity is enabled in config, but Identity services are unavailable.", null);
        }

        var appUser = _users.FirstOrDefault(u =>
            u.IsLocalAccount &&
            string.Equals(u.Username, normalizedUsername, StringComparison.OrdinalIgnoreCase));

        if (appUser is null)
        {
            AppendAudit(
                actor: null,
                AuditActionType.Login,
                AuditEntityType.Authentication,
                entityId: null,
                projectId: null,
                AuditOutcome.Failure,
                $"Failed local login attempt for username '{normalizedUsername}'.");
            return new LoginResult(false, "Invalid username or password.", null);
        }

        var signInResult = _identitySignInManager.PasswordSignInAsync(
            userName: normalizedUsername,
            password: password,
            isPersistent: false,
            lockoutOnFailure: false).GetAwaiter().GetResult();

        if (!signInResult.Succeeded)
        {
            _logger.LogWarning("Local login failed for user {Username} via Identity", normalizedUsername);
            AppendAudit(
                actor: appUser,
                AuditActionType.Login,
                AuditEntityType.Authentication,
                entityId: appUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Failure,
                $"Failed local login attempt for user '{appUser.Username}'.");
            return new LoginResult(false, "Invalid username or password.", null);
        }

        var identityUser = _identityUserManager.FindByNameAsync(normalizedUsername).GetAwaiter().GetResult();
        if (identityUser is not null)
        {
            SyncAppUserMetadataFromIdentity(identityUser);
        }

        _logger.LogInformation("Local login succeeded for user {Username} via Identity", normalizedUsername);
        AppendAudit(
            appUser,
            AuditActionType.Login,
            AuditEntityType.Authentication,
            entityId: appUser.UserId.ToString(),
            projectId: null,
            AuditOutcome.Success,
            $"User '{appUser.Username}' logged in.");
        return new LoginResult(true, $"Logged in as {appUser.DisplayName}.", ToUserContext(appUser));
    }

    private PasswordChangeResult ChangeCurrentUserPasswordWithIdentity(AppUser actor, ChangePasswordRequest request)
    {
        if (_identityUserManager is null)
        {
            return new PasswordChangeResult(false, "Identity services are unavailable.");
        }

        var currentPassword = request.CurrentPassword ?? string.Empty;
        var newPassword = request.NewPassword ?? string.Empty;
        if (string.IsNullOrWhiteSpace(newPassword))
        {
            return new PasswordChangeResult(false, "New password is required.");
        }

        if (TryGetPasswordPolicyViolationMessage(newPassword, "New password") is { } passwordPolicyError)
        {
            return new PasswordChangeResult(false, passwordPolicyError);
        }

        if (string.Equals(currentPassword, newPassword, StringComparison.Ordinal))
        {
            return new PasswordChangeResult(false, "New password must be different from the current password.");
        }

        var identityUser = _identityUserManager.FindByNameAsync(actor.Username).GetAwaiter().GetResult();
        if (identityUser is null)
        {
            AppendAudit(actor, AuditActionType.Update, AuditEntityType.Authentication, actor.UserId.ToString(), null, AuditOutcome.Failure,
                "Password change failed because the Identity user record was not found.");
            return new PasswordChangeResult(false, "Current account does not have a local password configured.");
        }

        var result = _identityUserManager.ChangePasswordAsync(identityUser, currentPassword, newPassword).GetAwaiter().GetResult();
        if (!result.Succeeded)
        {
            var error = string.Join("; ", result.Errors.Select(e => e.Description));
            _logger.LogWarning("Password change failed for user {Username} via Identity: {Error}", actor.Username, error);
            AppendAudit(actor, AuditActionType.Update, AuditEntityType.Authentication, actor.UserId.ToString(), null, AuditOutcome.Failure,
                "Password change failed because the current password did not match.");
            return new PasswordChangeResult(false, error.Contains("Incorrect", StringComparison.OrdinalIgnoreCase)
                ? "Current password is incorrect."
                : error);
        }

        _sqliteStore.UpsertUser(new StoredUserRow(
            actor.UserId,
            actor.Username,
            actor.DisplayName,
            actor.Role,
            actor.IsLocalAccount,
            PasswordHash: null));

        _logger.LogInformation("Password change succeeded for user {Username} via Identity", actor.Username);
        AppendAudit(actor, AuditActionType.Update, AuditEntityType.Authentication, actor.UserId.ToString(), null, AuditOutcome.Success,
            "Local password changed for current user.");
        return new PasswordChangeResult(true, "Password changed successfully.");
    }

    private PasswordChangeResult ResetLocalUserPasswordWithIdentity(AppUser actor, AppUser targetUser, string? newPassword)
    {
        if (_identityUserManager is null)
        {
            return new PasswordChangeResult(false, "Identity services are unavailable.");
        }

        EnsurePasswordMeetsPolicy(newPassword, "Reset password");
        var candidatePassword = newPassword ?? string.Empty;

        var identityUser = _identityUserManager.FindByNameAsync(targetUser.Username).GetAwaiter().GetResult();
        if (identityUser is null)
        {
            return new PasswordChangeResult(false, "Selected user does not have an Identity local account.");
        }

        var resetToken = _identityUserManager.GeneratePasswordResetTokenAsync(identityUser).GetAwaiter().GetResult();
        var result = _identityUserManager.ResetPasswordAsync(identityUser, resetToken, candidatePassword).GetAwaiter().GetResult();
        if (!result.Succeeded)
        {
            var error = string.Join("; ", result.Errors.Select(e => e.Description));
            return new PasswordChangeResult(false, error);
        }

        _sqliteStore.UpsertUser(new StoredUserRow(
            targetUser.UserId,
            targetUser.Username,
            targetUser.DisplayName,
            targetUser.Role,
            targetUser.IsLocalAccount,
            PasswordHash: null));

        _logger.LogInformation(
            "Password reset by admin {ActorUsername} for user {TargetUsername} via Identity",
            actor.Username,
            targetUser.Username);

        AppendAudit(
            actor,
            AuditActionType.Update,
            AuditEntityType.Authentication,
            entityId: targetUser.UserId.ToString(),
            projectId: null,
            AuditOutcome.Success,
            $"Administrator '{actor.Username}' reset local password for user '{targetUser.Username}'.");

        return new PasswordChangeResult(true, $"Password reset for '{targetUser.Username}'.");
    }

    private void CreateOrUpdateIdentityLocalUser(AppUser appUser, string password)
    {
        if (_identityUserManager is null)
        {
            throw new InvalidOperationException("ASP.NET Identity is enabled but UserManager is unavailable.");
        }

        var existing = _identityUserManager.FindByNameAsync(appUser.Username).GetAwaiter().GetResult();
        if (existing is not null)
        {
            throw new InvalidOperationException($"An Identity user with username '{appUser.Username}' already exists.");
        }

        var identityUser = new SecureJournalIdentityUser
        {
            UserName = appUser.Username,
            Email = $"{appUser.Username}@local.invalid",
            EmailConfirmed = true,
            DisplayName = appUser.DisplayName,
            IsBootstrapAdmin = false
        };

        var create = _identityUserManager.CreateAsync(identityUser, password).GetAwaiter().GetResult();
        if (!create.Succeeded)
        {
            var error = string.Join("; ", create.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed creating Identity user '{appUser.Username}': {error}");
        }

        SyncIdentityUserRoles(identityUser, appUser.Role);
    }

    private void EnsureIdentityExternalUser(AppUser appUser)
    {
        // External/OIDC users authenticate at the IdP and may not exist in the local Identity store.
        // We still keep app metadata for authorization/project-group mapping.
        if (_identityUserManager is null)
        {
            return;
        }

        var existing = _identityUserManager.FindByNameAsync(appUser.Username).GetAwaiter().GetResult();
        if (existing is null)
        {
            return;
        }

        existing.DisplayName = appUser.DisplayName;
        _identityUserManager.UpdateAsync(existing).GetAwaiter().GetResult();
        SyncIdentityUserRoles(existing, appUser.Role);
    }

    private void SyncIdentityUserRoles(SecureJournalIdentityUser identityUser, AppRole appRole)
    {
        if (_identityUserManager is null)
        {
            return;
        }

        var desiredRole = appRole.ToString();
        var existingRoles = _identityUserManager.GetRolesAsync(identityUser).GetAwaiter().GetResult();
        foreach (var role in existingRoles.Where(r => r is "Administrator" or "ProjectUser" or "Auditor"))
        {
            if (!string.Equals(role, desiredRole, StringComparison.OrdinalIgnoreCase))
            {
                _identityUserManager.RemoveFromRoleAsync(identityUser, role).GetAwaiter().GetResult();
            }
        }

        if (!existingRoles.Any(r => string.Equals(r, desiredRole, StringComparison.OrdinalIgnoreCase)))
        {
            var addRole = _identityUserManager.AddToRoleAsync(identityUser, desiredRole).GetAwaiter().GetResult();
            if (!addRole.Succeeded)
            {
                var error = string.Join("; ", addRole.Errors.Select(e => e.Description));
                throw new InvalidOperationException($"Failed assigning Identity role '{desiredRole}' to '{identityUser.UserName}': {error}");
            }
        }
    }

    private bool TryGetCurrentPrincipal(out ClaimsPrincipal principal)
    {
        var httpContextUser = _httpContextAccessor?.HttpContext?.User;
        if (httpContextUser?.Identity?.IsAuthenticated == true)
        {
            principal = httpContextUser;
            return true;
        }

        if (_authenticationStateProvider is not null)
        {
            try
            {
                var authState = _authenticationStateProvider.GetAuthenticationStateAsync().GetAwaiter().GetResult();
                if (authState.User.Identity?.IsAuthenticated == true)
                {
                    principal = authState.User;
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to resolve Blazor AuthenticationState principal.");
            }
        }

        principal = new ClaimsPrincipal();
        return false;
    }

    private bool TryResolveOrProvisionUserFromPrincipal(ClaimsPrincipal principal, out AppUser user)
    {
        user = default!;
        var username = GetNormalizedPrincipalUsername(principal);
        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        var existing = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
        var mappedRole = GetRoleFromPrincipal(principal, existing?.Role);
        var mappedDisplayName = GetDisplayNameFromPrincipal(principal, username);
        var isLocalPrincipal = existing?.IsLocalAccount ?? IsLocalPrincipal(principal);

        if (existing is null)
        {
            var created = new AppUser(Guid.NewGuid(), username, mappedDisplayName, mappedRole, isLocalPrincipal);
            _users.Add(created);
            _userGroups[created.UserId] = new HashSet<Guid>();
            _sqliteStore.UpsertUser(new StoredUserRow(created.UserId, created.Username, created.DisplayName, created.Role, created.IsLocalAccount, null));
            _logger.LogInformation("App user provisioned from authenticated principal: {Username} ({Role})", created.Username, created.Role);
            AppendAudit(
                created,
                AuditActionType.Configure,
                AuditEntityType.User,
                entityId: created.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                "App user provisioned from authenticated Identity/OIDC principal.");
            user = created;
            return true;
        }

        var needsUpdate =
            !string.Equals(existing.DisplayName, mappedDisplayName, StringComparison.Ordinal) ||
            existing.Role != mappedRole ||
            (existing.IsLocalAccount && !isLocalPrincipal && _enableOidc); // preserve local flag unless clearly external-only

        if (needsUpdate)
        {
            var updated = existing with { DisplayName = mappedDisplayName, Role = mappedRole };
            var index = _users.FindIndex(u => u.UserId == existing.UserId);
            if (index >= 0)
            {
                _users[index] = updated;
            }

            _sqliteStore.UpsertUser(new StoredUserRow(updated.UserId, updated.Username, updated.DisplayName, updated.Role, updated.IsLocalAccount, existing.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updated.UserId) : null));
            user = updated;
            return true;
        }

        user = existing;
        return true;
    }

    private void SyncAppUserMetadataFromIdentity(SecureJournalIdentityUser identityUser)
    {
        var appUser = _users.FirstOrDefault(u => string.Equals(u.Username, identityUser.UserName, StringComparison.OrdinalIgnoreCase));
        if (appUser is null)
        {
            return;
        }

        var roles = _identityUserManager?.GetRolesAsync(identityUser).GetAwaiter().GetResult() ?? Array.Empty<string>();
        var role = roles.Any(r => string.Equals(r, nameof(AppRole.Administrator), StringComparison.OrdinalIgnoreCase))
            ? AppRole.Administrator
            : roles.Any(r => string.Equals(r, nameof(AppRole.Auditor), StringComparison.OrdinalIgnoreCase))
                ? AppRole.Auditor
                : AppRole.ProjectUser;
        var displayName = string.IsNullOrWhiteSpace(identityUser.DisplayName) ? appUser.DisplayName : identityUser.DisplayName;

        if (appUser.Role == role && string.Equals(appUser.DisplayName, displayName, StringComparison.Ordinal))
        {
            return;
        }

        var updated = appUser with { Role = role, DisplayName = displayName };
        var index = _users.FindIndex(u => u.UserId == appUser.UserId);
        if (index >= 0)
        {
            _users[index] = updated;
        }

        _sqliteStore.UpsertUser(new StoredUserRow(updated.UserId, updated.Username, updated.DisplayName, updated.Role, updated.IsLocalAccount, null));
    }

    private static string? GetNormalizedPrincipalUsername(ClaimsPrincipal principal)
    {
        var raw = principal.FindFirstValue("preferred_username")
                  ?? principal.FindFirstValue(ClaimTypes.Upn)
                  ?? principal.FindFirstValue(ClaimTypes.Email)
                  ?? principal.FindFirstValue("email")
                  ?? principal.Identity?.Name
                  ?? principal.FindFirstValue(ClaimTypes.Name);

        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return raw.Trim().ToLowerInvariant();
    }

    private static string GetDisplayNameFromPrincipal(ClaimsPrincipal principal, string fallbackUsername)
        => (principal.FindFirstValue("name")
            ?? principal.FindFirstValue(ClaimTypes.Name)
            ?? fallbackUsername).Trim();

    private static AppRole GetRoleFromPrincipal(ClaimsPrincipal principal, AppRole? fallbackRole)
    {
        if (principal.IsInRole(nameof(AppRole.Administrator)))
        {
            return AppRole.Administrator;
        }

        if (principal.IsInRole(nameof(AppRole.Auditor)))
        {
            return AppRole.Auditor;
        }

        if (principal.IsInRole(nameof(AppRole.ProjectUser)))
        {
            return AppRole.ProjectUser;
        }

        return fallbackRole ?? AppRole.ProjectUser;
    }

    private bool IsLocalPrincipal(ClaimsPrincipal principal)
    {
        var username = GetNormalizedPrincipalUsername(principal);
        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        if (_identityUserManager is null)
        {
            return false;
        }

        return _identityUserManager.FindByNameAsync(username).GetAwaiter().GetResult() is not null;
    }

    private void EnsurePasswordMeetsPolicy(string? password, string passwordLabel)
    {
        if (TryGetPasswordPolicyViolationMessage(password, passwordLabel) is { } error)
        {
            throw new InvalidOperationException(error);
        }
    }

    private string? TryGetPasswordPolicyViolationMessage(string? password, string passwordLabel)
    {
        var candidate = password ?? string.Empty;
        if (candidate.Length < _securitySettings.LocalPasswordMinLength)
        {
            return $"{passwordLabel} must be at least {_securitySettings.LocalPasswordMinLength} characters.";
        }

        if (_securitySettings.LocalPasswordRequireUppercase && !candidate.Any(char.IsUpper))
        {
            return $"{passwordLabel} must include at least one uppercase letter.";
        }

        if (_securitySettings.LocalPasswordRequireLowercase && !candidate.Any(char.IsLower))
        {
            return $"{passwordLabel} must include at least one lowercase letter.";
        }

        if (_securitySettings.LocalPasswordRequireDigit && !candidate.Any(char.IsDigit))
        {
            return $"{passwordLabel} must include at least one digit.";
        }

        if (_securitySettings.LocalPasswordRequireNonAlphanumeric && !candidate.Any(ch => !char.IsLetterOrDigit(ch)))
        {
            return $"{passwordLabel} must include at least one special character.";
        }

        return null;
    }

    private HashSet<Guid> GetReadableProjectIds(AppUser user)
    {
        if (user.Role is AppRole.Administrator or AppRole.Auditor)
        {
            return _projects.Select(p => p.ProjectId).ToHashSet();
        }

        if (!_userGroups.TryGetValue(user.UserId, out var groupIds) || groupIds.Count == 0)
        {
            return new HashSet<Guid>();
        }

        return _projectGroups
            .Where(pg => groupIds.Contains(pg.GroupId))
            .Select(pg => pg.ProjectId)
            .ToHashSet();
    }

    private bool CanAccessProject(AppUser user, Guid projectId)
        => GetReadableProjectIds(user).Contains(projectId);

    private static bool CanSeeSoftDeletedEntries(AppUser user)
        => user.Role == AppRole.Administrator;

    private bool IsUserInGroup(Guid userId, Guid groupId)
        => _userGroups.TryGetValue(userId, out var groups) && groups.Contains(groupId);

    private IReadOnlyList<string> GetAssignedGroupNames(Guid projectId)
        => _projectGroups
            .Where(pg => pg.ProjectId == projectId)
            .Join(_groups, pg => pg.GroupId, g => g.GroupId, (_, g) => g.Name)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private IReadOnlyList<string> GetUserGroupNames(Guid userId)
    {
        if (!_userGroups.TryGetValue(userId, out var groupIds))
        {
            return Array.Empty<string>();
        }

        return _groups
            .Where(g => groupIds.Contains(g.GroupId))
            .Select(g => g.Name)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private string GenerateUniqueProjectCode()
    {
        var nextOrdinal = 1;
        if (_projects.Count > 0)
        {
            var maxExistingOrdinal = _projects
                .Select(p =>
                {
                    const string prefix = "PRJ";
                    if (!p.Code.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        return 0;
                    }

                    return int.TryParse(p.Code[prefix.Length..], out var parsed) ? parsed : 0;
                })
                .DefaultIfEmpty(0)
                .Max();

            nextOrdinal = Math.Max(1, maxExistingOrdinal + 1);
        }

        while (true)
        {
            var candidate = $"PRJ{nextOrdinal:D4}";
            if (_projects.All(p => !string.Equals(p.Code, candidate, StringComparison.OrdinalIgnoreCase)))
            {
                return candidate;
            }

            nextOrdinal++;
        }
    }

    private AppUser EnsureBootstrapAdminConfiguredAccount()
    {
        var bootstrapUser = _users.FirstOrDefault(u =>
            string.Equals(u.Username, _bootstrapAdmin.Username, StringComparison.OrdinalIgnoreCase));

        if (bootstrapUser is null)
        {
            var preferredId = Guid.Parse("D2B1164F-1262-43E5-9E0F-84F7A2A55001");
            var bootstrapUserId = _users.Any(u => u.UserId == preferredId) ? Guid.NewGuid() : preferredId;
            bootstrapUser = new AppUser(
                bootstrapUserId,
                _bootstrapAdmin.Username,
                _bootstrapAdmin.DisplayName,
                AppRole.Administrator,
                IsLocalAccount: true);

            _users.Add(bootstrapUser);
            _userGroups[bootstrapUser.UserId] = new HashSet<Guid>();

            var passwordHash = _passwordHasher.HashPassword(bootstrapUser, _bootstrapAdmin.Password);
            _localPasswordHashes[bootstrapUser.UserId] = passwordHash;

            _sqliteStore.UpsertUser(new StoredUserRow(
                bootstrapUser.UserId,
                bootstrapUser.Username,
                bootstrapUser.DisplayName,
                bootstrapUser.Role,
                bootstrapUser.IsLocalAccount,
                passwordHash));

            _logger.LogInformation("Bootstrap administrator {Username} created from appsettings", bootstrapUser.Username);

            AppendAudit(
                bootstrapUser,
                AuditActionType.Configure,
                AuditEntityType.User,
                entityId: bootstrapUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                "Bootstrap administrator user created from appsettings.");

            return bootstrapUser;
        }

        if (!_userGroups.ContainsKey(bootstrapUser.UserId))
        {
            _userGroups[bootstrapUser.UserId] = new HashSet<Guid>();
        }

        var updatedBootstrapUser = bootstrapUser;
        var metadataUpdated = false;
        if (bootstrapUser.Role != AppRole.Administrator ||
            !bootstrapUser.IsLocalAccount ||
            !string.Equals(bootstrapUser.DisplayName, _bootstrapAdmin.DisplayName, StringComparison.Ordinal))
        {
            updatedBootstrapUser = new AppUser(
                bootstrapUser.UserId,
                bootstrapUser.Username,
                _bootstrapAdmin.DisplayName,
                AppRole.Administrator,
                IsLocalAccount: true);

            var index = _users.FindIndex(u => u.UserId == bootstrapUser.UserId);
            if (index >= 0)
            {
                _users[index] = updatedBootstrapUser;
            }

            metadataUpdated = true;
            _logger.LogWarning(
                "Bootstrap admin account {Username} metadata was normalized from appsettings (Role/DisplayName/LocalAccount).",
                updatedBootstrapUser.Username);
        }

        EnsurePasswordMeetsPolicy(_bootstrapAdmin.Password, "Bootstrap admin password");

        _localPasswordHashes.TryGetValue(updatedBootstrapUser.UserId, out var existingPasswordHash);
        var shouldSyncPassword = _bootstrapAdmin.SyncPasswordOnStartup || string.IsNullOrWhiteSpace(existingPasswordHash);
        var passwordUpdated = false;
        var passwordHashToPersist = existingPasswordHash;

        if (shouldSyncPassword)
        {
            passwordHashToPersist = _passwordHasher.HashPassword(updatedBootstrapUser, _bootstrapAdmin.Password);
            _localPasswordHashes[updatedBootstrapUser.UserId] = passwordHashToPersist;
            passwordUpdated = true;

            _logger.LogInformation(
                "Bootstrap admin password {Action} from appsettings for username {Username}",
                _bootstrapAdmin.SyncPasswordOnStartup ? "synced" : "initialized",
                updatedBootstrapUser.Username);
        }

        if (metadataUpdated || passwordUpdated)
        {
            _sqliteStore.UpsertUser(new StoredUserRow(
                updatedBootstrapUser.UserId,
                updatedBootstrapUser.Username,
                updatedBootstrapUser.DisplayName,
                updatedBootstrapUser.Role,
                updatedBootstrapUser.IsLocalAccount,
                passwordHashToPersist));

            AppendAudit(
                updatedBootstrapUser,
                AuditActionType.Configure,
                AuditEntityType.User,
                entityId: updatedBootstrapUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                passwordUpdated
                    ? "Bootstrap administrator account synchronized from appsettings (metadata/password)."
                    : "Bootstrap administrator account metadata synchronized from appsettings.");
        }

        return updatedBootstrapUser;
    }

    private sealed record BootstrapAdminSettings(
        string Username,
        string DisplayName,
        string Password,
        bool SyncPasswordOnStartup)
    {
        public static BootstrapAdminSettings FromConfiguration(IConfiguration configuration)
        {
            var username = (configuration["BootstrapAdmin:Username"] ?? "admin").Trim().ToLowerInvariant();
            var displayName = (configuration["BootstrapAdmin:DisplayName"] ?? "Startup Admin").Trim();
            var password = configuration["BootstrapAdmin:Password"] ?? "ChangeMe123!";
            var syncPasswordOnStartup = bool.TryParse(configuration["BootstrapAdmin:SyncPasswordOnStartup"], out var parsedSync)
                ? parsedSync
                : false;

            if (string.IsNullOrWhiteSpace(username))
            {
                username = "admin";
            }

            if (string.IsNullOrWhiteSpace(displayName))
            {
                displayName = "Startup Admin";
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                password = "ChangeMe123!";
            }

            return new BootstrapAdminSettings(username, displayName, password, syncPasswordOnStartup);
        }
    }

    private sealed record SecuritySettings(
        int LocalPasswordMinLength,
        bool LocalPasswordRequireUppercase,
        bool LocalPasswordRequireLowercase,
        bool LocalPasswordRequireDigit,
        bool LocalPasswordRequireNonAlphanumeric,
        string SessionCookieName,
        int SessionCookieHours)
    {
        public static SecuritySettings FromConfiguration(IConfiguration configuration)
        {
            var configured = int.TryParse(configuration["Security:LocalPasswordMinLength"], out var parsed)
                ? parsed
                : 8;
            var sessionCookieName = (configuration["Security:SessionCookieName"] ?? "SecureJournal.Session").Trim();
            var sessionCookieHours = int.TryParse(configuration["Security:SessionCookieHours"], out var parsedHours)
                ? parsedHours
                : 8;
            var requireUppercase = bool.TryParse(configuration["Security:LocalPasswordRequireUppercase"], out var parsedUppercase)
                ? parsedUppercase
                : true;
            var requireLowercase = bool.TryParse(configuration["Security:LocalPasswordRequireLowercase"], out var parsedLowercase)
                ? parsedLowercase
                : true;
            var requireDigit = bool.TryParse(configuration["Security:LocalPasswordRequireDigit"], out var parsedDigit)
                ? parsedDigit
                : true;
            var requireNonAlphanumeric = bool.TryParse(configuration["Security:LocalPasswordRequireNonAlphanumeric"], out var parsedSpecial)
                ? parsedSpecial
                : true;

            if (string.IsNullOrWhiteSpace(sessionCookieName))
            {
                sessionCookieName = "SecureJournal.Session";
            }

            return new SecuritySettings(
                LocalPasswordMinLength: Math.Max(8, configured),
                LocalPasswordRequireUppercase: requireUppercase,
                LocalPasswordRequireLowercase: requireLowercase,
                LocalPasswordRequireDigit: requireDigit,
                LocalPasswordRequireNonAlphanumeric: requireNonAlphanumeric,
                SessionCookieName: sessionCookieName,
                SessionCookieHours: Math.Max(1, sessionCookieHours));
        }
    }
}
