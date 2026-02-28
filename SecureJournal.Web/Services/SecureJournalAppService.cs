using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
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

public sealed class SecureJournalAppService : ISecureJournalAppService
{
    private readonly IChecksumService _checksumService;
    private readonly IAuditFieldEncryptor _auditEncryptor;
    private readonly IJournalEntryRecordFactory _journalRecordFactory;
    private readonly IAuditLogRecordFactory _auditRecordFactory;
    private readonly IRecordViewMapper _recordViewMapper;
    private readonly IExportContentFormatter _exportFormatter;
    private readonly IPrototypeDataStore _sqliteStore;
    private readonly ILogger<SecureJournalAppService> _logger;
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
    private readonly bool _logOidcClaimsWhenIssuerSubjectMissing;
    private readonly bool _logOidcTokensWhenIssuerSubjectMissing;

    private object _sync => _shared.SyncRoot;
    private List<Project> _projects => _shared.Projects;
    private List<Group> _groups => _shared.Groups;
    private List<ProjectGroupAssignment> _projectGroups => _shared.ProjectGroups;
    private List<AppUser> _users => _shared.Users;
    private Dictionary<Guid, HashSet<AppRole>> _userRoles => _shared.UserRoles;
    private Dictionary<Guid, HashSet<Guid>> _userGroups => _shared.UserGroups;
    private Dictionary<Guid, string> _localPasswordHashes => _shared.LocalPasswordHashes;
    private List<JournalEntryRecord> _journalEntries => _shared.JournalEntries;
    private List<AuditLogRecord> _auditLogs => _shared.AuditLogs;

    private Guid _currentUserId;

    public SecureJournalAppService(
        IChecksumService checksumService,
        IAuditFieldEncryptor auditEncryptor,
        IJournalEntryRecordFactory journalRecordFactory,
        IAuditLogRecordFactory auditRecordFactory,
        IRecordViewMapper recordViewMapper,
        IExportContentFormatter exportFormatter,
        IPrototypeDataStore sqliteStore,
        PrototypeSharedState shared,
        IConfiguration configuration,
        ILogger<SecureJournalAppService> logger,
        IHttpContextAccessor? httpContextAccessor = null,
        PrototypeSessionRegistry? sessionRegistry = null,
        AuthenticationStateProvider? authenticationStateProvider = null,
        SignInManager<SecureJournalIdentityUser>? identitySignInManager = null,
        UserManager<SecureJournalIdentityUser>? identityUserManager = null)
    {
        _checksumService = checksumService;
        _auditEncryptor = auditEncryptor;
        _journalRecordFactory = journalRecordFactory;
        _auditRecordFactory = auditRecordFactory;
        _recordViewMapper = recordViewMapper;
        _exportFormatter = exportFormatter;
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
        _logOidcClaimsWhenIssuerSubjectMissing = bool.TryParse(
            configuration["Authentication:Oidc:LogClaimsWhenIssuerSubjectMissing"],
            out var logClaimsWhenIssuerSubjectMissing)
            && logClaimsWhenIssuerSubjectMissing;
        _logOidcTokensWhenIssuerSubjectMissing = bool.TryParse(
            configuration["Authentication:Oidc:LogTokensWhenIssuerSubjectMissing"],
            out var logTokensWhenIssuerSubjectMissing)
            && logTokensWhenIssuerSubjectMissing;

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
            if (_currentUserId != Guid.Empty)
            {
                var existingCurrent = _users.FirstOrDefault(u => u.UserId == _currentUserId);
                if (existingCurrent is not null && !existingCurrent.IsDisabled)
                {
                    return true;
                }

                _currentUserId = Guid.Empty;
            }
        }

        if (_enableAspNetIdentity && TryGetCurrentPrincipal(out var principal))
        {
            lock (_sync)
            {
                return TryResolveOrProvisionUserFromPrincipal(principal, out _);
            }
        }

        lock (_sync)
        {
            TryRestoreCurrentUserFromCookie();
            return _users.Any(u => u.UserId == _currentUserId && !u.IsDisabled);
        }
    }

    public async Task<bool> HasCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_sync)
        {
            if (_currentUserId != Guid.Empty)
            {
                var existingCurrent = _users.FirstOrDefault(u => u.UserId == _currentUserId);
                if (existingCurrent is not null && !existingCurrent.IsDisabled)
                {
                    return true;
                }

                _currentUserId = Guid.Empty;
            }
        }

        if (_enableAspNetIdentity)
        {
            var principal = await GetCurrentPrincipalAsync(cancellationToken);
            if (principal is not null)
            {
                lock (_sync)
                {
                    return TryResolveOrProvisionUserFromPrincipal(principal, out _);
                }
            }
        }

        lock (_sync)
        {
            TryRestoreCurrentUserFromCookie();
            return _users.Any(u => u.UserId == _currentUserId && !u.IsDisabled);
        }
    }

    public UserContext GetCurrentUser()
    {
        lock (_sync)
        {
            if (_currentUserId != Guid.Empty)
            {
                var existingCurrent = _users.FirstOrDefault(u => u.UserId == _currentUserId);
                if (existingCurrent is not null)
                {
                    if (existingCurrent.IsDisabled)
                    {
                        _currentUserId = Guid.Empty;
                        throw new UnauthorizedAccessException("Authentication is required.");
                    }

                    return ToUserContext(existingCurrent);
                }
            }
        }

        if (_enableAspNetIdentity && TryGetCurrentPrincipal(out var principal))
        {
            lock (_sync)
            {
                if (TryResolveOrProvisionUserFromPrincipal(principal, out var resolved))
                {
                    return ToUserContext(resolved);
                }
            }

            throw new UnauthorizedAccessException("Authentication is required.");
        }

        lock (_sync)
        {
            TryRestoreCurrentUserFromCookie();
            return ToUserContext(GetCurrentUserInternal());
        }
    }

    public async Task<UserContext> GetCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_sync)
        {
            if (_currentUserId != Guid.Empty)
            {
                var existingCurrent = _users.FirstOrDefault(u => u.UserId == _currentUserId);
                if (existingCurrent is not null)
                {
                    if (existingCurrent.IsDisabled)
                    {
                        _currentUserId = Guid.Empty;
                        throw new UnauthorizedAccessException("Authentication is required.");
                    }

                    return ToUserContext(existingCurrent);
                }
            }
        }

        if (_enableAspNetIdentity)
        {
            var principal = await GetCurrentPrincipalAsync(cancellationToken);
            if (principal is not null)
            {
                lock (_sync)
                {
                    if (TryResolveOrProvisionUserFromPrincipal(principal, out var resolved))
                    {
                        return ToUserContext(resolved);
                    }
                }

                throw new UnauthorizedAccessException("Authentication is required.");
            }
        }

        lock (_sync)
        {
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
            if (nextUser.IsDisabled)
            {
                throw new UnauthorizedAccessException("The selected user account is disabled.");
            }

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
        if (_enableAspNetIdentity)
        {
            throw new InvalidOperationException("Synchronous logout is unavailable when ASP.NET Identity is enabled. Use LogoutCurrentUserAsync.");
        }

        lock (_sync)
        {
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

    public async Task LogoutCurrentUserAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_enableAspNetIdentity)
        {
            var principal = await GetCurrentPrincipalAsync(cancellationToken);
            if (principal is not null)
            {
                lock (_sync)
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
                }

                if (_identitySignInManager is not null)
                {
                    await _identitySignInManager.SignOutAsync();
                }

                return;
            }
        }

        lock (_sync)
        {
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
                throw new InvalidOperationException("Synchronous local login is unavailable when ASP.NET Identity is enabled. Use TryLocalLoginAsync.");
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

            if (localUser.IsDisabled)
            {
                _logger.LogWarning("Local login rejected for disabled user {Username}", localUser.Username);
                AppendAudit(
                    actor: localUser,
                    AuditActionType.Login,
                    AuditEntityType.Authentication,
                    entityId: localUser.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    $"Failed local login for disabled user '{localUser.Username}'.");
                return new LoginResult(false, "Account is disabled.", null);
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

    public async Task<LoginResult> TryLocalLoginAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_enableAspNetIdentity)
        {
            return TryLocalLogin(username, password);
        }

        if (_identitySignInManager is null || _identityUserManager is null)
        {
            return new LoginResult(false, "ASP.NET Identity is enabled in config, but Identity services are unavailable.", null);
        }

        var normalizedUsername = InputNormalizer.NormalizeRequired(username, nameof(username), 100).ToLowerInvariant();
        _logger.LogInformation("Local login attempt for username {Username}", normalizedUsername);

        AppUser? appUser;
        lock (_sync)
        {
            appUser = _users.FirstOrDefault(u =>
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

            if (appUser.IsDisabled)
            {
                _logger.LogWarning("Local login rejected for disabled user {Username}", normalizedUsername);
                AppendAudit(
                    actor: appUser,
                    AuditActionType.Login,
                    AuditEntityType.Authentication,
                    entityId: appUser.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    $"Failed local login for disabled user '{appUser.Username}'.");
                return new LoginResult(false, "Account is disabled.", null);
            }
        }

        var signInResult = await _identitySignInManager.PasswordSignInAsync(
            userName: normalizedUsername,
            password: password ?? string.Empty,
            isPersistent: false,
            lockoutOnFailure: false);

        if (!signInResult.Succeeded)
        {
            lock (_sync)
            {
                var currentAppUser = _users.FirstOrDefault(u => u.UserId == appUser.UserId) ?? appUser;
                _logger.LogWarning("Local login failed for user {Username} via Identity", normalizedUsername);
                AppendAudit(
                    actor: currentAppUser,
                    AuditActionType.Login,
                    AuditEntityType.Authentication,
                    entityId: currentAppUser.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    $"Failed local login attempt for user '{currentAppUser.Username}'.");
            }

            return new LoginResult(false, "Invalid username or password.", null);
        }

        var identityUser = await _identityUserManager.FindByNameAsync(normalizedUsername);
        if (identityUser is not null)
        {
            await SyncAppUserMetadataFromIdentityAsync(identityUser, cancellationToken);
        }

        AppUser finalAppUser;
        lock (_sync)
        {
            finalAppUser = _users.FirstOrDefault(u => u.UserId == appUser.UserId) ?? appUser;
            if (finalAppUser.IsDisabled)
            {
                _logger.LogWarning("Local login rejected post-sign-in for disabled user {Username}", normalizedUsername);
                AppendAudit(
                    finalAppUser,
                    AuditActionType.Login,
                    AuditEntityType.Authentication,
                    entityId: finalAppUser.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    $"Failed local login for disabled user '{finalAppUser.Username}'.");
                return new LoginResult(false, "Account is disabled.", null);
            }

            _logger.LogInformation("Local login succeeded for user {Username} via Identity", normalizedUsername);
            AppendAudit(
                finalAppUser,
                AuditActionType.Login,
                AuditEntityType.Authentication,
                entityId: finalAppUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{finalAppUser.Username}' logged in.");
        }

        return new LoginResult(true, $"Logged in as {finalAppUser.DisplayName}.", ToUserContext(finalAppUser));
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
                .Where(u => !u.IsDisabled)
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
            var visibleEntries = IsAuditorOnly(currentUser)
                ? new List<JournalEntryRecord>()
                : _journalEntries
                    .Where(e => readableProjectIds.Contains(e.ProjectId))
                    .Where(e => !e.IsSoftDeleted || CanSeeSoftDeletedEntries(currentUser))
                    .ToList();

            var visibleAuditCount = HasRole(currentUser, AppRole.Administrator) || HasRole(currentUser, AppRole.Auditor)
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
                .Where(p => HasRole(currentUser, AppRole.Administrator) || HasRole(currentUser, AppRole.Auditor) || readableProjectIds.Contains(p.ProjectId))
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
            if (!HasRole(currentUser, AppRole.Administrator))
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
            if (!HasRole(currentUser, AppRole.Administrator))
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
                    GetUserGroupNames(user.UserId),
                    GetUserRoleNames(user.UserId),
                    user.IsDisabled))
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
        if (_enableAspNetIdentity)
        {
            throw new InvalidOperationException("Synchronous user creation is unavailable when ASP.NET Identity is enabled. Use CreateUserAsync.");
        }

        return CreateUserSyncCore(request);
    }

    public async Task<UserOverview> CreateUserAsync(CreateUserRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_enableAspNetIdentity)
        {
            return CreateUserSyncCore(request);
        }

        AppUser actor;
        AppUser user;
        string? localPassword = null;
        var usesIdentity = false;

        lock (_sync)
        {
            actor = RequireAdmin();
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

            user = new AppUser(Guid.NewGuid(), username, displayName, request.Role, request.IsLocalAccount);

            if (request.IsLocalAccount)
            {
                EnsurePasswordMeetsPolicy(request.LocalPassword, "Local account password");
                localPassword = request.LocalPassword ?? string.Empty;
                usesIdentity = true;
            }
            else
            {
                usesIdentity = true;
            }
        }

        if (user.IsLocalAccount)
        {
            await CreateOrUpdateIdentityLocalUserAsync(user, localPassword ?? string.Empty, cancellationToken);
        }
        else
        {
            await EnsureIdentityExternalUserAsync(user, cancellationToken);
        }

        lock (_sync)
        {
            if (_users.Any(u => string.Equals(u.Username, user.Username, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"A user with username '{user.Username}' already exists.");
            }

            _users.Add(user);
            _userRoles[user.UserId] = new HashSet<AppRole> { user.Role };
            _userGroups[user.UserId] = new HashSet<Guid>();

            string? passwordHash = null;
            if (request.IsLocalAccount && !usesIdentity)
            {
                passwordHash = _passwordHasher.HashPassword(user, request.LocalPassword ?? string.Empty);
                _localPasswordHashes[user.UserId] = passwordHash;
            }

            _sqliteStore.UpsertUser(ToStoredUserRow(user, passwordHash));
            _sqliteStore.AddUserRole(user.UserId, user.Role);
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
                Groups: Array.Empty<string>(),
                Roles: [user.Role]);
        }
    }

    private UserOverview CreateUserSyncCore(CreateUserRequest request)
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
            _userRoles[user.UserId] = new HashSet<AppRole> { user.Role };
            _userGroups[user.UserId] = new HashSet<Guid>();

            string? passwordHash = null;
            if (request.IsLocalAccount)
            {
                EnsurePasswordMeetsPolicy(request.LocalPassword, "Local account password");
                passwordHash = _passwordHasher.HashPassword(user, request.LocalPassword ?? string.Empty);
                _localPasswordHashes[user.UserId] = passwordHash;
            }

            _sqliteStore.UpsertUser(ToStoredUserRow(user, passwordHash));
            _sqliteStore.AddUserRole(user.UserId, user.Role);
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
                Groups: Array.Empty<string>(),
                Roles: [user.Role]);
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

    public bool DeleteGroup(Guid groupId)
    {
        lock (_sync)
        {
            var actor = RequireAdmin();

            if (groupId == Guid.Empty)
            {
                throw new InvalidOperationException("Group is required.");
            }

            var group = _groups.FirstOrDefault(g => g.GroupId == groupId);
            if (group is null)
            {
                return false;
            }

            _groups.Remove(group);

            var removedProjectAssignments = _projectGroups.RemoveAll(pg => pg.GroupId == groupId);
            var removedUserMemberships = 0;
            foreach (var memberships in _userGroups.Values)
            {
                if (memberships.Remove(groupId))
                {
                    removedUserMemberships++;
                }
            }

            _sqliteStore.RemoveGroup(groupId);
            _logger.LogInformation(
                "Group deleted by {ActorUsername}: {GroupName} ({GroupId}) MembersRemoved={MembersRemoved} ProjectAssignmentsRemoved={ProjectAssignmentsRemoved}",
                actor.Username,
                group.Name,
                group.GroupId,
                removedUserMemberships,
                removedProjectAssignments);

            AppendAudit(
                actor,
                AuditActionType.Delete,
                AuditEntityType.Group,
                entityId: group.GroupId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"Group '{group.Name}' deleted. Removed memberships={removedUserMemberships}, removed project assignments={removedProjectAssignments}.");

            return true;
        }
    }

    public bool AddUserToRole(UserRoleMembershipRequest request)
    {
        _logger.LogInformation("AddUserToRole requested: UserId={UserId} Role={Role}", request.UserId, request.Role);
        string? identityUsername = null;
        AppRole? identityRoleToSync = null;

        lock (_sync)
        {
            var actor = RequireAdmin();
            ValidateAdminRequest(request);

            if (request.UserId == Guid.Empty)
            {
                throw new InvalidOperationException("User is required.");
            }

            if (!Enum.IsDefined(typeof(AppRole), request.Role))
            {
                throw new InvalidOperationException("Selected role is invalid.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == request.UserId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            if (!_userRoles.TryGetValue(targetUser.UserId, out var memberships))
            {
                memberships = new HashSet<AppRole> { targetUser.Role };
                _userRoles[targetUser.UserId] = memberships;
            }

            var added = memberships.Add(request.Role);
            if (!added)
            {
                return false;
            }

            var updatedUser = targetUser with { Role = ResolveEffectiveRole(memberships) };
            var index = _users.FindIndex(u => u.UserId == targetUser.UserId);
            if (index >= 0)
            {
                _users[index] = updatedUser;
            }

            var passwordHash = updatedUser.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updatedUser.UserId) : null;
            _sqliteStore.UpsertUser(ToStoredUserRow(updatedUser, passwordHash));
            _sqliteStore.AddUserRole(updatedUser.UserId, request.Role);

            if (_enableAspNetIdentity && updatedUser.IsLocalAccount)
            {
                identityUsername = updatedUser.Username;
                identityRoleToSync = updatedUser.Role;
            }

            _logger.LogInformation(
                "User role membership added by {ActorUsername}: {TargetUsername} + {Role}",
                actor.Username,
                updatedUser.Username,
                request.Role);

            AppendAudit(
                actor,
                AuditActionType.Assign,
                AuditEntityType.Permission,
                entityId: updatedUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"Role '{request.Role}' added for user '{updatedUser.Username}'.");
        }

        if (!string.IsNullOrWhiteSpace(identityUsername) && identityRoleToSync.HasValue)
        {
            QueueIdentityRoleSync(identityUsername, identityRoleToSync.Value);
        }

        return true;
    }

    public bool RemoveUserFromRole(UserRoleMembershipRequest request)
    {
        _logger.LogInformation("RemoveUserFromRole requested: UserId={UserId} Role={Role}", request.UserId, request.Role);
        string? identityUsername = null;
        AppRole? identityRoleToSync = null;

        lock (_sync)
        {
            var actor = RequireAdmin();
            ValidateAdminRequest(request);

            if (request.UserId == Guid.Empty)
            {
                throw new InvalidOperationException("User is required.");
            }

            if (!Enum.IsDefined(typeof(AppRole), request.Role))
            {
                throw new InvalidOperationException("Selected role is invalid.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == request.UserId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            if (!_userRoles.TryGetValue(targetUser.UserId, out var memberships))
            {
                memberships = new HashSet<AppRole> { targetUser.Role };
                _userRoles[targetUser.UserId] = memberships;
            }

            var removed = memberships.Remove(request.Role);
            if (!removed)
            {
                return false;
            }

            if (memberships.Count == 0)
            {
                memberships.Add(AppRole.ProjectUser);
                _sqliteStore.AddUserRole(targetUser.UserId, AppRole.ProjectUser);
            }

            var updatedUser = targetUser with { Role = ResolveEffectiveRole(memberships) };
            var index = _users.FindIndex(u => u.UserId == targetUser.UserId);
            if (index >= 0)
            {
                _users[index] = updatedUser;
            }

            var passwordHash = updatedUser.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updatedUser.UserId) : null;
            _sqliteStore.UpsertUser(ToStoredUserRow(updatedUser, passwordHash));
            _sqliteStore.RemoveUserRole(updatedUser.UserId, request.Role);

            if (_enableAspNetIdentity && updatedUser.IsLocalAccount)
            {
                identityUsername = updatedUser.Username;
                identityRoleToSync = updatedUser.Role;
            }

            _logger.LogInformation(
                "User role membership removed by {ActorUsername}: {TargetUsername} - {RemovedRole} -> EffectiveRole={EffectiveRole}",
                actor.Username,
                updatedUser.Username,
                request.Role,
                updatedUser.Role);

            AppendAudit(
                actor,
                AuditActionType.Delete,
                AuditEntityType.Permission,
                entityId: updatedUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"Role '{request.Role}' removed from user '{updatedUser.Username}'. Effective role is now '{updatedUser.Role}'.");
        }

        if (!string.IsNullOrWhiteSpace(identityUsername) && identityRoleToSync.HasValue)
        {
            QueueIdentityRoleSync(identityUsername, identityRoleToSync.Value);
        }

        return true;
    }

    public bool AssignUserToGroup(AssignUserToGroupRequest request)
    {
        _logger.LogInformation("AssignUserToGroup requested: UserId={UserId} GroupId={GroupId}", request.UserId, request.GroupId);
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

    public bool RemoveUserFromGroup(AssignUserToGroupRequest request)
    {
        _logger.LogInformation("RemoveUserFromGroup requested: UserId={UserId} GroupId={GroupId}", request.UserId, request.GroupId);
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
                return false;
            }

            var removed = memberships.Remove(group.GroupId);
            if (!removed)
            {
                return false;
            }

            _sqliteStore.RemoveUserFromGroup(user.UserId, group.GroupId);
            _logger.LogInformation(
                "User removed from group by {ActorUsername}: {Username} -X-> {GroupName}",
                actor.Username,
                user.Username,
                group.Name);

            AppendAudit(
                actor,
                AuditActionType.Delete,
                AuditEntityType.Permission,
                entityId: user.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{user.Username}' removed from group '{group.Name}'.");

            return true;
        }
    }

    public bool DisableUser(Guid userId)
    {
        if (_enableAspNetIdentity)
        {
            throw new InvalidOperationException("Synchronous user disable is unavailable when ASP.NET Identity is enabled. Use DisableUserAsync.");
        }

        lock (_sync)
        {
            var actor = RequireAdmin();

            if (userId == Guid.Empty)
            {
                throw new InvalidOperationException("User is required.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            if (targetUser.UserId == actor.UserId)
            {
                throw new InvalidOperationException("You cannot disable your own account.");
            }

            if (targetUser.IsDisabled)
            {
                return false;
            }

            var updatedUser = targetUser with { IsDisabled = true };
            var index = _users.FindIndex(u => u.UserId == targetUser.UserId);
            if (index >= 0)
            {
                _users[index] = updatedUser;
            }

            var passwordHash = updatedUser.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updatedUser.UserId) : null;
            _sqliteStore.UpsertUser(ToStoredUserRow(updatedUser, passwordHash));

            if (_currentUserId == updatedUser.UserId)
            {
                _currentUserId = Guid.Empty;
            }

            _logger.LogInformation(
                "User disabled by {ActorUsername}: {Username} ({UserId})",
                actor.Username,
                updatedUser.Username,
                updatedUser.UserId);

            AppendAudit(
                actor,
                AuditActionType.Configure,
                AuditEntityType.User,
                entityId: updatedUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{updatedUser.Username}' was disabled.");

            return true;
        }
    }

    public async Task<bool> DisableUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string? identityUsernameToDisable = null;
        bool changed;

        lock (_sync)
        {
            var actor = RequireAdmin();

            if (userId == Guid.Empty)
            {
                throw new InvalidOperationException("User is required.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            if (targetUser.UserId == actor.UserId)
            {
                throw new InvalidOperationException("You cannot disable your own account.");
            }

            if (targetUser.IsDisabled)
            {
                return false;
            }

            var updatedUser = targetUser with { IsDisabled = true };
            var index = _users.FindIndex(u => u.UserId == targetUser.UserId);
            if (index >= 0)
            {
                _users[index] = updatedUser;
            }

            var passwordHash = updatedUser.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updatedUser.UserId) : null;
            _sqliteStore.UpsertUser(ToStoredUserRow(updatedUser, passwordHash));

            if (_enableAspNetIdentity && updatedUser.IsLocalAccount)
            {
                identityUsernameToDisable = updatedUser.Username;
            }

            if (_currentUserId == updatedUser.UserId)
            {
                _currentUserId = Guid.Empty;
            }

            _logger.LogInformation(
                "User disabled by {ActorUsername}: {Username} ({UserId})",
                actor.Username,
                updatedUser.Username,
                updatedUser.UserId);

            AppendAudit(
                actor,
                AuditActionType.Configure,
                AuditEntityType.User,
                entityId: updatedUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{updatedUser.Username}' was disabled.");

            changed = true;
        }

        if (!string.IsNullOrWhiteSpace(identityUsernameToDisable))
        {
            await TryDisableIdentityUserByUsernameAsync(identityUsernameToDisable, cancellationToken);
        }

        return changed;
    }

    public bool EnableUser(Guid userId)
    {
        if (_enableAspNetIdentity)
        {
            throw new InvalidOperationException("Synchronous user enable is unavailable when ASP.NET Identity is enabled. Use EnableUserAsync.");
        }

        lock (_sync)
        {
            var actor = RequireAdmin();

            if (userId == Guid.Empty)
            {
                throw new InvalidOperationException("User is required.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            if (!targetUser.IsDisabled)
            {
                return false;
            }

            var updatedUser = targetUser with { IsDisabled = false };
            var index = _users.FindIndex(u => u.UserId == targetUser.UserId);
            if (index >= 0)
            {
                _users[index] = updatedUser;
            }

            var passwordHash = updatedUser.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updatedUser.UserId) : null;
            _sqliteStore.UpsertUser(ToStoredUserRow(updatedUser, passwordHash));

            _logger.LogInformation(
                "User enabled by {ActorUsername}: {Username} ({UserId})",
                actor.Username,
                updatedUser.Username,
                updatedUser.UserId);

            AppendAudit(
                actor,
                AuditActionType.Configure,
                AuditEntityType.User,
                entityId: updatedUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{updatedUser.Username}' was enabled.");

            return true;
        }
    }

    public async Task<bool> EnableUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string? identityUsernameToEnable = null;
        bool changed;

        lock (_sync)
        {
            var actor = RequireAdmin();

            if (userId == Guid.Empty)
            {
                throw new InvalidOperationException("User is required.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            if (!targetUser.IsDisabled)
            {
                return false;
            }

            var updatedUser = targetUser with { IsDisabled = false };
            var index = _users.FindIndex(u => u.UserId == targetUser.UserId);
            if (index >= 0)
            {
                _users[index] = updatedUser;
            }

            var passwordHash = updatedUser.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updatedUser.UserId) : null;
            _sqliteStore.UpsertUser(ToStoredUserRow(updatedUser, passwordHash));

            if (_enableAspNetIdentity && updatedUser.IsLocalAccount)
            {
                identityUsernameToEnable = updatedUser.Username;
            }

            _logger.LogInformation(
                "User enabled by {ActorUsername}: {Username} ({UserId})",
                actor.Username,
                updatedUser.Username,
                updatedUser.UserId);

            AppendAudit(
                actor,
                AuditActionType.Configure,
                AuditEntityType.User,
                entityId: updatedUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{updatedUser.Username}' was enabled.");

            changed = true;
        }

        if (!string.IsNullOrWhiteSpace(identityUsernameToEnable))
        {
            await TryEnableIdentityUserByUsernameAsync(identityUsernameToEnable, cancellationToken);
        }

        return changed;
    }

    public bool DeleteUser(Guid userId)
    {
        if (_enableAspNetIdentity)
        {
            throw new InvalidOperationException("Synchronous user deletion is unavailable when ASP.NET Identity is enabled. Use DeleteUserAsync.");
        }

        lock (_sync)
        {
            var actor = RequireAdmin();

            if (userId == Guid.Empty)
            {
                throw new InvalidOperationException("User is required.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            if (targetUser.UserId == actor.UserId)
            {
                throw new InvalidOperationException("You cannot delete your own account.");
            }

            _users.RemoveAll(u => u.UserId == targetUser.UserId);
            _userRoles.Remove(targetUser.UserId);
            _userGroups.Remove(targetUser.UserId);
            _localPasswordHashes.Remove(targetUser.UserId);

            if (_currentUserId == targetUser.UserId)
            {
                _currentUserId = Guid.Empty;
            }

            _sqliteStore.RemoveUser(targetUser.UserId);

            _logger.LogInformation(
                "User deleted by {ActorUsername}: {Username} ({UserId})",
                actor.Username,
                targetUser.Username,
                targetUser.UserId);

            AppendAudit(
                actor,
                AuditActionType.Delete,
                AuditEntityType.User,
                entityId: targetUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{targetUser.Username}' was deleted.");

            return true;
        }
    }

    public async Task<bool> DeleteUserAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        string? identityUsernameToDelete = null;

        lock (_sync)
        {
            var actor = RequireAdmin();

            if (userId == Guid.Empty)
            {
                throw new InvalidOperationException("User is required.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == userId)
                ?? throw new InvalidOperationException("Selected user was not found.");

            if (targetUser.UserId == actor.UserId)
            {
                throw new InvalidOperationException("You cannot delete your own account.");
            }

            _users.RemoveAll(u => u.UserId == targetUser.UserId);
            _userRoles.Remove(targetUser.UserId);
            _userGroups.Remove(targetUser.UserId);
            _localPasswordHashes.Remove(targetUser.UserId);

            if (_currentUserId == targetUser.UserId)
            {
                _currentUserId = Guid.Empty;
            }

            _sqliteStore.RemoveUser(targetUser.UserId);
            if (_enableAspNetIdentity && targetUser.IsLocalAccount)
            {
                identityUsernameToDelete = targetUser.Username;
            }

            _logger.LogInformation(
                "User deleted by {ActorUsername}: {Username} ({UserId})",
                actor.Username,
                targetUser.Username,
                targetUser.UserId);

            AppendAudit(
                actor,
                AuditActionType.Delete,
                AuditEntityType.User,
                entityId: targetUser.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                $"User '{targetUser.Username}' was deleted.");
        }

        if (!string.IsNullOrWhiteSpace(identityUsernameToDelete))
        {
            await TryDeleteIdentityUserByUsernameAsync(identityUsernameToDelete, cancellationToken);
        }

        return true;
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

    public bool RemoveGroupFromProject(AssignGroupToProjectRequest request)
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

            var membership = _projectGroups.FirstOrDefault(pg => pg.ProjectId == project.ProjectId && pg.GroupId == group.GroupId);
            if (membership is null)
            {
                return false;
            }

            _projectGroups.Remove(membership);
            _sqliteStore.RemoveGroupFromProject(project.ProjectId, group.GroupId);
            _logger.LogInformation(
                "Group-to-project removal by {ActorUsername}: {GroupName} -X-> {ProjectCode}",
                actor.Username,
                group.Name,
                project.Code);

            AppendAudit(
                actor,
                AuditActionType.Delete,
                AuditEntityType.Permission,
                entityId: group.GroupId.ToString(),
                projectId: project.ProjectId,
                AuditOutcome.Success,
                $"Group '{group.Name}' removed from project '{project.Code}'.");

            return true;
        }
    }

    public PasswordChangeResult ChangeCurrentUserPassword(ChangePasswordRequest request)
    {
        if (_enableAspNetIdentity)
        {
            throw new InvalidOperationException("Synchronous password changes are unavailable when ASP.NET Identity is enabled. Use ChangeCurrentUserPasswordAsync.");
        }

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

            return ChangeCurrentUserPasswordLocalCore(actor, request);
        }
    }

    public async Task<PasswordChangeResult> ChangeCurrentUserPasswordAsync(ChangePasswordRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        AppUser actor;
        lock (_sync)
        {
            actor = GetCurrentUserInternal();
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
                // Continue outside the global lock to avoid blocking while awaiting Identity/EF.
            }
            else
            {
                return ChangeCurrentUserPasswordLocalCore(actor, request);
            }
        }

        return await ChangeCurrentUserPasswordWithIdentityAsync(actor, request, cancellationToken);
    }

    public PasswordChangeResult ResetLocalUserPassword(AdminResetPasswordRequest request)
    {
        if (_enableAspNetIdentity)
        {
            throw new InvalidOperationException("Synchronous password resets are unavailable when ASP.NET Identity is enabled. Use ResetLocalUserPasswordAsync.");
        }

        lock (_sync)
        {
            var actor = RequireAdmin();
            ValidateAdminRequest(request);

            if (request.UserId == Guid.Empty)
            {
                return new PasswordChangeResult(false, "A user must be selected.");
            }

            var targetUser = _users.FirstOrDefault(u => u.UserId == request.UserId)!;
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

            var newHash = _passwordHasher.HashPassword(targetUser, request.NewPassword);
            _localPasswordHashes[targetUser.UserId] = newHash;
            _sqliteStore.UpsertUser(ToStoredUserRow(targetUser, newHash));

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

    public async Task<PasswordChangeResult> ResetLocalUserPasswordAsync(AdminResetPasswordRequest request, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        AppUser actor;
        AppUser targetUser;
        lock (_sync)
        {
            actor = RequireAdmin();
            ValidateAdminRequest(request);

            if (request.UserId == Guid.Empty)
            {
                return new PasswordChangeResult(false, "A user must be selected.");
            }

            targetUser = _users.FirstOrDefault(u => u.UserId == request.UserId)!;
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
                // Continue outside lock to avoid blocking on Identity APIs.
            }
            else
            {
                var newHash = _passwordHasher.HashPassword(targetUser, request.NewPassword);
                _localPasswordHashes[targetUser.UserId] = newHash;
                _sqliteStore.UpsertUser(ToStoredUserRow(targetUser, newHash));

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

        return await ResetLocalUserPasswordWithIdentityAsync(actor, targetUser, request.NewPassword, cancellationToken);
    }

    public IReadOnlyList<JournalEntryView> GetJournalEntries(Guid? projectId = null, bool includeSoftDeleted = false)
    {
        lock (_sync)
        {
            var currentUser = GetCurrentUserInternal();
            if (IsAuditorOnly(currentUser))
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
                .Select(record => _recordViewMapper.MapJournalEntry(record, _projects))
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

            if (IsAuditorOnly(actor))
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

            var record = _journalRecordFactory.Create(
                project.ProjectId,
                actor.UserId,
                actor.Username,
                now,
                action,
                subject,
                description,
                notes,
                result);

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

            return _recordViewMapper.MapJournalEntry(record, _projects);
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

            if (IsAuditorOnly(actor))
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
            if (!HasRole(actor, AppRole.Administrator) && !HasRole(actor, AppRole.Auditor))
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
                .Select(record => _recordViewMapper.MapAuditLog(record, _projects, _journalEntries))
                .ToList();
        }
    }

    public AuditChecksumValidationResult ValidateAuditLogChecksum(Guid auditId)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            if (!HasRole(actor, AppRole.Administrator) && !HasRole(actor, AppRole.Auditor))
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
            if (!HasRole(actor, AppRole.Administrator))
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
                ? _exportFormatter.BuildJournalCsv(request.Filter, rows)
                : _exportFormatter.BuildJournalJson(request.Filter, rows);

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
            if (!HasRole(actor, AppRole.Administrator) && !HasRole(actor, AppRole.Auditor))
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
                ? _exportFormatter.BuildAuditCsv(request.Filter, rows)
                : _exportFormatter.BuildAuditJson(request.Filter, rows);

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
                stored.IsLocalAccount,
                stored.ExternalIssuer,
                stored.ExternalSubject,
                stored.IsDisabled);

            _users.Add(user);
            _userRoles[user.UserId] = new HashSet<AppRole> { user.Role };
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

        foreach (var storedUserRole in _sqliteStore.LoadUserRoles())
        {
            if (!knownUserIds.Contains(storedUserRole.UserId))
            {
                continue;
            }

            if (!_userRoles.TryGetValue(storedUserRole.UserId, out var roles))
            {
                roles = new HashSet<AppRole>();
                _userRoles[storedUserRole.UserId] = roles;
            }

            roles.Add(storedUserRole.Role);
        }

        foreach (var user in _users.ToList())
        {
            if (!_userRoles.TryGetValue(user.UserId, out var roles) || roles.Count == 0)
            {
                roles = new HashSet<AppRole> { user.Role };
                _userRoles[user.UserId] = roles;
                _sqliteStore.AddUserRole(user.UserId, user.Role);
            }

            var effectiveRole = ResolveEffectiveRole(roles);
            if (user.Role != effectiveRole)
            {
                var updated = user with { Role = effectiveRole };
                var index = _users.FindIndex(u => u.UserId == user.UserId);
                if (index >= 0)
                {
                    _users[index] = updated;
                }

                _sqliteStore.UpsertUser(ToStoredUserRow(updated, updated.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updated.UserId) : null));
            }
        }

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

        var record = _journalRecordFactory.Create(
            project.ProjectId,
            actor.UserId,
            actor.Username,
            createdAtUtc,
            normalizedCategory,
            normalizedSubject,
            normalizedDescription,
            normalizedNotes,
            normalizedResult);

        _journalEntries.Add(record);
        _sqliteStore.UpsertJournalEntry(record);
        AppendAudit(actor, AuditActionType.Create, AuditEntityType.JournalEntry, record.RecordId.ToString(), project.ProjectId, AuditOutcome.Success, $"Seed entry created in project '{project.Code}'.");
        return record;
    }

    private void ValidateRequest(CreateJournalEntryRequest request)
    {
        var validationContext = new ValidationContext(request);
        Validator.ValidateObject(request, validationContext, validateAllProperties: true);

        if (request.ProjectId == Guid.Empty)
        {
            throw new ValidationException("Project is required.");
        }
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
        var auditRecord = _auditRecordFactory.Create(
            actor,
            action,
            entityType,
            entityId,
            projectId,
            outcome,
            details);

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
            .Select(record => _recordViewMapper.MapJournalEntry(record, _projects))
            .ToList();

        return rows;
    }

    private AppUser RequireAdmin()
    {
        AppUser? actor = null;

        if (_currentUserId != Guid.Empty)
        {
            actor = _users.FirstOrDefault(u => u.UserId == _currentUserId);
            if (actor?.IsDisabled == true)
            {
                _currentUserId = Guid.Empty;
                actor = null;
            }
        }

        if (actor is null)
        {
            actor = GetCurrentUserInternal();
        }

        if (actor is null)
        {
            throw new UnauthorizedAccessException("Authentication is required.");
        }

        if (!HasRole(actor, AppRole.Administrator))
        {
            throw new UnauthorizedAccessException("Administrator role is required for this operation.");
        }

        _currentUserId = actor.UserId;
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

    private static StoredUserRow ToStoredUserRow(AppUser user, string? passwordHash)
        => new(
            user.UserId,
            user.Username,
            user.DisplayName,
            user.Role,
            user.IsLocalAccount,
            passwordHash,
            user.ExternalIssuer,
            user.ExternalSubject,
            user.IsDisabled);

    private AppUser GetCurrentUserInternal()
    {
        if (_currentUserId != Guid.Empty)
        {
            var existingCurrent = _users.FirstOrDefault(u => u.UserId == _currentUserId);
            if (existingCurrent is not null)
            {
                if (existingCurrent.IsDisabled)
                {
                    _currentUserId = Guid.Empty;
                    throw new UnauthorizedAccessException("Authentication is required.");
                }

                return existingCurrent;
            }
        }

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

        if (sessionUser.IsDisabled)
        {
            _sessionRegistry.Remove(sessionToken);
            return;
        }

        _currentUserId = sessionUser.UserId;
        _logger.LogInformation("Current user restored from session cookie for username {Username}", sessionUser.Username);
    }

    private PasswordChangeResult ChangeCurrentUserPasswordLocalCore(AppUser actor, ChangePasswordRequest request)
    {
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
        _sqliteStore.UpsertUser(ToStoredUserRow(actor, newHash));
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

    private async Task<PasswordChangeResult> ChangeCurrentUserPasswordWithIdentityAsync(AppUser actor, ChangePasswordRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

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

        var identityUser = await _identityUserManager.FindByNameAsync(actor.Username);
        if (identityUser is null)
        {
            lock (_sync)
            {
                AppendAudit(actor, AuditActionType.Update, AuditEntityType.Authentication, actor.UserId.ToString(), null, AuditOutcome.Failure,
                    "Password change failed because the Identity user record was not found.");
            }
            return new PasswordChangeResult(false, "Current account does not have a local password configured.");
        }

        var result = await _identityUserManager.ChangePasswordAsync(identityUser, currentPassword, newPassword);
        if (!result.Succeeded)
        {
            var error = string.Join("; ", result.Errors.Select(e => e.Description));
            lock (_sync)
            {
                _logger.LogWarning("Password change failed for user {Username} via Identity: {Error}", actor.Username, error);
                AppendAudit(actor, AuditActionType.Update, AuditEntityType.Authentication, actor.UserId.ToString(), null, AuditOutcome.Failure,
                    "Password change failed because the current password did not match.");
            }

            return new PasswordChangeResult(false, error.Contains("Incorrect", StringComparison.OrdinalIgnoreCase)
                ? "Current password is incorrect."
                : error);
        }

        lock (_sync)
        {
            _sqliteStore.UpsertUser(ToStoredUserRow(actor, passwordHash: null));
            _logger.LogInformation("Password change succeeded for user {Username} via Identity", actor.Username);
            AppendAudit(actor, AuditActionType.Update, AuditEntityType.Authentication, actor.UserId.ToString(), null, AuditOutcome.Success,
                "Local password changed for current user.");
        }

        return new PasswordChangeResult(true, "Password changed successfully.");
    }

    private async Task<PasswordChangeResult> ResetLocalUserPasswordWithIdentityAsync(AppUser actor, AppUser targetUser, string? newPassword, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_identityUserManager is null)
        {
            return new PasswordChangeResult(false, "Identity services are unavailable.");
        }

        EnsurePasswordMeetsPolicy(newPassword, "Reset password");
        var candidatePassword = newPassword ?? string.Empty;

        var identityUser = await _identityUserManager.FindByNameAsync(targetUser.Username);
        if (identityUser is null)
        {
            return new PasswordChangeResult(false, "Selected user does not have an Identity local account.");
        }

        var resetToken = await _identityUserManager.GeneratePasswordResetTokenAsync(identityUser);
        var result = await _identityUserManager.ResetPasswordAsync(identityUser, resetToken, candidatePassword);
        if (!result.Succeeded)
        {
            var error = string.Join("; ", result.Errors.Select(e => e.Description));
            return new PasswordChangeResult(false, error);
        }

        lock (_sync)
        {
            _sqliteStore.UpsertUser(ToStoredUserRow(targetUser, passwordHash: null));
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
        }

        return new PasswordChangeResult(true, $"Password reset for '{targetUser.Username}'.");
    }

    private async Task CreateOrUpdateIdentityLocalUserAsync(AppUser appUser, string password, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_identityUserManager is null)
        {
            throw new InvalidOperationException("ASP.NET Identity is enabled but UserManager is unavailable.");
        }

        var existing = await _identityUserManager.FindByNameAsync(appUser.Username);
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

        var create = await _identityUserManager.CreateAsync(identityUser, password);
        if (!create.Succeeded)
        {
            var error = string.Join("; ", create.Errors.Select(e => e.Description));
            throw new InvalidOperationException($"Failed creating Identity user '{appUser.Username}': {error}");
        }

        await SyncIdentityUserRolesAsync(identityUser, appUser.Role, cancellationToken);
    }

    private async Task EnsureIdentityExternalUserAsync(AppUser appUser, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_identityUserManager is null)
        {
            return;
        }

        var existing = await _identityUserManager.FindByNameAsync(appUser.Username);
        if (existing is null)
        {
            return;
        }

        existing.DisplayName = appUser.DisplayName;
        await _identityUserManager.UpdateAsync(existing);
        await SyncIdentityUserRolesAsync(existing, appUser.Role, cancellationToken);
    }

    private async Task SyncIdentityUserRolesAsync(SecureJournalIdentityUser identityUser, AppRole appRole, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_identityUserManager is null)
        {
            return;
        }

        var desiredRole = appRole.ToString();
        var existingRoles = await _identityUserManager.GetRolesAsync(identityUser);
        foreach (var role in existingRoles.Where(r => r is "Administrator" or "ProjectUser" or "Auditor"))
        {
            if (!string.Equals(role, desiredRole, StringComparison.OrdinalIgnoreCase))
            {
                await _identityUserManager.RemoveFromRoleAsync(identityUser, role);
            }
        }

        if (!existingRoles.Any(r => string.Equals(r, desiredRole, StringComparison.OrdinalIgnoreCase)))
        {
            var addRole = await _identityUserManager.AddToRoleAsync(identityUser, desiredRole);
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

        principal = new ClaimsPrincipal();
        return false;
    }

    private async Task<ClaimsPrincipal?> GetCurrentPrincipalAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var httpContextUser = _httpContextAccessor?.HttpContext?.User;
        if (httpContextUser?.Identity?.IsAuthenticated == true)
        {
            return httpContextUser;
        }

        if (_authenticationStateProvider is not null)
        {
            try
            {
                var authState = await _authenticationStateProvider.GetAuthenticationStateAsync();
                if (authState.User.Identity?.IsAuthenticated == true)
                {
                    return authState.User;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to resolve Blazor AuthenticationState principal.");
            }
        }

        return null;
    }

    private bool TryResolveOrProvisionUserFromPrincipal(ClaimsPrincipal principal, out AppUser user)
    {
        user = default!;
        var username = OidcPrincipalHelpers.GetNormalizedPrincipalUsername(principal);
        if (string.IsNullOrWhiteSpace(username))
        {
            return false;
        }

        var isExternalOidcPrincipal = _enableOidc && OidcPrincipalHelpers.LooksLikeOidcPrincipal(principal);
        var existingByUsername = _users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase));
        AppUser? existing = existingByUsername;
        string? externalIssuer = null;
        string? externalSubject = null;

        if (!isExternalOidcPrincipal && existingByUsername is null)
        {
            _logger.LogWarning(
                "Rejected local principal because username {Username} is not a known application user",
                username);
            return false;
        }

        if (isExternalOidcPrincipal)
        {
            if (!OidcPrincipalHelpers.TryGetOidcIdentityKey(principal, out externalIssuer, out externalSubject))
            {
                if (_logOidcClaimsWhenIssuerSubjectMissing || _logOidcTokensWhenIssuerSubjectMissing)
                {
                    var claimsText = _logOidcClaimsWhenIssuerSubjectMissing
                        ? OidcPrincipalHelpers.FormatPrincipalClaimsForDiagnostics(principal)
                        : "(disabled)";
                    var tokensText = _logOidcTokensWhenIssuerSubjectMissing
                        ? GetOidcTokensForDiagnostics()
                        : "(disabled)";
                    _logger.LogWarning(
                        "Rejected OIDC principal for username {Username} because issuer/subject claims were missing. Claims={Claims} Tokens={Tokens}",
                        username,
                        claimsText,
                        tokensText);
                }
                else
                {
                    _logger.LogWarning(
                        "Rejected OIDC principal for username {Username} because issuer/subject claims were missing",
                        username);
                }
                AppendAudit(
                    actor: null,
                    AuditActionType.Login,
                    AuditEntityType.Authentication,
                    entityId: existingByUsername?.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    $"Rejected OIDC login for username '{username}' because issuer/subject claims were missing.");
                return false;
            }

            var existingByExternalIdentity = _users.FirstOrDefault(u =>
                !u.IsLocalAccount &&
                string.Equals(u.ExternalIssuer, externalIssuer, StringComparison.Ordinal) &&
                string.Equals(u.ExternalSubject, externalSubject, StringComparison.Ordinal));

            if (existingByExternalIdentity is not null)
            {
                if (existingByUsername is not null && existingByUsername.UserId != existingByExternalIdentity.UserId)
                {
                    _logger.LogWarning(
                        "Rejected OIDC principal for subject {Subject} because username {Username} collides with another account",
                        externalSubject,
                        username);
                    AppendAudit(
                        actor: null,
                        AuditActionType.Login,
                        AuditEntityType.Authentication,
                        entityId: existingByUsername.UserId.ToString(),
                        projectId: null,
                        AuditOutcome.Failure,
                        $"Rejected OIDC login for username '{username}' because it collides with another account.");
                    return false;
                }

                existing = existingByExternalIdentity;
            }
            else if (existingByUsername is not null)
            {
                if (existingByUsername.IsLocalAccount)
                {
                    _logger.LogWarning(
                        "Rejected OIDC principal for username {Username} due to collision with local account",
                        username);
                    AppendAudit(
                        actor: null,
                        AuditActionType.Login,
                        AuditEntityType.Authentication,
                        entityId: existingByUsername.UserId.ToString(),
                        projectId: null,
                        AuditOutcome.Failure,
                        $"Rejected OIDC login for username '{username}' because it collides with a local account.");
                    return false;
                }

                if (!string.IsNullOrWhiteSpace(existingByUsername.ExternalIssuer) ||
                    !string.IsNullOrWhiteSpace(existingByUsername.ExternalSubject))
                {
                    _logger.LogWarning(
                        "Rejected OIDC principal for username {Username} because an external account with a different identity is already linked",
                        username);
                    AppendAudit(
                        actor: null,
                        AuditActionType.Login,
                        AuditEntityType.Authentication,
                        entityId: existingByUsername.UserId.ToString(),
                        projectId: null,
                        AuditOutcome.Failure,
                        $"Rejected OIDC login for username '{username}' because an external account with a different identity is already linked.");
                    return false;
                }

                // Legacy upgrade path: bind an existing non-local username-only account to the stable OIDC identity.
                existing = existingByUsername with
                {
                    ExternalIssuer = externalIssuer,
                    ExternalSubject = externalSubject
                };
                var legacyIndex = _users.FindIndex(u => u.UserId == existingByUsername.UserId);
                if (legacyIndex >= 0)
                {
                    _users[legacyIndex] = existing;
                }

                _sqliteStore.UpsertUser(ToStoredUserRow(existing, passwordHash: null));
            }
        }

        if (existing is not null && existing.IsDisabled)
        {
            _logger.LogWarning(
                "Rejected principal for disabled user {Username}",
                username);
            AppendAudit(
                actor: null,
                AuditActionType.Login,
                AuditEntityType.Authentication,
                entityId: existing.UserId.ToString(),
                projectId: null,
                AuditOutcome.Failure,
                $"Rejected login for disabled user '{username}'.");
            return false;
        }

        AppRole mappedRole;
        if (isExternalOidcPrincipal)
        {
            if (!OidcPrincipalHelpers.TryGetExplicitRoleFromPrincipal(principal, out mappedRole))
            {
                _logger.LogWarning(
                    "Rejected OIDC principal for username {Username} because no mapped application role was present",
                    username);
                AppendAudit(
                    actor: null,
                    AuditActionType.Login,
                    AuditEntityType.Authentication,
                    entityId: existing?.UserId.ToString(),
                    projectId: null,
                    AuditOutcome.Failure,
                    $"Rejected OIDC login for username '{username}' because no mapped application role was present.");
                return false;
            }
        }
        else
        {
            mappedRole = OidcPrincipalHelpers.GetRoleFromPrincipal(principal, existing?.Role);
        }

        var mappedDisplayName = OidcPrincipalHelpers.GetDisplayNameFromPrincipal(principal, username);
        var isLocalPrincipal = existing?.IsLocalAccount ?? !isExternalOidcPrincipal;

        if (existing is null)
        {
            var created = new AppUser(
                Guid.NewGuid(),
                username,
                mappedDisplayName,
                mappedRole,
                isLocalPrincipal,
                isLocalPrincipal ? null : externalIssuer,
                isLocalPrincipal ? null : externalSubject);
            _users.Add(created);
            _userRoles[created.UserId] = new HashSet<AppRole> { created.Role };
            _userGroups[created.UserId] = new HashSet<Guid>();
            _sqliteStore.UpsertUser(ToStoredUserRow(created, passwordHash: null));
            _sqliteStore.AddUserRole(created.UserId, created.Role);
            _logger.LogInformation("App user provisioned from authenticated principal: {Username} ({Role})", created.Username, created.Role);
            AppendAudit(
                created,
                AuditActionType.Configure,
                AuditEntityType.User,
                entityId: created.UserId.ToString(),
                projectId: null,
                AuditOutcome.Success,
                "App user provisioned from authenticated Identity/OIDC principal.");
            _currentUserId = created.UserId;
            user = created;
            return true;
        }

        var needsUpdate =
            !string.Equals(existing.DisplayName, mappedDisplayName, StringComparison.Ordinal) ||
            existing.Role != mappedRole ||
            (isExternalOidcPrincipal && (
                !string.Equals(existing.ExternalIssuer, externalIssuer, StringComparison.Ordinal) ||
                !string.Equals(existing.ExternalSubject, externalSubject, StringComparison.Ordinal))) ||
            (existing.IsLocalAccount && !isLocalPrincipal && _enableOidc); // preserve local flag unless clearly external-only

        if (needsUpdate)
        {
            var updated = existing with
            {
                DisplayName = mappedDisplayName,
                Role = mappedRole,
                ExternalIssuer = isExternalOidcPrincipal ? externalIssuer : existing.ExternalIssuer,
                ExternalSubject = isExternalOidcPrincipal ? externalSubject : existing.ExternalSubject
            };
            var index = _users.FindIndex(u => u.UserId == existing.UserId);
            if (index >= 0)
            {
                _users[index] = updated;
            }

            ReplaceUserRoles(updated.UserId, [mappedRole]);
            _sqliteStore.UpsertUser(ToStoredUserRow(updated, existing.IsLocalAccount ? _localPasswordHashes.GetValueOrDefault(updated.UserId) : null));
            _currentUserId = updated.UserId;
            user = updated;
            return true;
        }

        _currentUserId = existing.UserId;
        user = existing;
        return true;
    }

    private async Task SyncAppUserMetadataFromIdentityAsync(SecureJournalIdentityUser identityUser, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_identityUserManager is null)
        {
            return;
        }

        var roles = await _identityUserManager.GetRolesAsync(identityUser);
        var resolvedRole = roles.Any(r => string.Equals(r, nameof(AppRole.Administrator), StringComparison.OrdinalIgnoreCase))
            ? AppRole.Administrator
            : roles.Any(r => string.Equals(r, nameof(AppRole.Auditor), StringComparison.OrdinalIgnoreCase))
                ? AppRole.Auditor
                : AppRole.ProjectUser;

        lock (_sync)
        {
            var appUser = _users.FirstOrDefault(u => string.Equals(u.Username, identityUser.UserName, StringComparison.OrdinalIgnoreCase));
            if (appUser is null)
            {
                return;
            }

            var displayName = string.IsNullOrWhiteSpace(identityUser.DisplayName) ? appUser.DisplayName : identityUser.DisplayName;
            if (appUser.Role == resolvedRole && string.Equals(appUser.DisplayName, displayName, StringComparison.Ordinal))
            {
                return;
            }

            var updated = appUser with { Role = resolvedRole, DisplayName = displayName };
            var index = _users.FindIndex(u => u.UserId == appUser.UserId);
            if (index >= 0)
            {
                _users[index] = updated;
            }

            ReplaceUserRoles(updated.UserId, [resolvedRole]);
            _sqliteStore.UpsertUser(ToStoredUserRow(updated, passwordHash: null));
        }
    }

    private string GetOidcTokensForDiagnostics()
    {
        var httpContext = _httpContextAccessor?.HttpContext;
        if (httpContext is null)
        {
            return "(http-context-unavailable)";
        }

        try
        {
            var authFeature = httpContext.Features.Get<IAuthenticateResultFeature>();
            var authProperties = authFeature?.AuthenticateResult?.Properties;
            if (authProperties is not null)
            {
                var idToken = authProperties.GetTokenValue("id_token") ?? "(none)";
                var accessToken = authProperties.GetTokenValue("access_token") ?? "(none)";
                var refreshToken = authProperties.GetTokenValue("refresh_token") ?? "(none)";
                return $"scheme=(feature); id_token={idToken}; access_token={accessToken}; refresh_token={refreshToken}";
            }
            return "(no-token-properties-found-in-feature)";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to read OIDC tokens for diagnostics.");
            return "(token-read-failed)";
        }
    }

    private bool IsLocalPrincipal(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true)
        {
            return false;
        }

        if (_enableOidc && OidcPrincipalHelpers.LooksLikeOidcPrincipal(principal))
        {
            return false;
        }

        return true;
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
        if (HasRole(user, AppRole.Administrator))
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

    private bool CanSeeSoftDeletedEntries(AppUser user)
        => HasRole(user, AppRole.Administrator);

    private bool HasRole(AppUser user, AppRole role)
        => _userRoles.TryGetValue(user.UserId, out var roles)
            ? roles.Contains(role)
            : user.Role == role;

    private bool IsAuditorOnly(AppUser user)
        => HasRole(user, AppRole.Auditor)
           && !HasRole(user, AppRole.Administrator)
           && !HasRole(user, AppRole.ProjectUser);

    private IReadOnlyList<AppRole> GetUserRoleNames(Guid userId)
    {
        if (!_userRoles.TryGetValue(userId, out var roles) || roles.Count == 0)
        {
            return [AppRole.ProjectUser];
        }

        return roles
            .OrderBy(r => r.ToString(), StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static AppRole ResolveEffectiveRole(IReadOnlyCollection<AppRole> roles)
    {
        if (roles.Contains(AppRole.Administrator))
        {
            return AppRole.Administrator;
        }

        if (roles.Contains(AppRole.ProjectUser))
        {
            return AppRole.ProjectUser;
        }

        if (roles.Contains(AppRole.Auditor))
        {
            return AppRole.Auditor;
        }

        return AppRole.ProjectUser;
    }

    private void QueueIdentityRoleSync(string username, AppRole appRole)
    {
        _ = TrySyncIdentityRoleForUsernameAsync(username, appRole);
    }

    private async Task TrySyncIdentityRoleForUsernameAsync(string username, AppRole appRole)
    {
        if (_identityUserManager is null)
        {
            return;
        }

        try
        {
            var identityUser = await _identityUserManager.FindByNameAsync(username);
            if (identityUser is null)
            {
                return;
            }

            await SyncIdentityUserRolesAsync(identityUser, appRole, CancellationToken.None);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to synchronize Identity role for username {Username}", username);
        }
    }

    private async Task TryDeleteIdentityUserByUsernameAsync(string username, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_identityUserManager is null)
        {
            return;
        }

        try
        {
            var identityUser = await _identityUserManager.FindByNameAsync(username);
            if (identityUser is null)
            {
                return;
            }

            var result = await _identityUserManager.DeleteAsync(identityUser);
            if (!result.Succeeded)
            {
                var errors = string.Join("; ", result.Errors.Select(e => $"{e.Code}:{e.Description}"));
                _logger.LogWarning("Failed to delete Identity account for username {Username}: {Errors}", username, errors);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to delete Identity account for username {Username}", username);
        }
    }

    private async Task TryDisableIdentityUserByUsernameAsync(string username, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_identityUserManager is null)
        {
            return;
        }

        try
        {
            var identityUser = await _identityUserManager.FindByNameAsync(username);
            if (identityUser is null)
            {
                return;
            }

            if (!identityUser.LockoutEnabled)
            {
                identityUser.LockoutEnabled = true;
                var updateResult = await _identityUserManager.UpdateAsync(identityUser);
                if (!updateResult.Succeeded)
                {
                    var updateErrors = string.Join("; ", updateResult.Errors.Select(e => $"{e.Code}:{e.Description}"));
                    _logger.LogWarning("Failed to enable lockout for disabled Identity user {Username}: {Errors}", username, updateErrors);
                    return;
                }
            }

            var lockoutResult = await _identityUserManager.SetLockoutEndDateAsync(identityUser, DateTimeOffset.MaxValue);
            if (!lockoutResult.Succeeded)
            {
                var lockoutErrors = string.Join("; ", lockoutResult.Errors.Select(e => $"{e.Code}:{e.Description}"));
                _logger.LogWarning("Failed to lockout disabled Identity user {Username}: {Errors}", username, lockoutErrors);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to lockout disabled Identity user {Username}", username);
        }
    }

    private async Task TryEnableIdentityUserByUsernameAsync(string username, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_identityUserManager is null)
        {
            return;
        }

        try
        {
            var identityUser = await _identityUserManager.FindByNameAsync(username);
            if (identityUser is null)
            {
                return;
            }

            if (!identityUser.LockoutEnabled)
            {
                identityUser.LockoutEnabled = true;
                var updateResult = await _identityUserManager.UpdateAsync(identityUser);
                if (!updateResult.Succeeded)
                {
                    var updateErrors = string.Join("; ", updateResult.Errors.Select(e => $"{e.Code}:{e.Description}"));
                    _logger.LogWarning("Failed to update lockout settings for enabled Identity user {Username}: {Errors}", username, updateErrors);
                    return;
                }
            }

            var unlockResult = await _identityUserManager.SetLockoutEndDateAsync(identityUser, null);
            if (!unlockResult.Succeeded)
            {
                var unlockErrors = string.Join("; ", unlockResult.Errors.Select(e => $"{e.Code}:{e.Description}"));
                _logger.LogWarning("Failed to clear lockout for enabled Identity user {Username}: {Errors}", username, unlockErrors);
                return;
            }

            await _identityUserManager.ResetAccessFailedCountAsync(identityUser);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to unlock enabled Identity user {Username}", username);
        }
    }

    private void ReplaceUserRoles(Guid userId, IReadOnlyCollection<AppRole> desiredRoles)
    {
        if (!_userRoles.TryGetValue(userId, out var currentRoles))
        {
            currentRoles = new HashSet<AppRole>();
            _userRoles[userId] = currentRoles;
        }

        foreach (var existingRole in currentRoles.ToList())
        {
            if (!desiredRoles.Contains(existingRole))
            {
                currentRoles.Remove(existingRole);
                _sqliteStore.RemoveUserRole(userId, existingRole);
            }
        }

        foreach (var desiredRole in desiredRoles)
        {
            if (currentRoles.Add(desiredRole))
            {
                _sqliteStore.AddUserRole(userId, desiredRole);
            }
        }

        if (currentRoles.Count == 0)
        {
            currentRoles.Add(AppRole.ProjectUser);
            _sqliteStore.AddUserRole(userId, AppRole.ProjectUser);
        }
    }

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
            _userRoles[bootstrapUser.UserId] = new HashSet<AppRole> { AppRole.Administrator };
            _userGroups[bootstrapUser.UserId] = new HashSet<Guid>();

            var passwordHash = _passwordHasher.HashPassword(bootstrapUser, _bootstrapAdmin.Password);
            _localPasswordHashes[bootstrapUser.UserId] = passwordHash;

            _sqliteStore.UpsertUser(ToStoredUserRow(bootstrapUser, passwordHash));
            _sqliteStore.AddUserRole(bootstrapUser.UserId, AppRole.Administrator);

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

        if (!_userRoles.TryGetValue(bootstrapUser.UserId, out var roles))
        {
            roles = new HashSet<AppRole>();
            _userRoles[bootstrapUser.UserId] = roles;
        }
        roles.Add(AppRole.Administrator);
        _sqliteStore.AddUserRole(bootstrapUser.UserId, AppRole.Administrator);

        var updatedBootstrapUser = bootstrapUser;
        var metadataUpdated = false;
        if (bootstrapUser.Role != AppRole.Administrator ||
            !bootstrapUser.IsLocalAccount ||
            bootstrapUser.IsDisabled ||
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
            _sqliteStore.UpsertUser(ToStoredUserRow(updatedBootstrapUser, passwordHashToPersist));

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
            var password = configuration["BootstrapAdmin:Password"]?.Trim();
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
                if (IsProductionEnvironment(configuration))
                {
                    throw new InvalidOperationException(
                        "BootstrapAdmin:Password is required in Production and cannot be empty.");
                }

                password = "ChangeMe123!";
            }

            if (IsProductionEnvironment(configuration) &&
                (string.Equals(password, "ChangeMe123!", StringComparison.Ordinal) ||
                 password.Contains("<bootstrap-admin", StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException(
                    "BootstrapAdmin:Password uses a default/placeholder value. Set a strong production password.");
            }

            return new BootstrapAdminSettings(username, displayName, password, syncPasswordOnStartup);
        }

        private static bool IsProductionEnvironment(IConfiguration configuration)
        {
            var configuredEnvironment = configuration["ASPNETCORE_ENVIRONMENT"]
                ?? configuration["DOTNET_ENVIRONMENT"]
                ?? Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")
                ?? Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");

            return string.Equals(configuredEnvironment, "Production", StringComparison.OrdinalIgnoreCase);
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


