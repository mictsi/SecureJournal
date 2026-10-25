using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;
using SecureJournal.Web.Infrastructure.Identity;
using SecureJournal.Web.Infrastructure.Persistence;
using SecureJournal.Web.Services;
using Xunit;

namespace SecureJournal.Tests;

public sealed class ProjectFavoriteTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Favorites_ArePrivateDurableAndIdempotent(bool ef)
    {
        using var ctx = new FavoriteContext(ef);
        var project = ctx.Admin.CreateProject(new CreateProjectRequest { Name = "Favorite project" });
        var second = ctx.AddProjectUser(project.ProjectId, "second");
        var adminId = ctx.Admin.GetCurrentUser().UserId;
        Assert.True(ctx.Admin.SetProjectFavorite(project.ProjectId, true));
        Assert.True(ctx.Admin.SetProjectFavorite(project.ProjectId, true));
        Assert.Equal(project.ProjectId, Assert.Single(ctx.Admin.GetFavoriteProjectIds()));
        Assert.Equal(project.ProjectId, Assert.Single(ctx.Store.LoadFavoriteProjectIds(adminId)));
        Assert.Empty(second.App.GetFavoriteProjectIds());
        Assert.True(second.App.SetProjectFavorite(project.ProjectId, true));
        Assert.False(second.App.SetProjectFavorite(project.ProjectId, false));
        Assert.False(second.App.SetProjectFavorite(project.ProjectId, false));
        Assert.Empty(second.App.GetFavoriteProjectIds());
        Assert.Equal(project.ProjectId, Assert.Single(ctx.Admin.GetFavoriteProjectIds()));

        var restarted = ctx.CreateApp();
        Assert.True(restarted.TryLocalLogin("admin", "AdminPass123!").Success);
        Assert.Equal(project.ProjectId, Assert.Single(restarted.GetFavoriteProjectIds()));
        Assert.False(restarted.SetProjectFavorite(project.ProjectId, false));
        Assert.Empty(ctx.Admin.GetFavoriteProjectIds()); // A second open circuit reads the durable preference.
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Favorites_NeverGrantAccessAndReappearWhenAccessReturns(bool ef)
    {
        using var ctx = new FavoriteContext(ef);
        var project = ctx.Admin.CreateProject(new CreateProjectRequest { Name = "Assigned project" });
        var inaccessible = ctx.Admin.CreateProject(new CreateProjectRequest { Name = "Other project" });
        var user = ctx.AddProjectUser(project.ProjectId, "writer");
        Assert.Throws<UnauthorizedAccessException>(() => user.App.SetProjectFavorite(inaccessible.ProjectId, true));
        Assert.Throws<UnauthorizedAccessException>(() => user.App.SetProjectFavorite(Guid.NewGuid(), false));
        user.App.SetProjectFavorite(project.ProjectId, true);

        ctx.Admin.RemoveUserFromGroup(user.Membership);
        Assert.Empty(user.App.GetFavoriteProjectIds());
        Assert.Throws<UnauthorizedAccessException>(() => user.App.SetProjectFavorite(project.ProjectId, true));
        Assert.Throws<UnauthorizedAccessException>(() => user.App.SetProjectFavorite(project.ProjectId, false));
        Assert.Equal(project.ProjectId, Assert.Single(ctx.Store.LoadFavoriteProjectIds(user.User.UserId)));
        ctx.Admin.AssignUserToGroup(user.Membership);
        Assert.Equal(project.ProjectId, Assert.Single(user.App.GetFavoriteProjectIds()));

        ctx.Admin.DisableProject(project.ProjectId);
        Assert.Empty(user.App.GetFavoriteProjectIds());
        Assert.Throws<UnauthorizedAccessException>(() => user.App.SetProjectFavorite(project.ProjectId, true));
        // Administrators retain the same disabled-project access as My projects.
        Assert.True(ctx.Admin.SetProjectFavorite(project.ProjectId, true));
        Assert.Contains(project.ProjectId, ctx.Admin.GetFavoriteProjectIds());
        ctx.Admin.EnableProject(project.ProjectId);
        Assert.Contains(project.ProjectId, user.App.GetFavoriteProjectIds());

        ctx.Admin.DeleteProject(project.ProjectId);
        Assert.Empty(user.App.GetFavoriteProjectIds());
        Assert.Empty(ctx.Admin.GetFavoriteProjectIds());
        Assert.Throws<UnauthorizedAccessException>(() => ctx.Admin.SetProjectFavorite(project.ProjectId, true));
        ctx.Admin.RestoreProject(project.ProjectId);
        Assert.Contains(project.ProjectId, user.App.GetFavoriteProjectIds());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Favorites_RequireAnActiveAccountAndProjectRole(bool ef)
    {
        using var ctx = new FavoriteContext(ef);
        var project = ctx.Admin.CreateProject(new CreateProjectRequest { Name = "Private preference" });
        var user = ctx.AddProjectUser(project.ProjectId, "writer");
        user.App.SetProjectFavorite(project.ProjectId, true);
        user.App.LogoutCurrentUser();
        AssertUnauthorized(user.App, project.ProjectId);
        Assert.True(user.App.TryLocalLogin("writer", "WriterPass123!").Success);
        ctx.Admin.DisableUser(user.User.UserId);
        AssertUnauthorized(user.App, project.ProjectId);
        ctx.Admin.EnableUser(user.User.UserId);
        Assert.True(user.App.TryLocalLogin("writer", "WriterPass123!").Success);
        ctx.Admin.AddUserToRole(new UserRoleMembershipRequest { UserId = user.User.UserId, Role = AppRole.Auditor });
        ctx.Admin.RemoveUserFromRole(new UserRoleMembershipRequest { UserId = user.User.UserId, Role = AppRole.ProjectUser });
        AssertUnauthorized(user.App, project.ProjectId);
        Assert.Equal(project.ProjectId, Assert.Single(ctx.Store.LoadFavoriteProjectIds(user.User.UserId)));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task CachedCircuit_CannotReadOrMutateFavoritesAfterSessionRevocation(bool ef, bool expire)
    {
        using var ctx = new FavoriteContext(ef);
        var project = ctx.Admin.CreateProject(new CreateProjectRequest { Name = "Session preference" });
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "admin"),
            new Claim(ClaimTypes.Role, nameof(AppRole.Administrator))
        }, "Identity.Application"));
        var tickets = new InMemoryAuthenticationTicketStore();
        var ticket = new AuthenticationTicket(principal, new AuthenticationProperties
        {
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
        }, "Identity.Application");
        var key = await tickets.StoreAsync(ticket);
        var accessor = new HttpContextAccessor { HttpContext = new DefaultHttpContext { User = principal } };
        var app = ctx.CreateApp(accessor: accessor, tickets: tickets);
        await app.GetCurrentUserAsync();
        Assert.True(app.SetProjectFavorite(project.ProjectId, true));
        Assert.Contains(project.ProjectId, app.GetFavoriteProjectIds());
        if (expire)
        {
            ticket.Properties.ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(-1);
            await tickets.RenewAsync(key, ticket);
        }
        else await tickets.RemoveAsync(key);
        AssertUnauthorized(app, project.ProjectId);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PhysicalDeletion_CascadesOnlyAffectedPreferences(bool ef)
    {
        using var ctx = new FavoriteContext(ef);
        var first = ctx.Admin.CreateProject(new CreateProjectRequest { Name = "First" });
        var second = ctx.Admin.CreateProject(new CreateProjectRequest { Name = "Second" });
        var user = ctx.AddProjectUser(first.ProjectId, "writer");
        var adminId = ctx.Admin.GetCurrentUser().UserId;
        ctx.Admin.SetProjectFavorite(first.ProjectId, true);
        ctx.Admin.SetProjectFavorite(second.ProjectId, true);
        user.App.SetProjectFavorite(first.ProjectId, true);
        ctx.Store.RemoveUser(user.User.UserId);
        Assert.Empty(ctx.Store.LoadFavoriteProjectIds(user.User.UserId));
        Assert.Equal(2, ctx.Store.LoadFavoriteProjectIds(adminId).Count);
        ctx.Store.RemoveProject(first.ProjectId);
        Assert.Equal(second.ProjectId, Assert.Single(ctx.Store.LoadFavoriteProjectIds(adminId)));
        using var connection = ctx.OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_key_check";
        using var reader = command.ExecuteReader();
        Assert.False(reader.Read());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void LegacyDatabase_GainsFavoriteTableWithoutChangingExistingData(bool ef)
    {
        using var ctx = new FavoriteContext(ef);
        var project = ctx.Admin.CreateProject(new CreateProjectRequest { Name = "Existing project" });
        var entry = ctx.Admin.CreateJournalEntry(new CreateJournalEntryRequest
        {
            ProjectId = project.ProjectId, Subject = "Existing record", Description = "Existing body",
            Attachments = new[] { new JournalAttachmentUpload { FileName = "existing.txt", Content = new byte[] { 1, 2, 3 } } }
        });
        using (var connection = ctx.OpenConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "DROP TABLE project_favorites";
            command.ExecuteNonQuery();
        }
        var upgraded = ctx.CreateApp();
        Assert.True(upgraded.TryLocalLogin("admin", "AdminPass123!").Success);
        Assert.Empty(upgraded.GetFavoriteProjectIds());
        var savedEntry = Assert.Single(upgraded.GetJournalEntries(project.ProjectId));
        Assert.Equal(entry.RecordId, savedEntry.RecordId);
        Assert.Equal(entry.FullRecordChecksum, savedEntry.FullRecordChecksum);
        Assert.Equal(new byte[] { 1, 2, 3 }, upgraded.DownloadJournalAttachment(entry.Attachments.Single().AttachmentId).Content);
        Assert.True(upgraded.SetProjectFavorite(project.ProjectId, true));
        var restarted = ctx.CreateApp();
        Assert.True(restarted.TryLocalLogin("admin", "AdminPass123!").Success);
        Assert.Equal(project.ProjectId, Assert.Single(restarted.GetFavoriteProjectIds()));
    }

    private static void AssertUnauthorized(SecureJournalAppService app, Guid projectId)
    {
        Assert.Throws<UnauthorizedAccessException>(() => app.GetFavoriteProjectIds());
        Assert.Throws<UnauthorizedAccessException>(() => app.SetProjectFavorite(projectId, true));
        Assert.Throws<UnauthorizedAccessException>(() => app.SetProjectFavorite(projectId, false));
    }

    private sealed class FavoriteContext : IDisposable
    {
        private readonly bool _ef;
        private readonly string _path = Path.Combine(Path.GetTempPath(), $"securejournal-favorites-{Guid.NewGuid():N}.db");
        private readonly IConfiguration _configuration;
        private readonly PrototypeSharedState _shared = new();
        public IPrototypeDataStore Store { get; }
        public SecureJournalAppService Admin { get; }
        public FavoriteContext(bool ef)
        {
            _ef = ef;
            _configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:SecureJournalSqlite"] = $"Data Source={_path};Foreign Keys=True",
                ["Security:JournalEncryptionKey"] = "tests-journal-key",
                ["Security:LocalPasswordMinLength"] = "8",
                ["BootstrapAdmin:Username"] = "admin", ["BootstrapAdmin:DisplayName"] = "Admin",
                ["BootstrapAdmin:Password"] = "AdminPass123!"
            }).Build();
            Store = CreateStore();
            Admin = CreateApp(shared: true);
            Assert.True(Admin.TryLocalLogin("admin", "AdminPass123!").Success);
        }
        private IPrototypeDataStore CreateStore() => _ef
            ? new EfCorePrototypeStore(new TestDbFactory($"Data Source={_path};Foreign Keys=True"))
            : new SqlitePrototypeStore(_configuration);
        public SecureJournalAppService CreateApp(bool shared = false, HttpContextAccessor? accessor = null, InMemoryAuthenticationTicketStore? tickets = null)
        {
            var configuration = accessor is null ? _configuration
                : new ConfigurationBuilder().AddConfiguration(_configuration)
                    .AddInMemoryCollection(new Dictionary<string, string?> { ["Authentication:EnableAspNetIdentity"] = "true" }).Build();
            var checksum = new Sha256ChecksumService();
            var journal = new JournalFieldEncryptor(EncryptionKeyParser.GetKeyBytes("tests-journal-key", "journal"));
            var audit = new PlaintextAuditFieldEncryptor();
            return new SecureJournalAppService(checksum, audit, new JournalEntryRecordFactory(checksum, journal),
                new AuditLogRecordFactory(audit, checksum), new RecordViewMapper(journal, audit), new ExportContentFormatter(), CreateStore(),
                shared ? _shared : new PrototypeSharedState(), configuration, NullLogger<SecureJournalAppService>.Instance,
                accessor, authenticationTickets: tickets);
        }
        public (UserOverview User, AssignUserToGroupRequest Membership, SecureJournalAppService App) AddProjectUser(Guid projectId, string username)
        {
            var user = Admin.CreateUser(new CreateUserRequest { Username = username, DisplayName = username, Role = AppRole.ProjectUser, IsLocalAccount = true, LocalPassword = "WriterPass123!" });
            var group = Admin.CreateGroup(new CreateGroupRequest { Name = "Group " + username });
            var membership = new AssignUserToGroupRequest { UserId = user.UserId, GroupId = group.GroupId };
            Admin.AssignUserToGroup(membership);
            Admin.AssignGroupToProject(new AssignGroupToProjectRequest { GroupId = group.GroupId, ProjectId = projectId });
            var app = CreateApp(shared: true);
            Assert.True(app.TryLocalLogin(username, "WriterPass123!").Success);
            return (user, membership, app);
        }
        public SqliteConnection OpenConnection() { var connection = new SqliteConnection($"Data Source={_path};Foreign Keys=True"); connection.Open(); return connection; }
        public void Dispose() { SqliteConnection.ClearAllPools(); File.Delete(_path); }
    }
    private sealed class TestDbFactory(string connectionString) : IDbContextFactory<SecureJournalAppDbContext>
    {
        public SecureJournalAppDbContext CreateDbContext() => new(new DbContextOptionsBuilder<SecureJournalAppDbContext>().UseSqlite(connectionString).Options);
    }
}
