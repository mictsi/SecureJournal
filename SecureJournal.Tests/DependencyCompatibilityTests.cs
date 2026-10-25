using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using SecureJournal.Web.Infrastructure.Persistence;
using Xunit;

namespace SecureJournal.Tests;

public sealed class DependencyCompatibilityTests
{
    [Fact]
    public void Sqlite_LoadsPatchedNativeEngine_AndSupportsTransactionalAppStorage()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        using (var versionCommand = connection.CreateCommand())
        {
            versionCommand.CommandText = "SELECT sqlite_version()";
            var nativeVersion = Version.Parse(Assert.IsType<string>(versionCommand.ExecuteScalar()));
            Assert.True(nativeVersion >= new Version(3, 54, 1), $"Loaded SQLite {nativeVersion}; expected 3.54.1 or newer.");
        }

        var options = new DbContextOptionsBuilder<SecureJournalAppDbContext>()
            .UseSqlite(connection)
            .Options;
        using var context = new SecureJournalAppDbContext(options);
        context.Database.EnsureCreated();

        var projectId = Guid.NewGuid();
        using (var transaction = context.Database.BeginTransaction())
        {
            context.Projects.Add(new ProjectEntity
            {
                ProjectId = projectId,
                Code = "COMPAT-1",
                Name = "Dependency compatibility"
            });
            context.SaveChanges();
            transaction.Commit();
        }

        context.ChangeTracker.Clear();
        Assert.Equal("Dependency compatibility", context.Projects.Single(project => project.ProjectId == projectId).Name);

        using (var transaction = context.Database.BeginTransaction())
        {
            context.Projects.Where(project => project.ProjectId == projectId).ExecuteDelete();
            transaction.Rollback();
        }

        Assert.True(context.Projects.AsNoTracking().Any(project => project.ProjectId == projectId));
    }

    [Theory]
    [InlineData("SqlServer")]
    [InlineData("PostgreSql")]
    public void DatabaseProviders_BuildAppSchemaAndTranslateQueries_WithoutConnecting(string provider)
    {
        var options = new DbContextOptionsBuilder<SecureJournalAppDbContext>();
        if (provider == "SqlServer")
        {
            options.UseSqlServer("Server=localhost;Database=compatibility_only;Integrated Security=true;Encrypt=true");
        }
        else
        {
            options.UseNpgsql("Host=localhost;Database=compatibility_only;Username=compatibility_only");
        }

        using var context = new SecureJournalAppDbContext(options.Options);
        var schema = context.Database.GenerateCreateScript();
        var projectId = Guid.NewGuid();
        var query = context.Projects
            .AsNoTracking()
            .Where(project => project.ProjectId == projectId && !project.IsSoftDeleted)
            .OrderBy(project => project.Name)
            .Take(10)
            .ToQueryString();

        Assert.Contains("journal_entries", schema);
        Assert.Contains("audit_logs", schema);
        Assert.Contains("WHERE", query);
        Assert.Contains("ORDER BY", query);
        Assert.Equal(System.Data.ConnectionState.Closed, context.Database.GetDbConnection().State);

        if (provider == "SqlServer")
        {
            Assert.IsType<SqlConnection>(context.Database.GetDbConnection());
        }
        else
        {
            Assert.IsType<NpgsqlConnection>(context.Database.GetDbConnection());
        }
    }

    [Theory]
    [InlineData(SqlAuthenticationMethod.ActiveDirectoryDefault)]
    [InlineData(SqlAuthenticationMethod.ActiveDirectoryManagedIdentity)]
    [InlineData(SqlAuthenticationMethod.ActiveDirectoryServicePrincipal)]
    public void SqlClient_AzureExtensionRegistersSupportedAuthenticationProviders(SqlAuthenticationMethod method)
    {
        // No credentials are requested and no database connection is opened.
        // SqlClient 7 requires its separate Azure extension for these modes.
        using var connection = new SqlConnection("Server=localhost;Database=compatibility_only;Authentication=Active Directory Default");
        var provider = SqlAuthenticationProvider.GetProvider(method);

        Assert.NotNull(provider);
        Assert.IsType<ActiveDirectoryAuthenticationProvider>(provider);
        Assert.True(provider.IsSupported(method));
        Assert.Equal(System.Data.ConnectionState.Closed, connection.State);
    }
}
