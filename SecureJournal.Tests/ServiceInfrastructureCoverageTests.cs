using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;
using SecureJournal.Web.Infrastructure;
using SecureJournal.Web.Infrastructure.Identity;
using SecureJournal.Web.Infrastructure.Logging;
using SecureJournal.Web.Infrastructure.Persistence;
using SecureJournal.Web.Services;
using Xunit;

namespace SecureJournal.Tests;

public sealed class JournalEntryRecordFactoryTests
{
    [Fact]
    public void Create_EncryptsFieldsAndComputesChecksums()
    {
        var checksum = new RecordingChecksumService();
        var encryptor = new PrefixJournalEncryptor();
        var factory = new JournalEntryRecordFactory(checksum, encryptor);
        var projectId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var userId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var createdAtUtc = new DateTime(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc);

        var record = factory.Create(
            projectId,
            userId,
            "alice",
            createdAtUtc,
            "subject",
            "description",
            "notes",
            "result");

        Assert.NotEqual(Guid.Empty, record.RecordId);
        Assert.Equal(projectId, record.ProjectId);
        Assert.Equal(userId, record.CreatedByUserId);
        Assert.Equal("alice", record.CreatedByUsername);
        Assert.Equal("enc:subject", record.SubjectCiphertext);
        Assert.Equal("enc:description", record.DescriptionCiphertext);
        Assert.Equal("enc:notes", record.NotesCiphertext);
        Assert.Equal("enc:result", record.ResultCiphertext);
        Assert.Equal("chk:subject", record.SubjectChecksum);
        Assert.Equal("chk:description", record.DescriptionChecksum);
        Assert.Equal("chk:notes", record.NotesChecksum);
        Assert.Equal("chk:result", record.ResultChecksum);
        Assert.StartsWith("chk:", record.FullRecordChecksum, StringComparison.Ordinal);
        Assert.Contains("subject", checksum.Inputs);
        Assert.Contains("description", checksum.Inputs);
        Assert.Contains("notes", checksum.Inputs);
        Assert.Contains("result", checksum.Inputs);
    }
}

public sealed class AuditLogRecordFactoryTests
{
    [Fact]
    public void Create_UsesSystemActorAndNormalizedDetails()
    {
        var encryptor = new PrefixAuditEncryptor();
        var checksum = new RecordingChecksumService();
        var factory = new AuditLogRecordFactory(encryptor, checksum);

        var record = factory.Create(
            actor: null,
            AuditActionType.Login,
            AuditEntityType.Authentication,
            entityId: "entity-1",
            projectId: null,
            AuditOutcome.Success,
            details: "  details  ");

        Assert.Equal("system", record.ActorUsername);
        Assert.Null(record.ActorUserId);
        Assert.Equal("entity-1", record.EntityId);
        Assert.Equal("enc:details", record.DetailsCiphertext);
        Assert.StartsWith("chk:", record.DetailsChecksum, StringComparison.Ordinal);
        Assert.Contains(checksum.Inputs, input => input.Contains("details", StringComparison.Ordinal));
        Assert.DoesNotContain(checksum.Inputs, input => input.Contains("  details  ", StringComparison.Ordinal));
    }
}

public sealed class OidcRoleMappingClaimsTransformerTests
{
    [Fact]
    public async Task TransformAsync_AddsMappedRolesWithoutDuplicatingExistingRoles()
    {
        var identity = new ClaimsIdentity(
        [
            new Claim("groups", "admins"),
            new Claim("groups", "auditors"),
            new Claim(ClaimTypes.NameIdentifier, "subject-1"),
            new Claim(ClaimTypes.Role, nameof(AppRole.Administrator))
        ], authenticationType: "oidc");
        var principal = new ClaimsPrincipal(identity);
        var mappings = new OidcRoleGroupMappings(
            "groups",
            new Dictionary<AppRole, IReadOnlyList<string>>
            {
                [AppRole.Administrator] = ["admins"],
                [AppRole.Auditor] = ["auditors"]
            });
        var transformer = new OidcRoleMappingClaimsTransformer(mappings, NullLogger<OidcRoleMappingClaimsTransformer>.Instance);

        var transformed = await transformer.TransformAsync(principal);
        var roles = transformed.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

        Assert.Equal(2, roles.Count);
        Assert.Contains(nameof(AppRole.Administrator), roles);
        Assert.Contains(nameof(AppRole.Auditor), roles);
        Assert.Equal(1, roles.Count(r => r == nameof(AppRole.Administrator)));
    }

    [Fact]
    public async Task TransformAsync_ReturnsOriginalPrincipalForUnauthenticatedIdentity()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var transformer = new OidcRoleMappingClaimsTransformer(
            new OidcRoleGroupMappings("groups", new Dictionary<AppRole, IReadOnlyList<string>>()),
            NullLogger<OidcRoleMappingClaimsTransformer>.Instance);

        var transformed = await transformer.TransformAsync(principal);

        Assert.Same(principal, transformed);
        Assert.Empty(transformed.Claims);
    }
}

public sealed class OidcPrincipalHelpersTests
{
    [Fact]
    public void GetNormalizedPrincipalUsername_PrefersOidcClaimsAndLowercases()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "sub-1"),
            new Claim("iss", "https://issuer.example"),
            new Claim("preferred_username", "  ALICE@EXAMPLE.COM ")
        ], "oidc"));

        var username = OidcPrincipalHelpers.GetNormalizedPrincipalUsername(principal);

        Assert.Equal("alice@example.com", username);
    }

    [Fact]
    public void TryGetOidcIdentityKey_FallsBackToSubjectClaimIssuer()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", "subject-1", ClaimValueTypes.String, "https://issuer.example")
        ], "oidc"));

        var found = OidcPrincipalHelpers.TryGetOidcIdentityKey(principal, out var issuer, out var subject);

        Assert.True(found);
        Assert.Equal("https://issuer.example", issuer);
        Assert.Equal("subject-1", subject);
    }

    [Fact]
    public void TryGetOidcIdentityKey_BuildsIssuerFromTenantId()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("oid", "object-1"),
            new Claim("tid", "tenant-1")
        ], "oidc"));

        var found = OidcPrincipalHelpers.TryGetOidcIdentityKey(principal, out var issuer, out var subject);

        Assert.True(found);
        Assert.Equal("https://login.microsoftonline.com/tenant-1/v2.0", issuer);
        Assert.Equal("object-1", subject);
    }

    [Fact]
    public void FormatPrincipalClaimsForDiagnostics_RedactsSensitiveValuesAndTruncatesLongClaims()
    {
        var longValue = new string('x', 300);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("access_token", "top-secret-token"),
            new Claim("name", "line1\r\nline2"),
            new Claim("long", longValue)
        ], "oidc"));

        var formatted = OidcPrincipalHelpers.FormatPrincipalClaimsForDiagnostics(principal);

        Assert.Contains("access_token=<redacted:16 chars>", formatted, StringComparison.Ordinal);
        Assert.Contains("name=line1  line2", formatted, StringComparison.Ordinal);
        Assert.Contains("...(300 chars)", formatted, StringComparison.Ordinal);
    }
}

public sealed class ProductionPersistenceOptionsTests
{
    [Fact]
    public void FromConfiguration_UsesConfiguredProviderAndConnectionStrings()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Persistence:Provider"] = "PostgreSql",
                ["Persistence:EnableProductionAppDatabase"] = "true",
                ["Persistence:EnableProductionIdentityDatabase"] = "true",
                ["Persistence:AutoMigrateOnStartup"] = "true",
                ["Persistence:AppConnectionString"] = "Host=app-db",
                ["ConnectionStrings:SecureJournalIdentityPostgres"] = "Host=identity-db"
            })
            .Build();

        var options = ProductionPersistenceOptions.FromConfiguration(configuration);

        Assert.Equal(ProductionDatabaseProvider.PostgreSql, options.Provider);
        Assert.True(options.EnableProductionAppDatabase);
        Assert.True(options.EnableProductionIdentityDatabase);
        Assert.True(options.AutoMigrateOnStartup);
        Assert.Equal("Host=app-db", options.AppConnectionString);
        Assert.Equal("Host=identity-db", options.IdentityConnectionString);
    }

    [Fact]
    public void FromConfiguration_UsesEnvironmentFallbackForAzureConnectionStrings()
    {
        const string envVar = "SQLCONNSTR_SecureJournalSqlServer";
        var previous = Environment.GetEnvironmentVariable(envVar);
        try
        {
            Environment.SetEnvironmentVariable(envVar, "Server=tcp:test");
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Persistence:Provider"] = "SqlServer",
                    ["Persistence:EnableProductionAppDatabase"] = "true"
                })
                .Build();

            var options = ProductionPersistenceOptions.FromConfiguration(configuration);

            Assert.Equal(ProductionDatabaseProvider.SqlServer, options.Provider);
            Assert.Equal("Server=tcp:test", options.AppConnectionString);
        }
        finally
        {
            Environment.SetEnvironmentVariable(envVar, previous);
        }
    }

    [Fact]
    public void FromConfiguration_ThrowsWhenEnabledConnectionStringIsMissing()
    {
        var envVarNames = new[]
        {
            "ConnectionStrings__SecureJournalIdentitySqlite",
            "SQLCONNSTR_SecureJournalIdentitySqlite",
            "SQLAZURECONNSTR_SecureJournalIdentitySqlite",
            "MYSQLCONNSTR_SecureJournalIdentitySqlite",
            "POSTGRESQLCONNSTR_SecureJournalIdentitySqlite",
            "CUSTOMCONNSTR_SecureJournalIdentitySqlite"
        };
        var previousValues = envVarNames.ToDictionary(name => name, Environment.GetEnvironmentVariable, StringComparer.Ordinal);

        try
        {
            foreach (var envVarName in envVarNames)
            {
                Environment.SetEnvironmentVariable(envVarName, null);
            }

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Persistence:EnableProductionIdentityDatabase"] = "true"
                })
                .Build();

            var ex = Assert.Throws<InvalidOperationException>(() => ProductionPersistenceOptions.FromConfiguration(configuration));

            Assert.Contains("Missing identity connection string", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            foreach (var pair in previousValues)
            {
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }
        }
    }
}

public sealed class ProductionInfrastructureRegistrationTests
{
    [Fact]
    public void BuildSqlServerLegacyJournalCategoryCompatibilitySql_UsesDynamicSqlForLegacyColumns()
    {
        var sql = ProductionInfrastructureRegistration.BuildSqlServerLegacyJournalCategoryCompatibilitySql();

        Assert.Contains("EXEC(N'", sql, StringComparison.Ordinal);
        Assert.Contains("WHERE [category_ciphertext] IS NULL;');", sql, StringComparison.Ordinal);
        Assert.Contains("WHERE [category_checksum] IS NULL;');", sql, StringComparison.Ordinal);
        Assert.Contains("DEFAULT (N'''') FOR [category_ciphertext];');", sql, StringComparison.Ordinal);
        Assert.Contains("DEFAULT (N'''') FOR [category_checksum];');", sql, StringComparison.Ordinal);
    }
}

public sealed class EnvironmentConfigurationOverridesTests
{
    [Fact]
    public void Apply_MapsExplicitAndAzureStyleEnvironmentOverrides()
    {
        var previousJournalKey = Environment.GetEnvironmentVariable("SECUREJOURNAL_JOURNAL_ENCRYPTION_KEY");
        var previousBootstrapPassword = Environment.GetEnvironmentVariable("BOOTSTRAP_ADMIN_PASSWORD");
        var previousSqliteConn = Environment.GetEnvironmentVariable("CUSTOMCONNSTR_SecureJournalSqlite");
        try
        {
            Environment.SetEnvironmentVariable("SECUREJOURNAL_JOURNAL_ENCRYPTION_KEY", "journal-key");
            Environment.SetEnvironmentVariable("BOOTSTRAP_ADMIN_PASSWORD", "admin-pass");
            Environment.SetEnvironmentVariable("CUSTOMCONNSTR_SecureJournalSqlite", "Data Source=env.db");

            var builder = WebApplication.CreateBuilder();

            EnvironmentConfigurationOverrides.Apply(builder.Configuration);

            Assert.Equal("journal-key", builder.Configuration["Security:JournalEncryptionKey"]);
            Assert.Equal("admin-pass", builder.Configuration["BootstrapAdmin:Password"]);
            Assert.Equal("Data Source=env.db", builder.Configuration.GetConnectionString("SecureJournalSqlite"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("SECUREJOURNAL_JOURNAL_ENCRYPTION_KEY", previousJournalKey);
            Environment.SetEnvironmentVariable("BOOTSTRAP_ADMIN_PASSWORD", previousBootstrapPassword);
            Environment.SetEnvironmentVariable("CUSTOMCONNSTR_SecureJournalSqlite", previousSqliteConn);
        }
    }
}

public sealed class FileLoggingSettingsTests
{
    [Fact]
    public void FromConfiguration_UsesDefaultsAndParsesOverrides()
    {
        var defaults = FileLoggingSettings.FromConfiguration(new ConfigurationBuilder().AddInMemoryCollection().Build());
        Assert.False(defaults.Enabled);
        Assert.Equal("logs/securejournal.log", defaults.Path);
        Assert.Equal(LogLevel.Information, defaults.MinimumLevel);

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Logging:File:Enabled"] = "true",
                ["Logging:File:Path"] = "  logs/custom.log  ",
                ["Logging:File:MinimumLevel"] = "debug"
            })
            .Build();

        var parsed = FileLoggingSettings.FromConfiguration(configuration);

        Assert.True(parsed.Enabled);
        Assert.Equal("logs/custom.log", parsed.Path);
        Assert.Equal(LogLevel.Debug, parsed.MinimumLevel);
    }
}

public sealed class SimpleFileLoggerProviderTests
{
    [Fact]
    public void Logger_WritesEnabledMessagesAndSkipsBelowMinimumLevel()
    {
        var tempDirectory = Path.Combine(Path.GetTempPath(), "SecureJournal.Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDirectory);
        var logPath = Path.Combine(tempDirectory, "app.log");

        try
        {
            using (var provider = new SimpleFileLoggerProvider(tempDirectory, new FileLoggingSettings(true, logPath, LogLevel.Warning)))
            {
                var logger = provider.CreateLogger("SecureJournal.Tests.Logger");

                logger.LogInformation("ignored");
                logger.LogWarning(new EventId(7, "WarnEvent"), new InvalidOperationException("boom"), "written {Value}", 42);
            }

            var text = File.ReadAllText(logPath);

            Assert.DoesNotContain("ignored", text, StringComparison.Ordinal);
            Assert.Contains("[Warning] SecureJournal.Tests.Logger (7:WarnEvent): written 42", text, StringComparison.Ordinal);
            Assert.Contains("System.InvalidOperationException: boom", text, StringComparison.Ordinal);
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempDirectory))
                {
                    Directory.Delete(tempDirectory, recursive: true);
                }
            }
            catch
            {
                // Best-effort cleanup for temporary logger tests.
            }
        }
    }
}

file sealed class PrefixJournalEncryptor : IJournalFieldEncryptor
{
    public string Encrypt(string plaintext) => $"enc:{plaintext}";
    public string Decrypt(string ciphertext) => ciphertext;
}

file sealed class PrefixAuditEncryptor : IAuditFieldEncryptor
{
    public string Encrypt(string plaintext) => $"enc:{plaintext}";
    public string Decrypt(string ciphertext) => ciphertext;
}

file sealed class RecordingChecksumService : IChecksumService
{
    public List<string> Inputs { get; } = new();

    public string ComputeHex(string value)
    {
        Inputs.Add(value);
        return $"chk:{value}";
    }
}
