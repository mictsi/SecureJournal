using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace SecureJournal.Tests;

public sealed class CsrfEndpointIntegrationTests
{
    [Fact]
    public async Task CSRF_LocalLogin_RejectsMissingAntiforgeryToken()
    {
        await using var factory = new SecureJournalWebAppFactory();
        using var client = factory.CreateSecureClient();
        const string successProbe = "/csrf-login-success-probe";
        const string failureProbe = "/csrf-login-failure-probe";

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = "admin",
            ["password"] = "AdminPass123!",
            ["returnUrl"] = successProbe,
            ["failurePath"] = failureProbe
        });

        using var response = await client.PostAsync("/auth/local-login", content);

        var details = await DescribeResponseAsync(response);
        Assert.False(response.IsSuccessStatusCode, details);
        Assert.True(
            response.StatusCode is System.Net.HttpStatusCode.BadRequest
                or System.Net.HttpStatusCode.InternalServerError
                or System.Net.HttpStatusCode.Found,
            details);

        var location = response.Headers.Location?.ToString() ?? string.Empty;
        Assert.DoesNotContain(successProbe, location, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(failureProbe, location, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CSRF_Logout_IsPostOnly_AndRejectsMissingAntiforgeryToken()
    {
        await using var factory = new SecureJournalWebAppFactory();
        using var client = factory.CreateSecureClient();
        const string getProbe = "/csrf-logout-get-probe";
        const string postProbe = "/csrf-logout-post-probe";

        using var getResponse = await client.GetAsync($"/auth/logout?returnUrl={Uri.EscapeDataString(getProbe)}");
        var getDetails = await DescribeResponseAsync(getResponse);
        Assert.False(getResponse.IsSuccessStatusCode, getDetails);
        Assert.True(
            getResponse.StatusCode is System.Net.HttpStatusCode.NotFound
                or System.Net.HttpStatusCode.MethodNotAllowed
                or System.Net.HttpStatusCode.Found,
            getDetails);
        var getLocation = getResponse.Headers.Location?.ToString() ?? string.Empty;
        Assert.DoesNotContain(getProbe, getLocation, StringComparison.OrdinalIgnoreCase);

        using var postContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["returnUrl"] = postProbe
        });
        using var postResponse = await client.PostAsync("/auth/logout", postContent);
        var postDetails = await DescribeResponseAsync(postResponse);

        Assert.False(postResponse.IsSuccessStatusCode, postDetails);
        Assert.True(
            postResponse.StatusCode is System.Net.HttpStatusCode.BadRequest
                or System.Net.HttpStatusCode.InternalServerError
                or System.Net.HttpStatusCode.Found,
            postDetails);
        var postLocation = postResponse.Headers.Location?.ToString() ?? string.Empty;
        Assert.DoesNotContain(postProbe, postLocation, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class SecureJournalWebAppFactory : WebApplicationFactory<global::Program>, IAsyncDisposable
    {
        private readonly string _appDbPath;
        private readonly string _identityDbPath;
        private readonly string _dbDirectory;
        private readonly Dictionary<string, string?> _previousEnvironmentValues = new(StringComparer.Ordinal);

        public SecureJournalWebAppFactory()
        {
            var repoRoot = FindRepoRoot(AppContext.BaseDirectory);
            _dbDirectory = Path.Combine(repoRoot, ".artifacts", "tests", "web-int", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(_dbDirectory);
            _appDbPath = Path.Combine(_dbDirectory, "securejournal.test.db");
            _identityDbPath = Path.Combine(_dbDirectory, "securejournal.identity.test.db");

            SetEnvironmentOverride("ASPNETCORE_ENVIRONMENT", "Production");
            SetEnvironmentOverride("ConnectionStrings__SecureJournalSqlite", $"Data Source={_appDbPath}");
            SetEnvironmentOverride("ConnectionStrings__SecureJournalIdentitySqlite", $"Data Source={_identityDbPath}");
            SetEnvironmentOverride("Persistence__Provider", "Sqlite");
            SetEnvironmentOverride("Persistence__EnableProductionAppDatabase", "true");
            SetEnvironmentOverride("Persistence__EnableProductionIdentityDatabase", "true");
            SetEnvironmentOverride("Persistence__AutoMigrateOnStartup", "false");
            SetEnvironmentOverride("Authentication__EnableLocalLogin", "true");
            SetEnvironmentOverride("Authentication__EnableAspNetIdentity", "true");
            SetEnvironmentOverride("Authentication__EnableOidc", "false");
            SetEnvironmentOverride("Security__JournalEncryptionKey", "tests-journal-key");
            SetEnvironmentOverride("BootstrapAdmin__Username", "admin");
            SetEnvironmentOverride("BootstrapAdmin__DisplayName", "Startup Admin");
            SetEnvironmentOverride("BootstrapAdmin__Password", "AdminPass123!");
            SetEnvironmentOverride("BootstrapAdmin__SyncPasswordOnStartup", "true");
        }

        public HttpClient CreateSecureClient()
            => CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                BaseAddress = new Uri("https://localhost")
            });

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment(Environments.Production);
            builder.ConfigureAppConfiguration((_, config) =>
            {
                config.Sources.Clear();
                config.AddEnvironmentVariables();
            });
        }

        public new async ValueTask DisposeAsync()
        {
            await base.DisposeAsync();
            try
            {
                if (Directory.Exists(_dbDirectory))
                {
                    Directory.Delete(_dbDirectory, recursive: true);
                }
            }
            catch
            {
                // Best-effort cleanup for test temp data.
            }

            foreach (var pair in _previousEnvironmentValues)
            {
                Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            }
        }

        private void SetEnvironmentOverride(string key, string value)
        {
            if (!_previousEnvironmentValues.ContainsKey(key))
            {
                _previousEnvironmentValues[key] = Environment.GetEnvironmentVariable(key);
            }

            Environment.SetEnvironmentVariable(key, value);
        }

        private static string FindRepoRoot(string startDirectory)
        {
            var directory = new DirectoryInfo(startDirectory);
            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "SecureJournal.slnx")))
                {
                    return directory.FullName;
                }

                directory = directory.Parent;
            }

            throw new InvalidOperationException("Could not locate repository root.");
        }
    }

    private static async Task<string> DescribeResponseAsync(HttpResponseMessage response)
    {
        var body = string.Empty;
        try
        {
            body = await response.Content.ReadAsStringAsync();
        }
        catch
        {
            // Best effort for diagnostics.
        }

        if (body.Length > 300)
        {
            body = body[..300];
        }

        return $"Status={(int)response.StatusCode} {response.StatusCode}; Location={response.Headers.Location}; Body={body}";
    }
}
