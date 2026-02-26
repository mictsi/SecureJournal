using System.Security.Claims;
using System.Data;
using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using SecureJournal.Web.Infrastructure.Identity;
using SecureJournal.Web.Infrastructure.Persistence;
using SecureJournal.Web.Services;

namespace SecureJournal.Web.Infrastructure;

public static class ProductionInfrastructureRegistration
{
    public static IServiceCollection AddProductionIdentityAndDatabaseFoundation(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        var persistenceOptions = ProductionPersistenceOptions.FromConfiguration(configuration);
        var identityOptions = ProductionIdentityOptions.FromConfiguration(configuration);

        services.AddSingleton(persistenceOptions);
        services.AddSingleton(identityOptions);

        if (!identityOptions.EnableAspNetIdentity || !persistenceOptions.EnableProductionIdentityDatabase)
        {
            if (persistenceOptions.EnableProductionAppDatabase)
            {
                services.AddDbContextFactory<SecureJournalAppDbContext>(options =>
                    ConfigureProvider(options, persistenceOptions.Provider, persistenceOptions.AppConnectionString));
            }

            return services;
        }

        if (persistenceOptions.EnableProductionIdentityDatabase)
        {
            services.AddDbContext<SecureJournalIdentityDbContext>(options =>
                ConfigureProvider(options, persistenceOptions.Provider, persistenceOptions.IdentityConnectionString));

            services.AddIdentityCore<SecureJournalIdentityUser>(options =>
                {
                    options.Password.RequireDigit = true;
                    options.Password.RequireLowercase = true;
                    options.Password.RequireUppercase = true;
                    options.Password.RequireNonAlphanumeric = true;
                    options.Password.RequiredLength = Math.Max(8, int.TryParse(configuration["Security:LocalPasswordMinLength"], out var min) ? min : 8);
                    options.User.RequireUniqueEmail = false;
                    options.SignIn.RequireConfirmedAccount = false;
                })
                .AddRoles<IdentityRole>()
                .AddSignInManager()
                .AddEntityFrameworkStores<SecureJournalIdentityDbContext>()
                .AddDefaultTokenProviders();

            services.ConfigureApplicationCookie(options =>
            {
                var cookieHours = int.TryParse(configuration["Security:SessionCookieHours"], out var parsedHours)
                    ? Math.Max(1, parsedHours)
                    : 8;
                var cookieName = configuration["Security:SessionCookieName"];
                if (!string.IsNullOrWhiteSpace(cookieName))
                {
                    options.Cookie.Name = cookieName;
                }

                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.ExpireTimeSpan = TimeSpan.FromHours(cookieHours);
                options.SlidingExpiration = true;
                options.LoginPath = "/";
                options.AccessDeniedPath = "/";
            });
        }

        var authBuilder = services.AddAuthentication(options =>
            {
                options.DefaultScheme = IdentityConstants.ApplicationScheme;
                options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
                options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
            });

        authBuilder.AddIdentityCookies();

        var enableOidc = bool.TryParse(configuration["Authentication:EnableOidc"], out var parsedEnableOidc) && parsedEnableOidc;
        if (enableOidc)
        {
            authBuilder.AddOpenIdConnect("oidc", options =>
                {
                    options.SignInScheme = IdentityConstants.ExternalScheme;
                    options.Authority = configuration["Authentication:Oidc:Authority"];
                    options.ClientId = configuration["Authentication:Oidc:ClientId"];
                    options.ClientSecret = configuration["Authentication:Oidc:ClientSecret"];
                    options.CallbackPath = configuration["Authentication:Oidc:CallbackPath"] ?? "/signin-oidc";
                    options.ResponseType = OpenIdConnectResponseType.Code;
                    options.SaveTokens = true;
                    options.GetClaimsFromUserInfoEndpoint = true;
                    options.MapInboundClaims = false;
                    options.TokenValidationParameters.NameClaimType = "name";
                    options.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;
                });
        }

        services.AddAuthorization();
        services.AddScoped<IClaimsTransformation, OidcRoleMappingClaimsTransformer>();
        services.AddScoped<ProductionIdentityBootstrapSeeder>();

        if (persistenceOptions.EnableProductionAppDatabase)
        {
            services.AddDbContextFactory<SecureJournalAppDbContext>(options =>
                ConfigureProvider(options, persistenceOptions.Provider, persistenceOptions.AppConnectionString));
        }

        return services;
    }

    public static async Task InitializeProductionIdentityDatabaseAsync(this WebApplication app)
    {
        var persistenceOptions = app.Services.GetRequiredService<ProductionPersistenceOptions>();
        var identityOptions = app.Services.GetRequiredService<ProductionIdentityOptions>();

        if (persistenceOptions.EnableProductionAppDatabase)
        {
            using var appScope = app.Services.CreateScope();
            var appDbFactory = appScope.ServiceProvider.GetRequiredService<IDbContextFactory<SecureJournalAppDbContext>>();
            await using var appDb = await appDbFactory.CreateDbContextAsync();
            await EnsureContextDatabaseReadyAsync(appDb, persistenceOptions.Provider, persistenceOptions.AutoMigrateOnStartup, "app_users");
        }

        if (!identityOptions.EnableAspNetIdentity || !persistenceOptions.EnableProductionIdentityDatabase)
        {
            return;
        }

        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureJournalIdentityDbContext>();
        await EnsureContextDatabaseReadyAsync(db, persistenceOptions.Provider, persistenceOptions.AutoMigrateOnStartup, "AspNetRoles");

        var seeder = scope.ServiceProvider.GetRequiredService<ProductionIdentityBootstrapSeeder>();
        await seeder.SeedAsync();
    }

    private static void ConfigureProvider(DbContextOptionsBuilder options, ProductionDatabaseProvider provider, string connectionString)
    {
        switch (provider)
        {
            case ProductionDatabaseProvider.SqlServer:
                options.UseSqlServer(connectionString, sql => sql.EnableRetryOnFailure());
                break;
            case ProductionDatabaseProvider.PostgreSql:
                options.UseNpgsql(connectionString, npgsql => npgsql.EnableRetryOnFailure());
                break;
            default:
                options.UseSqlite(connectionString);
                break;
        }
    }

    private static async Task EnsureContextDatabaseReadyAsync(
        DbContext context,
        ProductionDatabaseProvider provider,
        bool autoMigrateOnStartup,
        string sentinelTableName)
    {
        var database = context.Database;

        if (autoMigrateOnStartup)
        {
            try
            {
                await database.MigrateAsync();
                return;
            }
            catch (InvalidOperationException)
            {
                // No migrations were added yet for this context; fall back to schema creation.
            }
        }

        var created = await database.EnsureCreatedAsync();
        if (created)
        {
            return;
        }

        // EnsureCreated() skips schema creation if *any* table already exists in the database.
        // When app-data and Identity contexts share one database, the second context needs its
        // own tables created explicitly.
        if (await TableExistsAsync(database, provider, sentinelTableName))
        {
            return;
        }

        var createScript = database.GenerateCreateScript();
        if (string.IsNullOrWhiteSpace(createScript))
        {
            return;
        }

        try
        {
            await ExecuteCreateScriptAsync(database, provider, createScript);
        }
        catch
        {
            // If another startup path created the tables concurrently, treat it as success.
            if (await TableExistsAsync(database, provider, sentinelTableName))
            {
                return;
            }

            throw;
        }
    }

    private static async Task ExecuteCreateScriptAsync(DatabaseFacade database, ProductionDatabaseProvider provider, string createScript)
    {
        if (provider != ProductionDatabaseProvider.SqlServer)
        {
            await database.ExecuteSqlRawAsync(createScript);
            return;
        }

        foreach (var batch in SplitSqlServerBatches(createScript))
        {
            if (string.IsNullOrWhiteSpace(batch))
            {
                continue;
            }

            await database.ExecuteSqlRawAsync(batch);
        }
    }

    private static IEnumerable<string> SplitSqlServerBatches(string script)
    {
        var sb = new StringBuilder();
        using var reader = new StringReader(script);

        while (reader.ReadLine() is { } line)
        {
            if (string.Equals(line.Trim(), "GO", StringComparison.OrdinalIgnoreCase))
            {
                if (sb.Length > 0)
                {
                    yield return sb.ToString();
                    sb.Clear();
                }

                continue;
            }

            sb.AppendLine(line);
        }

        if (sb.Length > 0)
        {
            yield return sb.ToString();
        }
    }

    private static async Task<bool> TableExistsAsync(DatabaseFacade database, ProductionDatabaseProvider provider, string tableName)
    {
        var connection = database.GetDbConnection();
        var shouldClose = connection.State != ConnectionState.Open;
        if (shouldClose)
        {
            await connection.OpenAsync();
        }

        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = provider switch
            {
                ProductionDatabaseProvider.SqlServer =>
                    "SELECT TOP(1) 1 FROM sys.tables WHERE [name] = @tableName",
                ProductionDatabaseProvider.PostgreSql =>
                    "SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = @tableName LIMIT 1",
                _ =>
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = @tableName LIMIT 1"
            };

            var parameter = command.CreateParameter();
            parameter.ParameterName = "@tableName";
            parameter.Value = tableName;
            command.Parameters.Add(parameter);

            var result = await command.ExecuteScalarAsync();
            return result is not null and not DBNull;
        }
        finally
        {
            if (shouldClose)
            {
                await connection.CloseAsync();
            }
        }
    }
}
