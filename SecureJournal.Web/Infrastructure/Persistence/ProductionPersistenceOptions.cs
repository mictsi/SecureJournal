namespace SecureJournal.Web.Infrastructure.Persistence;

public enum ProductionDatabaseProvider
{
    Sqlite,
    SqlServer,
    PostgreSql
}

public sealed record ProductionPersistenceOptions(
    bool EnableProductionAppDatabase,
    bool EnableProductionIdentityDatabase,
    bool AutoMigrateOnStartup,
    ProductionDatabaseProvider Provider,
    string AppConnectionString,
    string IdentityConnectionString)
{
    public static ProductionPersistenceOptions FromConfiguration(IConfiguration configuration)
    {
        var providerText = configuration["Persistence:Provider"];
        var provider = Enum.TryParse<ProductionDatabaseProvider>(providerText, ignoreCase: true, out var parsedProvider)
            ? parsedProvider
            : ProductionDatabaseProvider.Sqlite;

        var enableApp = bool.TryParse(configuration["Persistence:EnableProductionAppDatabase"], out var parsedEnableApp) && parsedEnableApp;
        var enableIdentity = bool.TryParse(configuration["Persistence:EnableProductionIdentityDatabase"], out var parsedEnableIdentity) && parsedEnableIdentity;
        var autoMigrate = bool.TryParse(configuration["Persistence:AutoMigrateOnStartup"], out var parsedMigrate) && parsedMigrate;

        var appConnectionStringName = provider switch
        {
            ProductionDatabaseProvider.SqlServer => "SecureJournalSqlServer",
            ProductionDatabaseProvider.PostgreSql => "SecureJournalPostgres",
            _ => "SecureJournalSqlite"
        };
        var identityConnectionStringName = provider switch
        {
            ProductionDatabaseProvider.SqlServer => "SecureJournalIdentitySqlServer",
            ProductionDatabaseProvider.PostgreSql => "SecureJournalIdentityPostgres",
            _ => "SecureJournalIdentitySqlite"
        };

        var appConnectionString = ResolveConnectionString(
            configuration,
            configuredConnectionString: configuration["Persistence:AppConnectionString"],
            namedConnectionString: appConnectionStringName);
        if (enableApp && string.IsNullOrWhiteSpace(appConnectionString))
        {
            throw new InvalidOperationException(
                $"Missing app connection string. Set 'Persistence:AppConnectionString' or 'ConnectionStrings:{appConnectionStringName}'.");
        }

        var identityConnectionString = ResolveConnectionString(
            configuration,
            configuredConnectionString: configuration["Persistence:IdentityConnectionString"],
            namedConnectionString: identityConnectionStringName);
        if (enableIdentity && string.IsNullOrWhiteSpace(identityConnectionString))
        {
            throw new InvalidOperationException(
                $"Missing identity connection string. Set 'Persistence:IdentityConnectionString' or 'ConnectionStrings:{identityConnectionStringName}'.");
        }

        return new ProductionPersistenceOptions(
            EnableProductionAppDatabase: enableApp,
            EnableProductionIdentityDatabase: enableIdentity,
            AutoMigrateOnStartup: autoMigrate,
            Provider: provider,
            AppConnectionString: appConnectionString,
            IdentityConnectionString: identityConnectionString);
    }

    private static string ResolveConnectionString(
        IConfiguration configuration,
        string? configuredConnectionString,
        string namedConnectionString)
    {
        if (!string.IsNullOrWhiteSpace(configuredConnectionString))
        {
            return configuredConnectionString;
        }

        var fromConfig = configuration.GetConnectionString(namedConnectionString);
        if (!string.IsNullOrWhiteSpace(fromConfig))
        {
            return fromConfig;
        }

        var fromHierarchicalEnv = Environment.GetEnvironmentVariable($"ConnectionStrings__{namedConnectionString}");
        if (!string.IsNullOrWhiteSpace(fromHierarchicalEnv))
        {
            return fromHierarchicalEnv;
        }

        foreach (var prefix in new[] { "SQLCONNSTR_", "SQLAZURECONNSTR_", "MYSQLCONNSTR_", "POSTGRESQLCONNSTR_", "CUSTOMCONNSTR_" })
        {
            var fromAppService = Environment.GetEnvironmentVariable($"{prefix}{namedConnectionString}");
            if (!string.IsNullOrWhiteSpace(fromAppService))
            {
                return fromAppService;
            }
        }

        return string.Empty;
    }
}
