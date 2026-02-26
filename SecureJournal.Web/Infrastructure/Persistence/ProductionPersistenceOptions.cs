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

        var appConnectionString = configuration.GetConnectionString(appConnectionStringName) ?? string.Empty;
        if (enableApp && string.IsNullOrWhiteSpace(appConnectionString))
        {
            throw new InvalidOperationException($"Missing connection string '{appConnectionStringName}' for Persistence:Provider={provider}.");
        }

        var identityConnectionString = configuration.GetConnectionString(identityConnectionStringName) ?? string.Empty;
        if (enableIdentity && string.IsNullOrWhiteSpace(identityConnectionString))
        {
            throw new InvalidOperationException($"Missing connection string '{identityConnectionStringName}' for Persistence:Provider={provider}.");
        }

        return new ProductionPersistenceOptions(
            EnableProductionAppDatabase: enableApp,
            EnableProductionIdentityDatabase: enableIdentity,
            AutoMigrateOnStartup: autoMigrate,
            Provider: provider,
            AppConnectionString: appConnectionString,
            IdentityConnectionString: identityConnectionString);
    }
}
