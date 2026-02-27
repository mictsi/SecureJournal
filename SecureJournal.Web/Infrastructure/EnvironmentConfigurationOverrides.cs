namespace SecureJournal.Web.Infrastructure;

internal static class EnvironmentConfigurationOverrides
{
    private static readonly string[] AzureConnectionStringPrefixes =
    [
        "SQLCONNSTR_",
        "SQLAZURECONNSTR_",
        "MYSQLCONNSTR_",
        "POSTGRESQLCONNSTR_",
        "CUSTOMCONNSTR_"
    ];

    private static readonly string[] KnownConnectionStringNames =
    [
        "SecureJournalSqlite",
        "SecureJournalSqlServer",
        "SecureJournalPostgres",
        "SecureJournalIdentitySqlite",
        "SecureJournalIdentitySqlServer",
        "SecureJournalIdentityPostgres"
    ];

    public static void Apply(ConfigurationManager configuration)
    {
        var overrides = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

        AddFirstPresent(overrides, "Security:JournalEncryptionKey",
            "SECUREJOURNAL_JOURNAL_ENCRYPTION_KEY",
            "JOURNAL_ENCRYPTION_KEY");
        AddFirstPresent(overrides, "BootstrapAdmin:Password",
            "SECUREJOURNAL_BOOTSTRAP_ADMIN_PASSWORD",
            "BOOTSTRAP_ADMIN_PASSWORD");
        AddFirstPresent(overrides, "BootstrapAdmin:Username",
            "SECUREJOURNAL_BOOTSTRAP_ADMIN_USERNAME",
            "BOOTSTRAP_ADMIN_USERNAME");
        AddFirstPresent(overrides, "BootstrapAdmin:DisplayName",
            "SECUREJOURNAL_BOOTSTRAP_ADMIN_DISPLAYNAME",
            "BOOTSTRAP_ADMIN_DISPLAYNAME");
        AddFirstPresent(overrides, "Persistence:Provider",
            "SECUREJOURNAL_PERSISTENCE_PROVIDER");
        AddFirstPresent(overrides, "Persistence:AppConnectionString",
            "SECUREJOURNAL_APP_CONNECTION_STRING");
        AddFirstPresent(overrides, "Persistence:IdentityConnectionString",
            "SECUREJOURNAL_IDENTITY_CONNECTION_STRING");

        foreach (var connectionStringName in KnownConnectionStringNames)
        {
            foreach (var prefix in AzureConnectionStringPrefixes)
            {
                var value = Environment.GetEnvironmentVariable($"{prefix}{connectionStringName}");
                if (!string.IsNullOrWhiteSpace(value))
                {
                    overrides[$"ConnectionStrings:{connectionStringName}"] = value;
                    break;
                }
            }
        }

        if (overrides.Count > 0)
        {
            configuration.AddInMemoryCollection(overrides);
        }
    }

    public static void ApplyWebHostPortOverride(WebApplicationBuilder builder)
    {
        if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ASPNETCORE_URLS")))
        {
            return;
        }

        var websitesPort = Environment.GetEnvironmentVariable("WEBSITES_PORT");
        if (string.IsNullOrWhiteSpace(websitesPort))
        {
            return;
        }

        builder.WebHost.UseUrls($"http://+:{websitesPort.Trim()}");
    }

    private static void AddFirstPresent(
        IDictionary<string, string?> values,
        string targetKey,
        params string[] envVarNames)
    {
        foreach (var envVarName in envVarNames)
        {
            var value = Environment.GetEnvironmentVariable(envVarName);
            if (!string.IsNullOrWhiteSpace(value))
            {
                values[targetKey] = value;
                return;
            }
        }
    }
}
