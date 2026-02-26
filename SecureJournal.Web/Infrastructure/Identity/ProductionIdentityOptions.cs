namespace SecureJournal.Web.Infrastructure.Identity;

public sealed record ProductionIdentityOptions(bool EnableAspNetIdentity)
{
    public static ProductionIdentityOptions FromConfiguration(IConfiguration configuration)
    {
        var enabled = bool.TryParse(configuration["Authentication:EnableAspNetIdentity"], out var parsed) && parsed;
        return new ProductionIdentityOptions(enabled);
    }
}
