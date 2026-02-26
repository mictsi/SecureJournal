namespace SecureJournal.Web.Services;

public sealed record PrototypeSessionCookieSettings(
    string CookieName,
    int SessionCookieHours)
{
    public TimeSpan Lifetime => TimeSpan.FromHours(SessionCookieHours);

    public static PrototypeSessionCookieSettings FromConfiguration(IConfiguration configuration)
    {
        var cookieName = (configuration["Security:SessionCookieName"] ?? "SecureJournal.Session").Trim();
        var configuredHours = int.TryParse(configuration["Security:SessionCookieHours"], out var parsedHours)
            ? parsedHours
            : 8;

        if (string.IsNullOrWhiteSpace(cookieName))
        {
            cookieName = "SecureJournal.Session";
        }

        return new PrototypeSessionCookieSettings(
            cookieName,
            SessionCookieHours: Math.Max(1, configuredHours));
    }
}
