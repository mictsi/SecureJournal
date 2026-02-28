namespace SecureJournal.Web.Services;

public sealed record PrototypeSessionCookieSettings(
    string CookieName,
    int SessionCookieHours,
    bool EnableJavaScriptFallback,
    int JavaScriptFallbackMaxAgeSeconds)
{
    public TimeSpan Lifetime => TimeSpan.FromHours(SessionCookieHours);

    public static PrototypeSessionCookieSettings FromConfiguration(IConfiguration configuration)
    {
        var cookieName = (configuration["Security:SessionCookieName"] ?? "SecureJournal.Session").Trim();
        var configuredHours = int.TryParse(configuration["Security:SessionCookieHours"], out var parsedHours)
            ? parsedHours
            : 8;
        var enableJavaScriptFallback = bool.TryParse(configuration["Security:EnableJsSessionCookieFallback"], out var parsedJsFallback)
            && parsedJsFallback;
        var configuredFallbackMaxAgeSeconds = int.TryParse(configuration["Security:JsSessionCookieFallbackMaxAgeSeconds"], out var parsedFallbackMaxAgeSeconds)
            ? parsedFallbackMaxAgeSeconds
            : 120;

        if (string.IsNullOrWhiteSpace(cookieName))
        {
            cookieName = "SecureJournal.Session";
        }

        return new PrototypeSessionCookieSettings(
            cookieName,
            SessionCookieHours: Math.Max(1, configuredHours),
            EnableJavaScriptFallback: enableJavaScriptFallback,
            JavaScriptFallbackMaxAgeSeconds: Math.Clamp(configuredFallbackMaxAgeSeconds, 30, 900));
    }
}
