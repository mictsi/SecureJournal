using Microsoft.JSInterop;
using SecureJournal.Core.Application;

namespace SecureJournal.Web.Services;

public sealed class PrototypeSessionCookieCoordinator
{
    private readonly ISecureJournalAppService _app;
    private readonly PrototypeSessionRegistry _sessionRegistry;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IJSRuntime _jsRuntime;
    private readonly ILogger<PrototypeSessionCookieCoordinator> _logger;
    private readonly PrototypeSessionCookieSettings _settings;
    private readonly bool _enableAspNetIdentity;

    public PrototypeSessionCookieCoordinator(
        ISecureJournalAppService app,
        PrototypeSessionRegistry sessionRegistry,
        IHttpContextAccessor httpContextAccessor,
        IJSRuntime jsRuntime,
        IConfiguration configuration,
        ILogger<PrototypeSessionCookieCoordinator> logger)
    {
        _app = app;
        _sessionRegistry = sessionRegistry;
        _httpContextAccessor = httpContextAccessor;
        _jsRuntime = jsRuntime;
        _logger = logger;
        _settings = PrototypeSessionCookieSettings.FromConfiguration(configuration);
        _enableAspNetIdentity = bool.TryParse(configuration["Authentication:EnableAspNetIdentity"], out var enabled) && enabled;
    }

    public int SessionCookieHours => _settings.SessionCookieHours;

    public async Task PersistCurrentLoginAsync()
    {
        if (_enableAspNetIdentity)
        {
            return;
        }

        if (!_app.HasCurrentUser())
        {
            return;
        }

        var userId = _app.GetCurrentUser().UserId;
        var token = _sessionRegistry.CreateSession(userId, _settings.Lifetime);

        if (TryAppendServerCookie(token))
        {
            _logger.LogInformation("Session cookie persisted via HTTP response for user {UserId}", userId);
            return;
        }

        try
        {
            await _jsRuntime.InvokeVoidAsync(
                "secureJournalSession.set",
                _settings.CookieName,
                token,
                (int)_settings.Lifetime.TotalSeconds);

            _logger.LogInformation("Session cookie persisted via JS fallback for user {UserId}", userId);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Session cookie JS write failed after login for user {UserId}", userId);
        }
    }

    public async Task LogoutAndClearSessionAsync()
    {
        if (_enableAspNetIdentity)
        {
            await _app.LogoutCurrentUserAsync();
            return;
        }

        var token = TryReadServerCookie();
        if (string.IsNullOrWhiteSpace(token))
        {
            try
            {
                token = await _jsRuntime.InvokeAsync<string?>("secureJournalSession.get", _settings.CookieName);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Session cookie JS read failed during logout; proceeding with local logout");
            }
        }

        if (!string.IsNullOrWhiteSpace(token))
        {
            _sessionRegistry.Remove(token);
        }

        _app.LogoutCurrentUser();

        if (TryDeleteServerCookie())
        {
            _logger.LogInformation("Session cookie cleared via HTTP response");
            return;
        }

        try
        {
            await _jsRuntime.InvokeVoidAsync("secureJournalSession.clear", _settings.CookieName);
            _logger.LogInformation("Session cookie cleared via JS fallback");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Session cookie JS clear failed during logout");
        }
    }

    private bool TryAppendServerCookie(string token)
    {
        var context = _httpContextAccessor.HttpContext;
        if (context is null || context.Response.HasStarted)
        {
            return false;
        }

        context.Response.Cookies.Append(
            _settings.CookieName,
            token,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                IsEssential = true,
                Path = "/",
                Expires = DateTimeOffset.UtcNow.Add(_settings.Lifetime)
            });

        return true;
    }

    private bool TryDeleteServerCookie()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context is null || context.Response.HasStarted)
        {
            return false;
        }

        context.Response.Cookies.Delete(
            _settings.CookieName,
            new CookieOptions
            {
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                Path = "/"
            });

        return true;
    }

    private string? TryReadServerCookie()
    {
        var context = _httpContextAccessor.HttpContext;
        if (context is null)
        {
            return null;
        }

        return context.Request.Cookies.TryGetValue(_settings.CookieName, out var token)
            ? token
            : null;
    }
}
