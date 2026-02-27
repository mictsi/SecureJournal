using SecureJournal.Web.Components;
using SecureJournal.Web.Services;
using SecureJournal.Web.Infrastructure;
using SecureJournal.Web.Infrastructure.Logging;
using SecureJournal.Core.Application;
using SecureJournal.Core.Security;
using Microsoft.Extensions.Logging;
using SecureJournal.Web.Infrastructure.Persistence;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);
EnvironmentConfigurationOverrides.Apply(builder.Configuration);
EnvironmentConfigurationOverrides.ApplyWebHostPortOverride(builder);

builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false;
});

builder.Logging.ClearProviders();
builder.Logging.AddConfiguration(builder.Configuration.GetSection("Logging"));
var consoleLoggingSettings = ConsoleLoggingSettings.FromConfiguration(builder.Configuration);
if (consoleLoggingSettings.Enabled)
{
    builder.Logging.AddConsole();
}
builder.Logging.AddDebug();
var sqlQueryLoggingSettings = SqlQueryLoggingSettings.FromConfiguration(builder.Configuration);
if (!sqlQueryLoggingSettings.Enabled)
{
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Warning);
}
var fileLoggingSettings = FileLoggingSettings.FromConfiguration(builder.Configuration);
if (fileLoggingSettings.Enabled)
{
    builder.Logging.AddProvider(new SimpleFileLoggerProvider(builder.Environment.ContentRootPath, fileLoggingSettings));
}

var requestLoggingSettings = RequestLoggingSettings.FromConfiguration(builder.Configuration);
var useProductionAppDatabase = bool.TryParse(builder.Configuration["Persistence:EnableProductionAppDatabase"], out var parsedProdAppDb)
    && parsedProdAppDb;
var enableAspNetIdentity = bool.TryParse(builder.Configuration["Authentication:EnableAspNetIdentity"], out var parsedEnableIdentity) && parsedEnableIdentity;
var enableOidc = bool.TryParse(builder.Configuration["Authentication:EnableOidc"], out var parsedEnableOidc) && parsedEnableOidc;

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
builder.Services.AddSingleton<IChecksumService, Sha256ChecksumService>();
builder.Services.AddSingleton<IJournalFieldEncryptor>(_ =>
    new JournalFieldEncryptor(EncryptionKeyParser.GetKeyBytes(
        builder.Configuration["Security:JournalEncryptionKey"],
        "journal")));
builder.Services.AddSingleton<IAuditFieldEncryptor, PlaintextAuditFieldEncryptor>();
builder.Services.AddSingleton<PrototypeSharedState>();
builder.Services.AddSingleton<PrototypeSessionRegistry>();
builder.Services.AddSingleton(_ => OidcRoleGroupMappings.FromConfiguration(builder.Configuration));
if (useProductionAppDatabase)
{
    builder.Services.AddScoped<IPrototypeDataStore, EfCorePrototypeStore>();
}
else
{
    builder.Services.AddSingleton<SqlitePrototypeStore>();
    builder.Services.AddScoped<IPrototypeDataStore>(sp => sp.GetRequiredService<SqlitePrototypeStore>());
}
builder.Services.AddScoped<ISecureJournalAppService, InMemorySecureJournalAppService>();
builder.Services.AddScoped<PrototypeSessionCookieCoordinator>();
builder.Services.AddProductionIdentityAndDatabaseFoundation(builder.Configuration);

var app = builder.Build();
var oidcRoleMappings = app.Services.GetRequiredService<OidcRoleGroupMappings>();
app.Logger.LogInformation(
    "OIDC role-group mappings configured: GroupClaimType={GroupClaimType}, RolesMapped={RolesMapped}",
    oidcRoleMappings.GroupClaimType,
    oidcRoleMappings.RoleGroups.Count);

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();
app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        var headers = context.Response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["X-Frame-Options"] = "DENY";
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        headers["X-Permitted-Cross-Domain-Policies"] = "none";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers["Cross-Origin-Resource-Policy"] = "same-origin";

        // Blazor Server requires self scripts + websocket connectivity; ImportMap emits inline script content.
        headers["Content-Security-Policy"] =
            "default-src 'self'; " +
            "base-uri 'self'; " +
            "object-src 'none'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self'; " +
            "img-src 'self' data: blob:; " +
            "style-src 'self' 'unsafe-inline'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "connect-src 'self' ws: wss:; " +
            "font-src 'self' data:;";

        if (context.Request.IsHttps && !headers.ContainsKey("Strict-Transport-Security"))
        {
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
        }

        return Task.CompletedTask;
    });

    await next();
});
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value ?? string.Empty;
    var isAssetRequest = HttpMethods.IsGet(context.Request.Method) && (
        path == "/" ||
        path.StartsWith("/_framework/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/js/", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/Components/", StringComparison.OrdinalIgnoreCase));
    var shouldLogPosts = requestLoggingSettings.Mode is RequestLoggingMode.PostsOnly or RequestLoggingMode.Verbose;
    var shouldLogAssetRequest = requestLoggingSettings.Mode == RequestLoggingMode.Verbose && isAssetRequest;

    if (shouldLogPosts && HttpMethods.IsPost(context.Request.Method))
    {
        app.Logger.Log(
            requestLoggingSettings.LogLevel,
            "POST request received: {Path} ContentType={ContentType}",
            context.Request.Path,
            context.Request.ContentType ?? "(none)");
    }
    else if (shouldLogAssetRequest)
    {
        app.Logger.Log(
            requestLoggingSettings.LogLevel,
            "GET request received: {Path}",
            context.Request.Path);
    }

    await next();

    if (shouldLogPosts && HttpMethods.IsPost(context.Request.Method))
    {
        app.Logger.Log(
            requestLoggingSettings.LogLevel,
            "POST request completed: {Path} -> {StatusCode}",
            context.Request.Path,
            context.Response.StatusCode);
    }
    else if (shouldLogAssetRequest)
    {
        app.Logger.Log(
            requestLoggingSettings.LogLevel,
            "GET request completed: {Path} -> {StatusCode} ContentType={ContentType}",
            context.Request.Path,
            context.Response.StatusCode,
            context.Response.ContentType ?? "(none)");
    }
});

app.UseStaticFiles();
app.UseAntiforgery();
app.UseAuthentication();
app.UseAuthorization();

if (enableAspNetIdentity)
{
    app.MapPost("/auth/local-login", async (HttpContext httpContext, IAntiforgery antiforgery, ISecureJournalAppService journalApp, PrototypeSessionCookieCoordinator sessionCookies) =>
    {
        await antiforgery.ValidateRequestAsync(httpContext);

        var form = await httpContext.Request.ReadFormAsync();
        var username = (form["username"].ToString() ?? string.Empty).Trim();
        var password = form["password"].ToString() ?? string.Empty;
        var returnUrl = form["returnUrl"].ToString();
        var failurePath = form["failurePath"].ToString();

        static string SafeRelative(string? path, string fallback)
            => !string.IsNullOrWhiteSpace(path) && Uri.IsWellFormedUriString(path, UriKind.Relative)
                ? path
                : fallback;

        var safeReturnUrl = SafeRelative(returnUrl, "/projects");
        var safeFailurePath = SafeRelative(failurePath, "/");

        try
        {
            var result = await journalApp.TryLocalLoginAsync(username, password, httpContext.RequestAborted);
            if (result.Success)
            {
                await sessionCookies.PersistCurrentLoginAsync();
                return Results.Redirect(safeReturnUrl);
            }

            var encodedError = Uri.EscapeDataString(result.Message ?? "Login failed.");
            return Results.Redirect($"{safeFailurePath}?error={encodedError}");
        }
        catch (Exception ex)
        {
            app.Logger.LogError(ex, "Local login endpoint failed for username {Username}", username);
            var encodedError = Uri.EscapeDataString("Login failed due to a server error.");
            return Results.Redirect($"{safeFailurePath}?error={encodedError}");
        }
    });

    app.MapPost("/auth/logout", async (HttpContext httpContext, IAntiforgery antiforgery) =>
    {
        await antiforgery.ValidateRequestAsync(httpContext);
        var form = await httpContext.Request.ReadFormAsync();
        var returnUrl = form["returnUrl"].ToString();
        await httpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
        var safeReturnUrl = string.IsNullOrWhiteSpace(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative)
            ? "/"
            : returnUrl;
        return Results.Redirect(safeReturnUrl);
    });

    app.MapGet("/auth/oidc-login", (HttpContext httpContext, string? returnUrl) =>
    {
        if (!enableOidc)
        {
            return Results.Redirect("/");
        }

        var safeReturnUrl = string.IsNullOrWhiteSpace(returnUrl) || !Uri.IsWellFormedUriString(returnUrl, UriKind.Relative)
            ? "/projects"
            : returnUrl;

        return Results.Challenge(
            new AuthenticationProperties { RedirectUri = safeReturnUrl },
            authenticationSchemes: new[] { "oidc" });
    });
}

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.InitializeProductionIdentityDatabaseAsync();

app.Run();

public partial class Program { }

internal sealed record ConsoleLoggingSettings(bool Enabled)
{
    public static ConsoleLoggingSettings FromConfiguration(IConfiguration configuration)
    {
        var enabled = !bool.TryParse(configuration["Logging:Console:Enabled"], out var parsedEnabled) || parsedEnabled;
        return new ConsoleLoggingSettings(enabled);
    }
}

internal sealed record SqlQueryLoggingSettings(bool Enabled)
{
    public static SqlQueryLoggingSettings FromConfiguration(IConfiguration configuration)
    {
        var enabled = bool.TryParse(configuration["Logging:SqlQueries:Enabled"], out var parsedEnabled) && parsedEnabled;
        return new SqlQueryLoggingSettings(enabled);
    }
}

internal enum RequestLoggingMode
{
    None,
    PostsOnly,
    Verbose
}

internal sealed record RequestLoggingSettings(RequestLoggingMode Mode, LogLevel LogLevel)
{
    public static RequestLoggingSettings FromConfiguration(IConfiguration configuration)
    {
        var modeText = configuration["Logging:RequestLogging:Mode"];
        var levelText = configuration["Logging:RequestLogging:Level"];

        var mode = Enum.TryParse<RequestLoggingMode>(modeText, ignoreCase: true, out var parsedMode)
            ? parsedMode
            : RequestLoggingMode.PostsOnly;
        var level = Enum.TryParse<LogLevel>(levelText, ignoreCase: true, out var parsedLevel)
            ? parsedLevel
            : LogLevel.Information;

        return new RequestLoggingSettings(mode, level);
    }
}
