using Microsoft.AspNetCore.Identity;

namespace SecureJournal.Web.Infrastructure.Identity;

public sealed class ProductionIdentityBootstrapSeeder
{
    private readonly IServiceProvider _services;
    private readonly IConfiguration _configuration;
    private readonly IHostEnvironment _hostEnvironment;
    private readonly ILogger<ProductionIdentityBootstrapSeeder> _logger;

    public ProductionIdentityBootstrapSeeder(
        IServiceProvider services,
        IConfiguration configuration,
        IHostEnvironment hostEnvironment,
        ILogger<ProductionIdentityBootstrapSeeder> logger)
    {
        _services = services;
        _configuration = configuration;
        _hostEnvironment = hostEnvironment;
        _logger = logger;
    }

    public async Task SeedAsync(CancellationToken cancellationToken = default)
    {
        using var scope = _services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<SecureJournalIdentityUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

        foreach (var roleName in new[] { "Administrator", "ProjectUser", "Auditor" })
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                var createRole = await roleManager.CreateAsync(new IdentityRole(roleName));
                if (!createRole.Succeeded)
                {
                    var error = string.Join("; ", createRole.Errors.Select(e => e.Description));
                    throw new InvalidOperationException($"Failed creating Identity role '{roleName}': {error}");
                }
            }
        }

        var bootstrapUsername = (_configuration["BootstrapAdmin:Username"] ?? "admin").Trim();
        var bootstrapDisplayName = (_configuration["BootstrapAdmin:DisplayName"] ?? "Startup Administrator").Trim();
        var bootstrapPassword = _configuration["BootstrapAdmin:Password"]?.Trim();

        if (string.IsNullOrWhiteSpace(bootstrapUsername))
        {
            bootstrapUsername = "admin";
        }

        if (string.IsNullOrWhiteSpace(bootstrapPassword))
        {
            if (_hostEnvironment.IsProduction())
            {
                throw new InvalidOperationException("BootstrapAdmin:Password is required in Production and cannot be empty.");
            }

            bootstrapPassword = "ChangeMe123!";
        }

        if (_hostEnvironment.IsProduction() &&
            (string.Equals(bootstrapPassword, "ChangeMe123!", StringComparison.Ordinal) ||
             bootstrapPassword.Contains("<bootstrap-admin", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException(
                "BootstrapAdmin:Password uses a default/placeholder value. Set a strong production password.");
        }

        var normalizedUsername = bootstrapUsername.ToLowerInvariant();
        var user = await userManager.FindByNameAsync(normalizedUsername);
        if (user is null)
        {
            user = new SecureJournalIdentityUser
            {
                UserName = normalizedUsername,
                Email = $"{normalizedUsername}@local.invalid",
                EmailConfirmed = true,
                DisplayName = string.IsNullOrWhiteSpace(bootstrapDisplayName) ? normalizedUsername : bootstrapDisplayName,
                IsBootstrapAdmin = true
            };

            var createUser = await userManager.CreateAsync(user, bootstrapPassword);
            if (!createUser.Succeeded)
            {
                var error = string.Join("; ", createUser.Errors.Select(e => e.Description));
                throw new InvalidOperationException($"Failed creating bootstrap Identity admin '{normalizedUsername}': {error}");
            }

            _logger.LogInformation("Identity bootstrap admin created: {Username}", normalizedUsername);
        }
        else
        {
            user.DisplayName = string.IsNullOrWhiteSpace(bootstrapDisplayName) ? user.DisplayName : bootstrapDisplayName;
            user.IsBootstrapAdmin = true;
            await userManager.UpdateAsync(user);
        }

        if (!await userManager.IsInRoleAsync(user, "Administrator"))
        {
            var roleAdd = await userManager.AddToRoleAsync(user, "Administrator");
            if (!roleAdd.Succeeded)
            {
                var error = string.Join("; ", roleAdd.Errors.Select(e => e.Description));
                throw new InvalidOperationException($"Failed assigning Administrator role to bootstrap user '{normalizedUsername}': {error}");
            }
        }
    }
}
