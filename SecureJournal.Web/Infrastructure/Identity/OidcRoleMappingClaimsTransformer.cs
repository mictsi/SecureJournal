using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using SecureJournal.Core.Domain;
using SecureJournal.Web.Services;

namespace SecureJournal.Web.Infrastructure.Identity;

public sealed class OidcRoleMappingClaimsTransformer : IClaimsTransformation
{
    private readonly OidcRoleGroupMappings _mappings;
    private readonly ILogger<OidcRoleMappingClaimsTransformer> _logger;

    public OidcRoleMappingClaimsTransformer(
        OidcRoleGroupMappings mappings,
        ILogger<OidcRoleMappingClaimsTransformer> logger)
    {
        _mappings = mappings;
        _logger = logger;
    }

    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity is not ClaimsIdentity identity || !identity.IsAuthenticated)
        {
            return Task.FromResult(principal);
        }

        var groupValues = principal.Claims
            .Where(c => string.Equals(c.Type, _mappings.GroupClaimType, StringComparison.OrdinalIgnoreCase))
            .Select(c => c.Value)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (groupValues.Count == 0 || _mappings.RoleGroups.Count == 0)
        {
            return Task.FromResult(principal);
        }

        foreach (var pair in _mappings.RoleGroups)
        {
            var appRole = pair.Key.ToString();
            if (identity.Claims.Any(c => c.Type == ClaimTypes.Role && string.Equals(c.Value, appRole, StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            if (pair.Value.Any(groupValues.Contains))
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, appRole));
                _logger.LogDebug("OIDC group mapping granted role {Role} to subject {Subject}", appRole, principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? "(unknown)");
            }
        }

        return Task.FromResult(principal);
    }
}
