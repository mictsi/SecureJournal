using System.Security.Claims;
using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

internal static class OidcPrincipalHelpers
{
    public static string? GetNormalizedPrincipalUsername(ClaimsPrincipal principal)
    {
        var isOidcPrincipal = LooksLikeOidcPrincipal(principal);
        var raw = isOidcPrincipal
            ? principal.FindFirstValue("preferred_username")
              ?? principal.FindFirstValue(ClaimTypes.Upn)
              ?? principal.FindFirstValue(ClaimTypes.Email)
              ?? principal.FindFirstValue("email")
              ?? principal.Identity?.Name
              ?? principal.FindFirstValue(ClaimTypes.Name)
            : principal.Identity?.Name
              ?? principal.FindFirstValue(ClaimTypes.Name)
              ?? principal.FindFirstValue("preferred_username")
              ?? principal.FindFirstValue(ClaimTypes.Upn)
              ?? principal.FindFirstValue(ClaimTypes.Email)
              ?? principal.FindFirstValue("email");

        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return raw.Trim().ToLowerInvariant();
    }

    public static string GetDisplayNameFromPrincipal(ClaimsPrincipal principal, string fallbackUsername)
        => (principal.FindFirstValue("name")
            ?? principal.FindFirstValue(ClaimTypes.Name)
            ?? fallbackUsername).Trim();

    public static AppRole GetRoleFromPrincipal(ClaimsPrincipal principal, AppRole? fallbackRole)
    {
        if (principal.IsInRole(nameof(AppRole.Administrator)))
        {
            return AppRole.Administrator;
        }

        if (principal.IsInRole(nameof(AppRole.Auditor)))
        {
            return AppRole.Auditor;
        }

        if (principal.IsInRole(nameof(AppRole.ProjectUser)))
        {
            return AppRole.ProjectUser;
        }

        return fallbackRole ?? AppRole.ProjectUser;
    }

    public static bool TryGetExplicitRoleFromPrincipal(ClaimsPrincipal principal, out AppRole role)
    {
        if (principal.IsInRole(nameof(AppRole.Administrator)))
        {
            role = AppRole.Administrator;
            return true;
        }

        if (principal.IsInRole(nameof(AppRole.Auditor)))
        {
            role = AppRole.Auditor;
            return true;
        }

        if (principal.IsInRole(nameof(AppRole.ProjectUser)))
        {
            role = AppRole.ProjectUser;
            return true;
        }

        role = default;
        return false;
    }

    public static bool LooksLikeOidcPrincipal(ClaimsPrincipal principal)
    {
        var hasSub = principal.HasClaim(c => string.Equals(c.Type, "sub", StringComparison.OrdinalIgnoreCase));
        var hasIss = principal.HasClaim(c => string.Equals(c.Type, "iss", StringComparison.OrdinalIgnoreCase));
        var hasOid = principal.HasClaim(c =>
            string.Equals(c.Type, "oid", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(c.Type, "http://schemas.microsoft.com/identity/claims/objectidentifier", StringComparison.OrdinalIgnoreCase));
        var hasTid = principal.HasClaim(c =>
            string.Equals(c.Type, "tid", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(c.Type, "http://schemas.microsoft.com/identity/claims/tenantid", StringComparison.OrdinalIgnoreCase));

        return hasSub || hasIss || (hasOid && hasTid);
    }

    public static bool TryGetOidcIdentityKey(ClaimsPrincipal principal, out string issuer, out string subject)
    {
        subject = GetFirstClaimValue(
            principal,
            "sub",
            "oid",
            "http://schemas.microsoft.com/identity/claims/objectidentifier",
            ClaimTypes.NameIdentifier);
        issuer = GetFirstClaimValue(
            principal,
            "iss");

        if (string.IsNullOrWhiteSpace(issuer))
        {
            var subjectClaim = principal.Claims.FirstOrDefault(c =>
                string.Equals(c.Type, "sub", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(c.Type, "oid", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(c.Type, "http://schemas.microsoft.com/identity/claims/objectidentifier", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(c.Type, ClaimTypes.NameIdentifier, StringComparison.Ordinal));
            var subjectClaimIssuer = subjectClaim?.Issuer?.Trim();
            if (!string.IsNullOrWhiteSpace(subjectClaimIssuer) && !IsLocalIssuer(subjectClaimIssuer))
            {
                issuer = subjectClaimIssuer;
            }
        }

        if (string.IsNullOrWhiteSpace(issuer))
        {
            var tenantId = GetFirstClaimValue(
                principal,
                "tid",
                "http://schemas.microsoft.com/identity/claims/tenantid");
            if (!string.IsNullOrWhiteSpace(tenantId))
            {
                issuer = $"https://login.microsoftonline.com/{tenantId}/v2.0";
            }
        }

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        {
            issuer = string.Empty;
            subject = string.Empty;
            return false;
        }

        return true;
    }

    public static string GetFirstClaimValue(ClaimsPrincipal principal, params string[] claimTypes)
    {
        foreach (var claimType in claimTypes)
        {
            var value = principal.FindFirstValue(claimType);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }
        }

        return string.Empty;
    }

    public static bool IsLocalIssuer(string issuer)
        => string.Equals(issuer, "LOCAL AUTHORITY", StringComparison.OrdinalIgnoreCase);

    public static string FormatPrincipalClaimsForDiagnostics(ClaimsPrincipal principal)
    {
        var claims = principal.Claims
            .Select(c => $"{c.Type}={FormatClaimValueForDiagnostics(c.Type, c.Value)}")
            .ToArray();

        return claims.Length == 0 ? "(none)" : string.Join("; ", claims);
    }

    private static string FormatClaimValueForDiagnostics(string claimType, string? rawValue)
    {
        var value = rawValue ?? string.Empty;
        if (IsSensitiveClaimType(claimType))
        {
            return $"<redacted:{value.Length} chars>";
        }

        var singleLineValue = value.Replace("\r", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Trim();

        const int maxLength = 256;
        return singleLineValue.Length <= maxLength
            ? singleLineValue
            : $"{singleLineValue[..maxLength]}...({singleLineValue.Length} chars)";
    }

    private static bool IsSensitiveClaimType(string claimType)
    {
        var normalized = claimType.ToLowerInvariant();
        return normalized.Contains("token", StringComparison.Ordinal) ||
               normalized.Contains("secret", StringComparison.Ordinal) ||
               normalized.Contains("assertion", StringComparison.Ordinal) ||
               normalized.Contains("password", StringComparison.Ordinal) ||
               normalized.Contains("nonce", StringComparison.Ordinal);
    }
}
