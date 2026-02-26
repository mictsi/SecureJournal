using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public sealed record OidcRoleGroupMappings(
    string GroupClaimType,
    IReadOnlyDictionary<AppRole, IReadOnlyList<string>> RoleGroups)
{
    public static OidcRoleGroupMappings FromConfiguration(IConfiguration configuration)
    {
        var section = configuration.GetSection("Authentication:Oidc");
        var groupClaimType = (section["GroupClaimType"] ?? "groups").Trim();
        if (string.IsNullOrWhiteSpace(groupClaimType))
        {
            groupClaimType = "groups";
        }

        var roleMappingsSection = section.GetSection("RoleGroupMappings");
        var mappings = new Dictionary<AppRole, IReadOnlyList<string>>();

        foreach (var role in Enum.GetValues<AppRole>())
        {
            var roleSection = roleMappingsSection.GetSection(role.ToString());
            if (!roleSection.Exists())
            {
                continue;
            }

            var groups = roleSection
                .Get<string[]>()?
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Select(v => v.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList()
                ?? new List<string>();

            if (groups.Count > 0)
            {
                mappings[role] = groups;
            }
        }

        return new OidcRoleGroupMappings(groupClaimType, mappings);
    }
}
