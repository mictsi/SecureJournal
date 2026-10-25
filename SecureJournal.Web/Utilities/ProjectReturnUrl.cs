using Microsoft.AspNetCore.WebUtilities;

namespace SecureJournal.Web.Utilities;

internal static class ProjectReturnUrl
{
    // Only carry the project's own list state, never an arbitrary return target.
    public static string Resolve(string? candidate, string fallback)
    {
        if (string.IsNullOrEmpty(candidate) || candidate.Any(char.IsControl)
            || !candidate.StartsWith("/projects?", StringComparison.Ordinal)
            || !Uri.TryCreate("https://local.invalid" + candidate, UriKind.Absolute, out var uri)
            || uri.AbsolutePath != "/projects" || !string.IsNullOrEmpty(uri.Fragment)) return fallback;

        var allowed = new HashSet<string>(StringComparer.Ordinal)
        { "projectId", "q", "browse", "favorites", "projectPage", "projectSize", "entryQuery", "page", "size", "sort", "deleted", "view", "entryId" };
        var values = QueryHelpers.ParseQuery(uri.Query)
            .Where(pair => allowed.Contains(pair.Key))
            .ToDictionary(pair => pair.Key, pair => (string?)pair.Value.ToString());
        return QueryHelpers.AddQueryString("/projects", values);
    }

    public static string NewEntryUrl(Uri currentPage)
    {
        if (currentPage.AbsolutePath != "/projects" && currentPage.AbsolutePath != "/journal"
            && !currentPage.AbsolutePath.StartsWith("/projects/entry/", StringComparison.Ordinal)) return "/journal";
        var query = QueryHelpers.ParseQuery(currentPage.Query);
        if (!query.TryGetValue("projectId", out var projectValue) || !Guid.TryParse(projectValue.ToString(), out var projectId)) return "/journal";
        var returnCandidate = currentPage.AbsolutePath == "/projects" ? currentPage.PathAndQuery
            : query.TryGetValue("returnUrl", out var returnValue) ? returnValue.ToString() : null;
        return QueryHelpers.AddQueryString("/journal", new Dictionary<string, string?>
        {
            ["projectId"] = projectId.ToString("D"),
            ["returnUrl"] = Resolve(returnCandidate, $"/projects?projectId={projectId:D}")
        });
    }
}
