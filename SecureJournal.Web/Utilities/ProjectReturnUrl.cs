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
        { "projectId", "q", "browse", "projectPage", "projectSize", "entryQuery", "page", "size", "sort", "deleted" };
        var values = QueryHelpers.ParseQuery(uri.Query)
            .Where(pair => allowed.Contains(pair.Key))
            .ToDictionary(pair => pair.Key, pair => (string?)pair.Value.ToString());
        return QueryHelpers.AddQueryString("/projects", values);
    }
}
