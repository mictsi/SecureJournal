using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Components;

namespace SecureJournal.Web.Utilities;

public static partial class SimpleMarkupPreview
{
    public static MarkupString Render(string? input)
    {
        var encoded = WebUtility.HtmlEncode(input ?? string.Empty);
        if (string.IsNullOrWhiteSpace(encoded))
        {
            return new MarkupString("<em>No content</em>");
        }

        var html = encoded;
        html = BoldRegex().Replace(html, "<strong>$1</strong>");
        html = ItalicRegex().Replace(html, "<em>$1</em>");
        html = CodeRegex().Replace(html, "<code>$1</code>");
        html = HeadingRegex().Replace(html, "<strong>$1</strong>");
        html = html.Replace("\r\n", "\n", StringComparison.Ordinal)
                   .Replace("\r", "\n", StringComparison.Ordinal);
        html = string.Join("<br />", html.Split('\n'));

        return new MarkupString(html);
    }

    [GeneratedRegex(@"\*\*(.+?)\*\*", RegexOptions.Singleline)]
    private static partial Regex BoldRegex();

    [GeneratedRegex(@"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", RegexOptions.Singleline)]
    private static partial Regex ItalicRegex();

    [GeneratedRegex(@"`(.+?)`", RegexOptions.Singleline)]
    private static partial Regex CodeRegex();

    [GeneratedRegex(@"(?m)^#\s+(.+)$")]
    private static partial Regex HeadingRegex();
}
