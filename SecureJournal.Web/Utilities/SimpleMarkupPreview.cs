using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
using Ganss.Xss;
using Microsoft.AspNetCore.Components;
using Markdig;

namespace SecureJournal.Web.Utilities;

public static partial class SimpleMarkupPreview
{
    private static readonly MarkdownPipeline PreviewPipeline = new MarkdownPipelineBuilder()
        .DisableHtml()
        .Build();
    private static readonly HtmlSanitizer HtmlSanitizer = BuildHtmlSanitizer();

    public static MarkupString Render(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return new MarkupString("<em>No content</em>");
        }

        var normalized = input.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');

        if (HtmlTagPattern().IsMatch(normalized))
        {
            var sanitized = HtmlSanitizer.Sanitize(normalized);
            return new MarkupString(string.IsNullOrWhiteSpace(sanitized) ? "<em>No content</em>" : sanitized);
        }

        var html = Markdown.ToHtml(normalized, PreviewPipeline);
        return new MarkupString(html);
    }

    [GeneratedRegex(@"<\s*/?\s*[a-zA-Z][^>]*>", RegexOptions.Compiled)]
    private static partial Regex HtmlTagPattern();

    private static HtmlSanitizer BuildHtmlSanitizer()
    {
        var sanitizer = new HtmlSanitizer
        {
            KeepChildNodes = true
        };

        sanitizer.AllowedTags.Clear();
        sanitizer.AllowedAttributes.Clear();
        sanitizer.AllowedCssProperties.Clear();
        sanitizer.AllowedSchemes.Clear();
        sanitizer.UriAttributes.Clear();

        AllowRange(sanitizer.AllowedTags, "a", "blockquote", "br", "code", "em", "h2", "h3", "h4", "li", "ol", "p", "pre", "strong", "u", "s", "ul");
        AllowRange(sanitizer.AllowedAttributes, "href", "rel", "target");
        AllowRange(sanitizer.UriAttributes, "href");
        AllowRange(sanitizer.AllowedSchemes, "http", "https", "mailto");

        sanitizer.RemovingAttribute += (_, args) =>
        {
            if (args.Attribute.Name.Equals("target", StringComparison.OrdinalIgnoreCase))
            {
                args.Cancel = args.Attribute.Value is "_blank" or "_self";
            }
        };

        return sanitizer;
    }

    private static void AllowRange<T>(ICollection<T> target, params T[] values)
    {
        foreach (var value in values)
        {
            target.Add(value);
        }
    }
}
