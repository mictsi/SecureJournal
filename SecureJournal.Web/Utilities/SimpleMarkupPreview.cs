using System.Collections.ObjectModel;
using System.Text.RegularExpressions;
using AngleSharp.Dom;
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

        // Tables. The editor can produce them, so the allow-list has to admit the
        // structural elements or the content is silently flattened on display.
        // Presentational attributes (style, width, border, bgcolor) are deliberately
        // not allowed: layout comes from the stylesheet, not from author markup.
        AllowRange(sanitizer.AllowedTags, "table", "caption", "colgroup", "col", "thead", "tbody", "tfoot", "tr", "th", "td");

        AllowRange(sanitizer.AllowedAttributes, "href", "rel", "target");

        // colspan/rowspan carry meaning that cannot be expressed any other way, and
        // scope is what binds a header to its row or column for screen readers.
        AllowRange(sanitizer.AllowedAttributes, "colspan", "rowspan", "scope", "headers", "abbr", "span");
        AllowRange(sanitizer.UriAttributes, "href");
        AllowRange(sanitizer.AllowedSchemes, "http", "https", "mailto");

        // A table wider than its column forces the page to scroll sideways. The
        // design system's answer is a per-table scroll region, and the tabindex is
        // required rather than decorative: without it a keyboard user cannot scroll
        // the container at all (WCAG 2.1.1). The wrapper is added after sanitising,
        // so it is never author-controlled.
        sanitizer.PostProcessDom += (_, args) =>
        {
            var document = args.Document;

            foreach (var table in document.QuerySelectorAll("table").ToList())
            {
                if (table.ParentElement?.ClassList.Contains("sk-table") == true)
                {
                    continue;
                }

                var wrapper = document.CreateElement("div");
                wrapper.ClassList.Add("sk-table");
                wrapper.SetAttribute("role", "region");
                wrapper.SetAttribute("tabindex", "0");

                var caption = table.QuerySelector("caption")?.TextContent?.Trim();
                wrapper.SetAttribute("aria-label", string.IsNullOrWhiteSpace(caption) ? "Table" : caption);

                table.Parent?.InsertBefore(wrapper, table);
                wrapper.AppendChild(table);
            }
        };

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
