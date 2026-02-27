using Microsoft.AspNetCore.Components;
using Markdig;

namespace SecureJournal.Web.Utilities;

public static class SimpleMarkupPreview
{
    private static readonly MarkdownPipeline PreviewPipeline = new MarkdownPipelineBuilder()
        .DisableHtml()
        .Build();

    public static MarkupString Render(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return new MarkupString("<em>No content</em>");
        }

        var normalized = input.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');
        var html = Markdown.ToHtml(normalized, PreviewPipeline);
        return new MarkupString(html);
    }
}
