using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.Configuration;
using SecureJournal.Core.Domain;
using SecureJournal.Web.Services;
using SecureJournal.Web.Utilities;
using Xunit;

namespace SecureJournal.Tests;

public sealed class SimpleMarkupPreviewTests
{
    [Fact]
    public void Render_ReturnsPlaceholderForBlankInput()
    {
        var result = SimpleMarkupPreview.Render("  ");

        Assert.Equal("<em>No content</em>", result.Value);
    }

    [Fact]
    public void Render_KeepsTableStructureAuthoredInTheEditor()
    {
        var html = "<table><caption>Sample readings</caption><thead><tr>" +
                   "<th scope=\"col\">Station</th><th scope=\"col\">Depth</th></tr></thead>" +
                   "<tbody><tr><td>BS-114</td><td colspan=\"2\">42 m</td></tr></tbody></table>";

        var result = SimpleMarkupPreview.Render(html).Value;

        Assert.Contains("<table>", result, StringComparison.Ordinal);
        Assert.Contains("<caption>Sample readings</caption>", result, StringComparison.Ordinal);
        Assert.Contains("scope=\"col\"", result, StringComparison.Ordinal);
        Assert.Contains("colspan=\"2\"", result, StringComparison.Ordinal);
        Assert.Contains("<td>BS-114</td>", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_WrapsTablesInAKeyboardReachableScrollRegion()
    {
        var result = SimpleMarkupPreview.Render("<table><tr><td>one</td></tr></table>").Value;

        // Without tabindex the container cannot be scrolled by keyboard at all.
        Assert.Contains("class=\"sk-table\"", result, StringComparison.Ordinal);
        Assert.Contains("role=\"region\"", result, StringComparison.Ordinal);
        Assert.Contains("tabindex=\"0\"", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_NamesTheScrollRegionAfterTheCaptionWhenThereIsOne()
    {
        var withCaption = SimpleMarkupPreview.Render(
            "<table><caption>Depth readings</caption><tr><td>1</td></tr></table>").Value;
        var withoutCaption = SimpleMarkupPreview.Render("<table><tr><td>1</td></tr></table>").Value;

        Assert.Contains("aria-label=\"Depth readings\"", withCaption, StringComparison.Ordinal);
        Assert.Contains("aria-label=\"Table\"", withoutCaption, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_StripsPresentationalAndDangerousTableAttributes()
    {
        var html = "<table style=\"width:900px\" border=\"1\" bgcolor=\"red\" onclick=\"alert(1)\">" +
                   "<tr><td onmouseover=\"alert(2)\" style=\"color:red\">cell</td></tr></table>";

        var result = SimpleMarkupPreview.Render(html).Value;

        Assert.Contains("<td>cell</td>", result, StringComparison.Ordinal);
        Assert.DoesNotContain("style=", result, StringComparison.Ordinal);
        Assert.DoesNotContain("bgcolor", result, StringComparison.Ordinal);
        Assert.DoesNotContain("onclick", result, StringComparison.Ordinal);
        Assert.DoesNotContain("onmouseover", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_StillRejectsScriptInsideATable()
    {
        var result = SimpleMarkupPreview.Render(
            "<table><tr><td><script>alert(1)</script>safe</td></tr></table>").Value;

        // The sanitizer runs with KeepChildNodes, so a disallowed element is
        // unwrapped rather than deleted: the <script> element goes and its former
        // contents remain as inert text. Nothing executes, which is the property
        // that matters here.
        Assert.DoesNotContain("<script", result, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("safe", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_RejectsEventHandlersAndJavascriptUrisInTableContent()
    {
        var result = SimpleMarkupPreview.Render(
            "<table><tr><td><a href=\"javascript:alert(1)\" onclick=\"alert(2)\">link</a></td></tr></table>").Value;

        Assert.DoesNotContain("javascript:", result, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("onclick", result, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("link", result, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_RendersMarkdownAndNormalizesLineEndings()
    {
        var result = SimpleMarkupPreview.Render("**Bold**\r\n\r\nNext line");

        Assert.Contains("<strong>Bold</strong>", result.Value, StringComparison.Ordinal);
        Assert.Contains("<p>Next line</p>", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain('\r', result.Value);
    }
}

public sealed class PrototypeSessionCookieSettingsTests
{
    [Fact]
    public void FromConfiguration_UsesDefaultsWhenValuesAreMissing()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection()
            .Build();

        var settings = PrototypeSessionCookieSettings.FromConfiguration(configuration);

        Assert.Equal("SecureJournal.Session", settings.CookieName);
        Assert.Equal(8, settings.SessionCookieHours);
        Assert.False(settings.EnableJavaScriptFallback);
        Assert.Equal(120, settings.JavaScriptFallbackMaxAgeSeconds);
        Assert.Equal(TimeSpan.FromHours(8), settings.Lifetime);
    }

    [Fact]
    public void FromConfiguration_TrimsAndClampsConfiguredValues()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Security:SessionCookieName"] = "  Custom.Session  ",
                ["Security:SessionCookieHours"] = "0",
                ["Security:EnableJsSessionCookieFallback"] = "true",
                ["Security:JsSessionCookieFallbackMaxAgeSeconds"] = "5000"
            })
            .Build();

        var settings = PrototypeSessionCookieSettings.FromConfiguration(configuration);

        Assert.Equal("Custom.Session", settings.CookieName);
        Assert.Equal(1, settings.SessionCookieHours);
        Assert.True(settings.EnableJavaScriptFallback);
        Assert.Equal(900, settings.JavaScriptFallbackMaxAgeSeconds);
    }
}

public sealed class PrototypeSessionRegistryTests
{
    [Fact]
    public void TryGetUserId_ReturnsFalseAndRemovesExpiredSession()
    {
        var registry = new PrototypeSessionRegistry();
        var userId = Guid.NewGuid();
        var token = registry.CreateSession(userId, TimeSpan.FromSeconds(-1));

        var found = registry.TryGetUserId(token, out var resolvedUserId);
        var foundAfterCleanup = registry.TryGetUserId(token, out _);

        Assert.False(found);
        Assert.Equal(Guid.Empty, resolvedUserId);
        Assert.False(foundAfterCleanup);
    }

    [Fact]
    public void Remove_ReturnsExpectedResultForBlankAndExistingTokens()
    {
        var registry = new PrototypeSessionRegistry();
        var token = registry.CreateSession(Guid.NewGuid(), TimeSpan.FromMinutes(5));

        Assert.False(registry.Remove(" "));
        Assert.True(registry.Remove(token));
        Assert.False(registry.Remove(token));
    }
}

public sealed class OidcRoleGroupMappingsTests
{
    [Fact]
    public void FromConfiguration_UsesDefaultGroupClaimTypeAndDeduplicatesGroups()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authentication:Oidc:GroupClaimType"] = "   ",
                ["Authentication:Oidc:RoleGroupMappings:Administrator:0"] = " admins ",
                ["Authentication:Oidc:RoleGroupMappings:Administrator:1"] = "ADMINS",
                ["Authentication:Oidc:RoleGroupMappings:Administrator:2"] = "",
                ["Authentication:Oidc:RoleGroupMappings:Administrator:3"] = "auditors"
            })
            .Build();

        var mappings = OidcRoleGroupMappings.FromConfiguration(configuration);

        Assert.Equal("groups", mappings.GroupClaimType);
        Assert.True(mappings.RoleGroups.ContainsKey(AppRole.Administrator));
        Assert.Equal(["admins", "auditors"], mappings.RoleGroups[AppRole.Administrator]);
        Assert.False(mappings.RoleGroups.ContainsKey(AppRole.Auditor));
    }
}
