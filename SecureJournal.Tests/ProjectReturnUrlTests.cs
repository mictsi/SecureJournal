using Microsoft.AspNetCore.WebUtilities;
using SecureJournal.Web.Utilities;
using Xunit;

namespace SecureJournal.Tests;

public sealed class ProjectReturnUrlTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("https://example.com/projects?q=secret")]
    [InlineData("//example.com/projects?q=secret")]
    [InlineData("/admin/users?browse=true")]
    [InlineData("/projects/../admin?browse=true")]
    [InlineData("/projects?browse=true#other")]
    [InlineData("/projects?q=hello\nworld")]
    public void Resolve_RejectsNonProjectAndMalformedTargets(string? target)
    {
        Assert.Equal("/projects?projectId=fallback", ProjectReturnUrl.Resolve(target, "/projects?projectId=fallback"));
    }

    [Fact]
    public void Resolve_PreservesProjectFiltersAndPagingWithoutForwardingUnrelatedParameters()
    {
        var id = Guid.NewGuid();
        var target = QueryHelpers.AddQueryString("/projects", new Dictionary<string, string?>
        {
            ["projectId"] = id.ToString(), ["q"] = "Möten & planering", ["entryQuery"] = "handover",
            ["page"] = "3", ["size"] = "20", ["sort"] = "oldest", ["deleted"] = "true", ["view"] = "quick",
            ["access_token"] = "must-not-propagate", ["returnUrl"] = "https://example.com"
        });

        var result = ProjectReturnUrl.Resolve(target, "/projects");
        var values = QueryHelpers.ParseQuery(new Uri("https://local.invalid" + result).Query);

        Assert.Equal(id.ToString(), values["projectId"].ToString());
        Assert.Equal("Möten & planering", values["q"].ToString());
        Assert.Equal("handover", values["entryQuery"].ToString());
        Assert.Equal("3", values["page"].ToString());
        Assert.Equal("20", values["size"].ToString());
        Assert.Equal("oldest", values["sort"].ToString());
        Assert.Equal("true", values["deleted"].ToString());
        Assert.Equal("quick", values["view"].ToString());
        Assert.False(values.ContainsKey("access_token"));
        Assert.False(values.ContainsKey("returnUrl"));
    }

    [Fact]
    public void NewEntryUrl_PreservesCurrentJournalAndQuickReadContext()
    {
        var id = Guid.NewGuid();
        var current = new Uri($"https://local.invalid/projects?projectId={id:D}&view=quick&page=2");
        var result = ProjectReturnUrl.NewEntryUrl(current);
        var query = QueryHelpers.ParseQuery(new Uri("https://local.invalid" + result).Query);
        Assert.Equal(id.ToString("D"), query["projectId"].ToString());
        Assert.Equal(current.PathAndQuery, query["returnUrl"].ToString());
        var details = new Uri("https://local.invalid" + QueryHelpers.AddQueryString($"/projects/entry/{Guid.NewGuid():D}",
            new Dictionary<string, string?> { ["projectId"] = id.ToString("D"), ["returnUrl"] = current.PathAndQuery }));
        Assert.Equal(result, ProjectReturnUrl.NewEntryUrl(details));
    }

    [Theory]
    [InlineData("/audit?projectId=00000000-0000-0000-0000-000000000001")]
    [InlineData("/projects?projectId=invalid")]
    [InlineData("/projects?browse=true")]
    public void NewEntryUrl_OnlyCarriesValidJournalContext(string path)
        => Assert.Equal("/journal", ProjectReturnUrl.NewEntryUrl(new Uri("https://local.invalid" + path)));
}
