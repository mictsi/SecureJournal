using System.Reflection;
using Microsoft.AspNetCore.Components;
using SecureJournal.Core.Application;
using SecureJournal.Web.Components.Pages;
using Xunit;

namespace SecureJournal.Tests;

public sealed class JournalProjectContextTests
{
    private const BindingFlags PrivateInstance = BindingFlags.Instance | BindingFlags.NonPublic;

    [Fact]
    public async Task Save_UsesOpenedJournalInsteadOfPostedProject()
    {
        var opened = Guid.NewGuid();
        var other = Guid.NewGuid();
        var fixture = Create(opened.ToString(), other, opened, other);
        await SaveAsync(fixture.Page);
        Assert.Equal(opened, fixture.Service.SavedProject);
        Assert.Contains($"projectId={opened:D}", fixture.Navigation.LastUrl);
    }

    [Theory]
    [InlineData("invalid-project")]
    [InlineData("00000000-0000-0000-0000-000000000001")]
    public async Task Save_UnavailableContextCannotFallBackToAnotherPostedProject(string invalidContext)
    {
        var accessible = Guid.NewGuid();
        var fixture = Create(invalidContext, accessible, accessible);
        await SaveAsync(fixture.Page);
        Assert.Null(fixture.Service.SavedProject);
        Assert.Null(fixture.Navigation.LastUrl);
    }

    [Fact]
    public async Task Save_StandaloneComposerUsesExplicitProjectChoice()
    {
        var chosen = Guid.NewGuid();
        var fixture = Create(null, chosen, chosen);
        await SaveAsync(fixture.Page);
        Assert.Equal(chosen, fixture.Service.SavedProject);
    }

    private static (Journal Page, JournalServiceProxy Service, RecordingNavigation Navigation) Create(string? context, Guid posted, params Guid[] projects)
    {
        var page = new Journal { ProjectIdQuery = context };
        var service = DispatchProxy.Create<ISecureJournalAppService, JournalServiceProxy>();
        var navigation = new RecordingNavigation();
        typeof(Journal).GetProperty("JournalApp", PrivateInstance)!.SetValue(page, service);
        typeof(Journal).GetProperty("Navigation", PrivateInstance)!.SetValue(page, navigation);
        typeof(Journal).GetProperty("PostedDraftModel", PrivateInstance)!.SetValue(page,
            new CreateJournalEntryRequest { ProjectId = posted, Subject = "A record", Description = "Evidence" });
        typeof(Journal).GetField("_projects", PrivateInstance)!.SetValue(page,
            projects.Select(id => new ProjectOverview(id, "PRJ001", "Project", "", "", "", "", "", Array.Empty<string>(), true)).ToList());
        return (page, (JournalServiceProxy)(object)service, navigation);
    }

    private static Task SaveAsync(Journal page)
        => (Task)typeof(Journal).GetMethod("CreateEntryAsync", PrivateInstance)!.Invoke(page, null)!;

    public class JournalServiceProxy : DispatchProxy
    {
        public Guid? SavedProject { get; private set; }
        protected override object? Invoke(MethodInfo? method, object?[]? args)
        {
            if (method?.Name != nameof(ISecureJournalAppService.CreateJournalEntry))
                throw new InvalidOperationException($"Unexpected service method {method?.Name}.");
            var request = (CreateJournalEntryRequest)args![0]!;
            SavedProject = request.ProjectId;
            return new JournalEntryView(Guid.NewGuid(), request.ProjectId, "PRJ001", "Project", DateTime.UtcNow,
                "writer", request.Subject, request.Description, "", false, null, null, null, "checksum");
        }
    }

    public sealed class RecordingNavigation : NavigationManager
    {
        public string? LastUrl { get; private set; }
        public RecordingNavigation() => Initialize("https://local.invalid/", "https://local.invalid/journal");
        protected override void NavigateToCore(string uri, bool forceLoad) => LastUrl = uri;
        protected override void NavigateToCore(string uri, NavigationOptions options) => LastUrl = uri;
    }
}
