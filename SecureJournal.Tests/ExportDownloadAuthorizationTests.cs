using System.Reflection;
using Microsoft.JSInterop;
using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;
using SecureJournal.Web.Components.Pages;
using Xunit;

namespace SecureJournal.Tests;

public sealed class ExportDownloadAuthorizationTests
{
    [Theory]
    [InlineData("JournalEntries", AppRole.Administrator, true)]
    [InlineData("JournalEntries", AppRole.Auditor, false)]
    [InlineData("JournalEntries", AppRole.ProjectUser, false)]
    [InlineData("AuditLogs", AppRole.Administrator, true)]
    [InlineData("AuditLogs", AppRole.Auditor, true)]
    [InlineData("AuditLogs", AppRole.ProjectUser, false)]
    public async Task CachedDownload_RequiresCurrentPermissionForItsOriginalDataset(string dataset, AppRole currentRole, bool allowed)
    {
        using var fixture = new ExportFixture(dataset, currentRole);
        if (allowed)
        {
            await fixture.DownloadAsync();
            Assert.Single(fixture.JavaScript.Calls);
            Assert.Equal("secureJournalDownloads.downloadStream", fixture.JavaScript.Calls[0]);
        }
        else
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(fixture.DownloadAsync);
            Assert.Empty(fixture.JavaScript.Calls);
            fixture.AssertCacheCleared();
        }
        Assert.Equal(1, fixture.Service.UserLookups);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PreviousDownload_CannotBeRepeatedAfterSessionOrRoleRevocation(bool revokeSession)
    {
        using var fixture = new ExportFixture("JournalEntries", AppRole.Administrator);
        await fixture.DownloadAsync();
        Assert.Single(fixture.JavaScript.Calls);
        if (revokeSession) fixture.Service.SessionFailure = new UnauthorizedAccessException("Session ended.");
        else fixture.Service.CurrentUser = User(AppRole.Auditor);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(fixture.DownloadAsync);
        Assert.Single(fixture.JavaScript.Calls); // No second stream escapes after revocation.
        Assert.Equal(2, fixture.Service.UserLookups);
        fixture.AssertCacheCleared();
    }

    [Fact]
    public async Task SwitchingSelectorToAudit_CannotDowngradeACachedJournalExportsPermissionCheck()
    {
        using var fixture = new ExportFixture("JournalEntries", AppRole.Auditor);
        fixture.SetDatasetField("_selectedDataset", "AuditLogs");
        await Assert.ThrowsAsync<UnauthorizedAccessException>(fixture.DownloadAsync);
        Assert.Empty(fixture.JavaScript.Calls);
        fixture.AssertCacheCleared();
    }

    [Fact]
    public void LeavingExportPage_ClearsPreparedPlaintextFileBytes()
    {
        var fixture = new ExportFixture("JournalEntries", AppRole.Administrator);
        fixture.Dispose();
        fixture.AssertCacheCleared();
    }

    private static UserContext User(AppRole role) => new(Guid.NewGuid(), "review-user", "Review user", role, Array.Empty<Guid>());

    // Exercise the real component download method without introducing a browser
    // test framework. The service proxy supplies a fresh auth result on each call;
    // the JS fake records whether any bytes would have crossed into the browser.
    private sealed class ExportFixture : IDisposable
    {
        private const BindingFlags PrivateInstance = BindingFlags.Instance | BindingFlags.NonPublic;
        public Exports Component { get; } = new();
        public AuthServiceProxy Service { get; }
        public RecordingJsRuntime JavaScript { get; } = new();
        private readonly byte[] _plaintext = [21, 34, 55, 89];

        public ExportFixture(string dataset, AppRole role)
        {
            var service = DispatchProxy.Create<ISecureJournalAppService, AuthServiceProxy>();
            Service = (AuthServiceProxy)(object)service;
            Service.CurrentUser = User(role);
            typeof(Exports).GetProperty("JournalApp", PrivateInstance)!.SetValue(Component, service);
            typeof(Exports).GetProperty("JS", PrivateInstance)!.SetValue(Component, JavaScript);
            typeof(Exports).GetField("_exportResult", PrivateInstance)!.SetValue(Component,
                new ExportFileResult("cached.zip", "application/zip", string.Empty, 1, "Cached export") { ContentBytes = _plaintext });
            SetDatasetField("_exportDataset", dataset);
            SetDatasetField("_selectedDataset", dataset);
            // A rendered page may still carry an administrator context from before
            // revocation; authorization must replace it with the current service result.
            typeof(Exports).GetField("_currentUser", PrivateInstance)!.SetValue(Component, User(AppRole.Administrator));
        }

        public void SetDatasetField(string name, string value)
        {
            var field = typeof(Exports).GetField(name, PrivateInstance)!;
            field.SetValue(Component, Enum.Parse(Nullable.GetUnderlyingType(field.FieldType) ?? field.FieldType, value));
        }

        public Task DownloadAsync() => (Task)typeof(Exports).GetMethod("DownloadExport", PrivateInstance)!.Invoke(Component, null)!;
        public void AssertCacheCleared()
        {
            Assert.Null(typeof(Exports).GetField("_exportResult", PrivateInstance)!.GetValue(Component));
            Assert.Null(typeof(Exports).GetField("_exportDataset", PrivateInstance)!.GetValue(Component));
            Assert.All(_plaintext, value => Assert.Equal((byte)0, value));
        }
        public void Dispose() => ((IDisposable)Component).Dispose();
    }

    public class AuthServiceProxy : DispatchProxy
    {
        public UserContext CurrentUser { get; set; } = User(AppRole.Administrator);
        public Exception? SessionFailure { get; set; }
        public int UserLookups { get; private set; }
        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            if (targetMethod?.Name != nameof(ISecureJournalAppService.GetCurrentUserAsync))
                throw new InvalidOperationException($"Unexpected service call: {targetMethod?.Name}");
            UserLookups++;
            return SessionFailure is null ? Task.FromResult(CurrentUser) : Task.FromException<UserContext>(SessionFailure);
        }
    }

    private sealed class RecordingJsRuntime : IJSRuntime
    {
        public List<string> Calls { get; } = new();
        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args)
        {
            Calls.Add(identifier);
            return ValueTask.FromResult(default(TValue)!);
        }
        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
            => InvokeAsync<TValue>(identifier, args);
    }
}
