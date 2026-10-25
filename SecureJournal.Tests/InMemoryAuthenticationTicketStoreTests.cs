using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SecureJournal.Web.Infrastructure.Identity;
using Xunit;

namespace SecureJournal.Tests;

public sealed class InMemoryAuthenticationTicketStoreTests
{
    [Fact]
    public async Task ReplacedPrincipal_DoesNotAuthorizeThePreviousUsersCircuit()
    {
        var store = new InMemoryAuthenticationTicketStore();
        var previous = CreateTicket("previous-user", DateTimeOffset.UtcNow.AddMinutes(30));
        var replacement = CreateTicket("new-user", DateTimeOffset.UtcNow.AddMinutes(30));
        var key = await store.StoreAsync(previous);

        await store.RenewAsync(key, replacement);

        Assert.False(store.IsActive(previous.Principal));
        Assert.True(store.IsActive(replacement.Principal));
    }

    [Fact]
    public async Task ExpiredSession_CannotBeRenewedBeforePeriodicCleanup()
    {
        var store = new InMemoryAuthenticationTicketStore(cleanupInterval: TimeSpan.FromHours(1));
        var expired = CreateTicket("user", DateTimeOffset.UtcNow.AddSeconds(-1));
        var key = await store.StoreAsync(expired);
        var replacement = CreateTicket("user", DateTimeOffset.UtcNow.AddMinutes(30));

        await store.RenewAsync(key, replacement);

        Assert.Null(await store.RetrieveAsync(key));
        Assert.False(store.IsActive(replacement.Principal));
    }

    [Fact]
    public async Task RevokeUserSessions_RemovesOnlyTargetUsersOtherSessions()
    {
        var store = new InMemoryAuthenticationTicketStore();
        var current = CreateTicket("target", DateTimeOffset.UtcNow.AddMinutes(30));
        var other = CreateTicket("target", DateTimeOffset.UtcNow.AddMinutes(30));
        var unrelated = CreateTicket("different", DateTimeOffset.UtcNow.AddMinutes(30));
        var currentKey = await store.StoreAsync(current);
        await store.StoreAsync(other);
        await store.StoreAsync(unrelated);

        store.RevokeUserSessions("target", currentKey);

        Assert.True(store.IsActive(current.Principal));
        Assert.False(store.IsActive(other.Principal));
        Assert.True(store.IsActive(unrelated.Principal));

        store.RevokeUserSessions("target");
        Assert.False(store.IsActive(current.Principal));
    }

    [Fact]
    public async Task RemovedSession_CannotBeResurrectedByAnInFlightRenewal()
    {
        var store = new InMemoryAuthenticationTicketStore();
        var ticket = CreateTicket("user", DateTimeOffset.UtcNow.AddMinutes(30));
        var key = await store.StoreAsync(ticket);
        Assert.True(store.IsActive(ticket.Principal));

        await store.RemoveAsync(key);
        await store.RenewAsync(key, ticket);

        Assert.False(store.IsActive(ticket.Principal));
        Assert.Null(await store.RetrieveAsync(key));
    }

    [Fact]
    public async Task StoreAsync_GeneratesDistinctUrlSafeKeys()
    {
        var store = new InMemoryAuthenticationTicketStore();

        var keyA = await store.StoreAsync(CreateTicket("user-a", DateTimeOffset.UtcNow.AddMinutes(30)));
        var keyB = await store.StoreAsync(CreateTicket("user-b", DateTimeOffset.UtcNow.AddMinutes(30)));

        Assert.NotEqual(keyA, keyB);
        Assert.True(keyA.Length >= 43);
        Assert.True(keyB.Length >= 43);
        Assert.DoesNotContain('+', keyA);
        Assert.DoesNotContain('/', keyA);
        Assert.DoesNotContain('=', keyA);
        Assert.DoesNotContain('+', keyB);
        Assert.DoesNotContain('/', keyB);
        Assert.DoesNotContain('=', keyB);
    }

    [Fact]
    public async Task StoreAsync_CleansUpExpiredTickets_OnAccess()
    {
        var store = new InMemoryAuthenticationTicketStore(
            defaultLifetime: TimeSpan.FromHours(1),
            cleanupInterval: TimeSpan.Zero);

        await store.StoreAsync(CreateTicket("expired-a", DateTimeOffset.UtcNow.AddMinutes(-5)));
        await store.StoreAsync(CreateTicket("expired-b", DateTimeOffset.UtcNow.AddMinutes(-1)));
        await store.StoreAsync(CreateTicket("valid", DateTimeOffset.UtcNow.AddMinutes(20)));

        var tickets = GetBackingStore(store);
        Assert.Single(tickets);
    }

    private static AuthenticationTicket CreateTicket(string username, DateTimeOffset? expiresUtc)
    {
        var identity = new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, username), new Claim(ClaimTypes.NameIdentifier, username)],
            CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);
        var properties = new AuthenticationProperties
        {
            ExpiresUtc = expiresUtc
        };

        return new AuthenticationTicket(
            principal,
            properties,
            CookieAuthenticationDefaults.AuthenticationScheme);
    }

    private static ConcurrentDictionary<string, object> GetBackingStore(InMemoryAuthenticationTicketStore store)
    {
        var field = typeof(InMemoryAuthenticationTicketStore).GetField("_tickets", BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);

        var value = field!.GetValue(store);
        Assert.NotNull(value);

        // TicketEntry is a private nested record; inspect as object values.
        var dictionary = value as System.Collections.IDictionary;
        Assert.NotNull(dictionary);

        var result = new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
        foreach (System.Collections.DictionaryEntry entry in dictionary!)
        {
            result[(string)entry.Key] = entry.Value!;
        }

        return result;
    }
}
