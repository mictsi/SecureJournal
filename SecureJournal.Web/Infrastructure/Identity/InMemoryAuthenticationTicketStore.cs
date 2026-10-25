using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace SecureJournal.Web.Infrastructure.Identity;

public sealed class InMemoryAuthenticationTicketStore : ITicketStore
{
    internal const string SessionIdClaimType = "securejournal:server-session";
    private readonly ConcurrentDictionary<string, TicketEntry> _tickets = new(StringComparer.Ordinal);
    private readonly TimeSpan _defaultLifetime;
    private readonly TimeSpan _cleanupInterval;
    private long _nextCleanupTicksUtc;

    public InMemoryAuthenticationTicketStore(TimeSpan? defaultLifetime = null, TimeSpan? cleanupInterval = null)
    {
        _defaultLifetime = defaultLifetime ?? TimeSpan.FromHours(8);
        _cleanupInterval = cleanupInterval ?? TimeSpan.FromMinutes(5);
        _nextCleanupTicksUtc = DateTimeOffset.UtcNow.Add(_cleanupInterval).UtcTicks;
    }

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        TryCleanupExpiredEntries(DateTimeOffset.UtcNow);
        var key = CreateKey();
        SetSessionClaim(ticket.Principal, key);
        _tickets[key] = CreateEntry(ticket);
        return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        TryCleanupExpiredEntries(DateTimeOffset.UtcNow);
        // A request already in flight must not resurrect a session after logout.
        if (_tickets.TryGetValue(key, out var current))
        {
            if (current.ExpiresUtc <= DateTimeOffset.UtcNow)
            {
                _tickets.TryRemove(new KeyValuePair<string, TicketEntry>(key, current));
                return Task.CompletedTask;
            }

            SetSessionClaim(ticket.Principal, key);
            _tickets.TryUpdate(key, CreateEntry(ticket), current);
        }
        return Task.CompletedTask;
    }

    public bool IsActive(ClaimsPrincipal? principal)
    {
        var key = principal?.FindFirstValue(SessionIdClaimType);
        if (principal?.Identity?.IsAuthenticated != true || string.IsNullOrEmpty(key)
            || !_tickets.TryGetValue(key, out var entry))
        {
            return false;
        }

        if (DateTimeOffset.UtcNow >= entry.ExpiresUtc)
        {
            _tickets.TryRemove(new KeyValuePair<string, TicketEntry>(key, entry));
            return false;
        }

        // A sign-in or renewal can replace the principal behind a ticket key.
        // An existing circuit must not retain the previous user's authority.
        return SameIdentity(principal, entry.Ticket.Principal);
    }

    private static bool SameIdentity(ClaimsPrincipal left, ClaimsPrincipal right)
        => string.Equals(left.Identity?.AuthenticationType, right.Identity?.AuthenticationType, StringComparison.Ordinal)
           && string.Equals(left.FindFirstValue(ClaimTypes.NameIdentifier), right.FindFirstValue(ClaimTypes.NameIdentifier), StringComparison.Ordinal)
           && string.Equals(left.FindFirstValue("iss"), right.FindFirstValue("iss"), StringComparison.Ordinal)
           && string.Equals(left.FindFirstValue("sub"), right.FindFirstValue("sub"), StringComparison.Ordinal)
           && string.Equals(left.Identity?.Name, right.Identity?.Name, StringComparison.Ordinal);

    public void RevokeUserSessions(string identityUserId, string? exceptSessionId = null)
    {
        foreach (var pair in _tickets)
        {
            if (!string.Equals(pair.Key, exceptSessionId, StringComparison.Ordinal)
                && string.Equals(pair.Value.Ticket.Principal.FindFirstValue(ClaimTypes.NameIdentifier), identityUserId, StringComparison.Ordinal))
            {
                _tickets.TryRemove(pair.Key, out _);
            }
        }
    }

    private static void SetSessionClaim(ClaimsPrincipal principal, string key)
    {
        foreach (var identity in principal.Identities)
        {
            foreach (var claim in identity.FindAll(SessionIdClaimType).ToList())
            {
                identity.RemoveClaim(claim);
            }
        }

        principal.Identities.First(identity => identity.IsAuthenticated)
            .AddClaim(new Claim(SessionIdClaimType, key));
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var now = DateTimeOffset.UtcNow;
        TryCleanupExpiredEntries(now);

        if (!_tickets.TryGetValue(key, out var entry))
        {
            return Task.FromResult<AuthenticationTicket?>(null);
        }

        if (now >= entry.ExpiresUtc)
        {
            _tickets.TryRemove(new KeyValuePair<string, TicketEntry>(key, entry));
            return Task.FromResult<AuthenticationTicket?>(null);
        }

        return Task.FromResult<AuthenticationTicket?>(entry.Ticket);
    }

    public Task RemoveAsync(string key)
    {
        TryCleanupExpiredEntries(DateTimeOffset.UtcNow);
        _tickets.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    public Task<string> StoreAsync(HttpContext context, AuthenticationTicket ticket, CancellationToken cancellationToken)
        => StoreAsync(ticket);

    public Task RenewAsync(HttpContext context, string key, AuthenticationTicket ticket, CancellationToken cancellationToken)
        => RenewAsync(key, ticket);

    public Task<AuthenticationTicket?> RetrieveAsync(HttpContext context, string key, CancellationToken cancellationToken)
        => RetrieveAsync(key);

    public Task RemoveAsync(HttpContext context, string key, CancellationToken cancellationToken)
        => RemoveAsync(key);

    private TicketEntry CreateEntry(AuthenticationTicket ticket)
    {
        var expiresUtc = ticket.Properties.ExpiresUtc;
        return new TicketEntry(
            ticket,
            expiresUtc ?? DateTimeOffset.UtcNow.Add(_defaultLifetime));
    }

    private static string CreateKey()
    {
        Span<byte> randomBytes = stackalloc byte[32];
        RandomNumberGenerator.Fill(randomBytes);
        return Convert.ToBase64String(randomBytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private void TryCleanupExpiredEntries(DateTimeOffset nowUtc)
    {
        var nowTicks = nowUtc.UtcTicks;
        var nextCleanupTicks = Interlocked.Read(ref _nextCleanupTicksUtc);
        if (nowTicks < nextCleanupTicks)
        {
            return;
        }

        var updatedNextTicks = nowUtc.Add(_cleanupInterval).UtcTicks;
        if (Interlocked.CompareExchange(ref _nextCleanupTicksUtc, updatedNextTicks, nextCleanupTicks) != nextCleanupTicks)
        {
            return;
        }

        foreach (var pair in _tickets)
        {
            if (pair.Value.ExpiresUtc <= nowUtc)
            {
                _tickets.TryRemove(pair);
            }
        }
    }

    private sealed record TicketEntry(AuthenticationTicket Ticket, DateTimeOffset ExpiresUtc);
}
