using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace SecureJournal.Web.Infrastructure.Identity;

public sealed class InMemoryAuthenticationTicketStore : ITicketStore
{
    private readonly ConcurrentDictionary<string, TicketEntry> _tickets = new(StringComparer.Ordinal);
    private readonly TimeSpan _defaultLifetime;

    public InMemoryAuthenticationTicketStore(TimeSpan? defaultLifetime = null)
    {
        _defaultLifetime = defaultLifetime ?? TimeSpan.FromHours(8);
    }

    public Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = CreateKey();
        _tickets[key] = CreateEntry(ticket);
        return Task.FromResult(key);
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        _tickets[key] = CreateEntry(ticket);
        return Task.CompletedTask;
    }

    public Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        if (!_tickets.TryGetValue(key, out var entry))
        {
            return Task.FromResult<AuthenticationTicket?>(null);
        }

        if (DateTimeOffset.UtcNow >= entry.ExpiresUtc)
        {
            _tickets.TryRemove(key, out _);
            return Task.FromResult<AuthenticationTicket?>(null);
        }

        return Task.FromResult<AuthenticationTicket?>(entry.Ticket);
    }

    public Task RemoveAsync(string key)
    {
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
        => Convert.ToBase64String(Guid.NewGuid().ToByteArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private sealed record TicketEntry(AuthenticationTicket Ticket, DateTimeOffset ExpiresUtc);
}
