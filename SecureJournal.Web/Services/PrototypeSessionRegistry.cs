using System.Collections.Concurrent;

namespace SecureJournal.Web.Services;

public sealed class PrototypeSessionRegistry
{
    private readonly ConcurrentDictionary<string, SessionEntry> _sessions = new(StringComparer.Ordinal);

    public string CreateSession(Guid userId, TimeSpan lifetime)
    {
        CleanupExpiredSessions();

        var token = Convert.ToHexString(Guid.NewGuid().ToByteArray()) + Convert.ToHexString(Guid.NewGuid().ToByteArray());
        var expiresAtUtc = DateTimeOffset.UtcNow.Add(lifetime);

        _sessions[token] = new SessionEntry(userId, expiresAtUtc);
        return token;
    }

    public bool TryGetUserId(string? token, out Guid userId)
    {
        userId = Guid.Empty;
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        if (!_sessions.TryGetValue(token, out var entry))
        {
            return false;
        }

        if (entry.ExpiresAtUtc <= DateTimeOffset.UtcNow)
        {
            _sessions.TryRemove(token, out _);
            return false;
        }

        userId = entry.UserId;
        return true;
    }

    public bool Remove(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        return _sessions.TryRemove(token, out _);
    }

    private void CleanupExpiredSessions()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var pair in _sessions)
        {
            if (pair.Value.ExpiresAtUtc <= now)
            {
                _sessions.TryRemove(pair.Key, out _);
            }
        }
    }

    private sealed record SessionEntry(Guid UserId, DateTimeOffset ExpiresAtUtc);
}
