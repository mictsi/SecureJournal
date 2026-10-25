using SecureJournal.Core.Domain;

namespace SecureJournal.Web.Services;

public sealed partial class SecureJournalAppService
{
    public IReadOnlyList<Guid> GetFavoriteProjectIds()
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            RequireFavoriteRole(actor);
            var readable = GetReadableProjectIds(actor);
            // Keep a preference while access is temporarily unavailable, but do
            // not reveal inaccessible IDs or treat a favorite as an access grant.
            return _sqliteStore.LoadFavoriteProjectIds(actor.UserId)
                .Where(readable.Contains).ToArray();
        }
    }

    public bool SetProjectFavorite(Guid projectId, bool isFavorite)
    {
        lock (_sync)
        {
            var actor = GetCurrentUserInternal();
            RequireFavoriteRole(actor);
            if (!GetReadableProjectIds(actor).Contains(projectId))
                throw new UnauthorizedAccessException("This project is unavailable or you do not have access to it.");

            // The current actor is the only source of ownership. A client cannot
            // supply a user ID or mutate another user's preferences.
            _sqliteStore.SetProjectFavorite(actor.UserId, projectId, isFavorite);
            return isFavorite;
        }
    }

    private void RequireFavoriteRole(AppUser actor)
    {
        if (!HasRole(actor, AppRole.Administrator) && !HasRole(actor, AppRole.ProjectUser))
            throw new UnauthorizedAccessException("Project access is required to manage favorites.");
    }
}
