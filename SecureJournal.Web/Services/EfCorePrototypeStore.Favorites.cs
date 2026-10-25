using Microsoft.EntityFrameworkCore;
using SecureJournal.Web.Infrastructure.Persistence;

namespace SecureJournal.Web.Services;

public sealed partial class EfCorePrototypeStore
{
    private static void EnsureFavoriteSchema(SecureJournalAppDbContext db)
    {
        if (db.Database.IsSqlServer())
        {
            db.Database.ExecuteSqlRaw("""
                IF OBJECT_ID('project_favorites', 'U') IS NULL
                BEGIN
                    CREATE TABLE project_favorites (
                        user_id uniqueidentifier NOT NULL REFERENCES app_users(user_id) ON DELETE CASCADE,
                        project_id uniqueidentifier NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                        PRIMARY KEY (user_id, project_id)
                    );
                END
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'ix_project_favorites_project_id' AND object_id = OBJECT_ID('project_favorites'))
                    CREATE INDEX ix_project_favorites_project_id ON project_favorites(project_id);
                """);
        }
        else if (db.Database.IsNpgsql())
        {
            db.Database.ExecuteSqlRaw("""
                CREATE TABLE IF NOT EXISTS project_favorites (
                    user_id uuid NOT NULL REFERENCES app_users(user_id) ON DELETE CASCADE,
                    project_id uuid NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    PRIMARY KEY (user_id, project_id)
                );
                CREATE INDEX IF NOT EXISTS ix_project_favorites_project_id ON project_favorites(project_id);
                """);
        }
        else if (db.Database.IsSqlite())
        {
            db.Database.ExecuteSqlRaw("""
                CREATE TABLE IF NOT EXISTS project_favorites (
                    user_id TEXT NOT NULL REFERENCES app_users(user_id) ON DELETE CASCADE,
                    project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                    PRIMARY KEY (user_id, project_id)
                );
                CREATE INDEX IF NOT EXISTS ix_project_favorites_project_id ON project_favorites(project_id);
                """);
        }
    }

    public IReadOnlyList<Guid> LoadFavoriteProjectIds(Guid userId)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.ProjectFavorites.AsNoTracking().Where(f => f.UserId == userId)
            .OrderBy(f => f.ProjectId).Select(f => f.ProjectId).ToList();
    }

    public void SetProjectFavorite(Guid userId, Guid projectId, bool isFavorite)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        if (!isFavorite)
        {
            db.ProjectFavorites.Where(f => f.UserId == userId && f.ProjectId == projectId).ExecuteDelete();
        }
        else if (db.Database.IsSqlServer())
        {
            // Range locks keep concurrent requests idempotent without swallowing
            // constraint failures unrelated to a duplicate preference.
            db.Database.ExecuteSqlInterpolated($"""
                INSERT INTO project_favorites(user_id, project_id)
                SELECT {userId}, {projectId}
                WHERE NOT EXISTS (
                    SELECT 1 FROM project_favorites WITH (UPDLOCK, HOLDLOCK)
                    WHERE user_id = {userId} AND project_id = {projectId}
                )
                """);
        }
        else
        {
            db.Database.ExecuteSqlInterpolated($"""
                INSERT INTO project_favorites(user_id, project_id) VALUES ({userId}, {projectId})
                ON CONFLICT(user_id, project_id) DO NOTHING
                """);
        }
    }
}
