using Microsoft.Data.Sqlite;

namespace SecureJournal.Web.Services;

public sealed partial class SqlitePrototypeStore
{
    private static void EnsureFavoriteSchema(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS project_favorites (
                user_id TEXT NOT NULL REFERENCES app_users(user_id) ON DELETE CASCADE,
                project_id TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
                PRIMARY KEY (user_id, project_id)
            );
            CREATE INDEX IF NOT EXISTS ix_project_favorites_project_id ON project_favorites(project_id);
            """;
        command.ExecuteNonQuery();
    }

    public IReadOnlyList<Guid> LoadFavoriteProjectIds(Guid userId)
    {
        Initialize();
        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT project_id FROM project_favorites WHERE user_id = $user ORDER BY project_id";
        command.Parameters.AddWithValue("$user", userId.ToString("D"));
        using var reader = command.ExecuteReader();
        var result = new List<Guid>();
        while (reader.Read()) result.Add(Guid.Parse(reader.GetString(0)));
        return result;
    }

    public void SetProjectFavorite(Guid userId, Guid projectId, bool isFavorite)
    {
        Initialize();
        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText = isFavorite
            ? "INSERT INTO project_favorites(user_id, project_id) VALUES ($user, $project) ON CONFLICT(user_id, project_id) DO NOTHING"
            : "DELETE FROM project_favorites WHERE user_id = $user AND project_id = $project";
        command.Parameters.AddWithValue("$user", userId.ToString("D"));
        command.Parameters.AddWithValue("$project", projectId.ToString("D"));
        command.ExecuteNonQuery();
    }
}
