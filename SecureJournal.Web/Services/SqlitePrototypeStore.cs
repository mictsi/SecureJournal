using System.Globalization;
using Microsoft.Data.Sqlite;
using SecureJournal.Core.Domain;
using SQLitePCL;

namespace SecureJournal.Web.Services;

public sealed record StoredUserRow(
    Guid UserId,
    string Username,
    string DisplayName,
    AppRole Role,
    bool IsLocalAccount,
    string? PasswordHash,
    string? ExternalIssuer = null,
    string? ExternalSubject = null);

public sealed record StoredProjectRow(
    Guid ProjectId,
    string Code,
    string Name,
    string Description);

public sealed record StoredGroupRow(
    Guid GroupId,
    string Name);

public sealed record StoredUserGroupRow(
    Guid UserId,
    Guid GroupId);

public sealed record StoredProjectGroupRow(
    Guid ProjectId,
    Guid GroupId);

public sealed class SqlitePrototypeStore : IPrototypeDataStore
{
    private readonly string _connectionString;
    private bool _initialized;
    private readonly object _initLock = new();

    public SqlitePrototypeStore(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("SecureJournalSqlite")
            ?? "Data Source=securejournal.db";
    }

    public void Initialize()
    {
        if (_initialized)
        {
            return;
        }

        lock (_initLock)
        {
            if (_initialized)
            {
                return;
            }

            Batteries_V2.Init();
            EnsureDatabaseDirectory();

            using var connection = OpenConnectionInternal();
            using var command = connection.CreateCommand();
            command.CommandText =
                """
                CREATE TABLE IF NOT EXISTS app_users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    role INTEGER NOT NULL,
                    is_local_account INTEGER NOT NULL,
                    password_hash TEXT NULL,
                    external_issuer TEXT NULL,
                    external_subject TEXT NULL
                );

                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    code TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS groups_ref (
                    group_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE
                );

                CREATE TABLE IF NOT EXISTS user_groups (
                    user_id TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    PRIMARY KEY (user_id, group_id)
                );

                CREATE TABLE IF NOT EXISTS project_groups (
                    project_id TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    PRIMARY KEY (project_id, group_id)
                );

                CREATE TABLE IF NOT EXISTS journal_entries (
                    record_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    created_by_user_id TEXT NOT NULL,
                    created_by_username TEXT NOT NULL,
                    category_ciphertext TEXT NOT NULL,
                    subject_ciphertext TEXT NOT NULL,
                    description_ciphertext TEXT NOT NULL,
                    notes_ciphertext TEXT NOT NULL,
                    result_ciphertext TEXT NOT NULL,
                    category_checksum TEXT NOT NULL,
                    subject_checksum TEXT NOT NULL,
                    description_checksum TEXT NOT NULL,
                    notes_checksum TEXT NOT NULL,
                    result_checksum TEXT NOT NULL,
                    full_record_checksum TEXT NOT NULL,
                    is_soft_deleted INTEGER NOT NULL DEFAULT 0,
                    deleted_at_utc TEXT NULL,
                    deleted_by_user_id TEXT NULL,
                    deleted_by_username TEXT NULL,
                    delete_reason TEXT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    audit_id TEXT PRIMARY KEY,
                    timestamp_utc TEXT NOT NULL,
                    actor_user_id TEXT NULL,
                    actor_username TEXT NOT NULL,
                    action INTEGER NOT NULL,
                    entity_type INTEGER NOT NULL,
                    entity_id TEXT NULL,
                    project_id TEXT NULL,
                    outcome INTEGER NOT NULL,
                    details_ciphertext TEXT NOT NULL,
                    details_checksum TEXT NOT NULL
                );
                """;
            command.ExecuteNonQuery();
            EnsureAppUserExternalIdentityColumns(connection);

            _initialized = true;
        }
    }

    public IReadOnlyList<StoredUserRow> LoadUsers()
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT user_id, username, display_name, role, is_local_account, password_hash, external_issuer, external_subject
            FROM app_users
            ORDER BY username;
            """;

        using var reader = command.ExecuteReader();
        var rows = new List<StoredUserRow>();
        while (reader.Read())
        {
            rows.Add(new StoredUserRow(
                UserId: Guid.Parse(reader.GetString(0)),
                Username: reader.GetString(1),
                DisplayName: reader.GetString(2),
                Role: (AppRole)reader.GetInt32(3),
                IsLocalAccount: reader.GetInt64(4) == 1,
                PasswordHash: reader.IsDBNull(5) ? null : reader.GetString(5),
                ExternalIssuer: reader.IsDBNull(6) ? null : reader.GetString(6),
                ExternalSubject: reader.IsDBNull(7) ? null : reader.GetString(7)));
        }

        return rows;
    }

    public IReadOnlyList<StoredProjectRow> LoadProjects()
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT project_id, code, name, description
            FROM projects
            ORDER BY code;
            """;

        using var reader = command.ExecuteReader();
        var rows = new List<StoredProjectRow>();
        while (reader.Read())
        {
            rows.Add(new StoredProjectRow(
                ProjectId: Guid.Parse(reader.GetString(0)),
                Code: reader.GetString(1),
                Name: reader.GetString(2),
                Description: reader.GetString(3)));
        }

        return rows;
    }

    public IReadOnlyList<StoredGroupRow> LoadGroups()
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT group_id, name
            FROM groups_ref
            ORDER BY name;
            """;

        using var reader = command.ExecuteReader();
        var rows = new List<StoredGroupRow>();
        while (reader.Read())
        {
            rows.Add(new StoredGroupRow(
                GroupId: Guid.Parse(reader.GetString(0)),
                Name: reader.GetString(1)));
        }

        return rows;
    }

    public IReadOnlyList<StoredUserGroupRow> LoadUserGroups()
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT user_id, group_id
            FROM user_groups
            ORDER BY user_id, group_id;
            """;

        using var reader = command.ExecuteReader();
        var rows = new List<StoredUserGroupRow>();
        while (reader.Read())
        {
            rows.Add(new StoredUserGroupRow(
                UserId: Guid.Parse(reader.GetString(0)),
                GroupId: Guid.Parse(reader.GetString(1))));
        }

        return rows;
    }

    public IReadOnlyList<StoredProjectGroupRow> LoadProjectGroups()
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT project_id, group_id
            FROM project_groups
            ORDER BY project_id, group_id;
            """;

        using var reader = command.ExecuteReader();
        var rows = new List<StoredProjectGroupRow>();
        while (reader.Read())
        {
            rows.Add(new StoredProjectGroupRow(
                ProjectId: Guid.Parse(reader.GetString(0)),
                GroupId: Guid.Parse(reader.GetString(1))));
        }

        return rows;
    }

    public IReadOnlyList<JournalEntryRecord> LoadJournalEntries()
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
                record_id, project_id, created_at_utc, created_by_user_id, created_by_username,
                category_ciphertext, subject_ciphertext, description_ciphertext, notes_ciphertext, result_ciphertext,
                category_checksum, subject_checksum, description_checksum, notes_checksum, result_checksum,
                full_record_checksum, is_soft_deleted, deleted_at_utc, deleted_by_user_id, deleted_by_username, delete_reason
            FROM journal_entries
            ORDER BY created_at_utc DESC;
            """;

        using var reader = command.ExecuteReader();
        var rows = new List<JournalEntryRecord>();
        while (reader.Read())
        {
            var record = new JournalEntryRecord
            {
                RecordId = Guid.Parse(reader.GetString(0)),
                ProjectId = Guid.Parse(reader.GetString(1)),
                CreatedAtUtc = ParseUtc(reader.GetString(2)),
                CreatedByUserId = Guid.Parse(reader.GetString(3)),
                CreatedByUsername = reader.GetString(4),
                CategoryCiphertext = reader.GetString(5),
                SubjectCiphertext = reader.GetString(6),
                DescriptionCiphertext = reader.GetString(7),
                NotesCiphertext = reader.GetString(8),
                ResultCiphertext = reader.GetString(9),
                CategoryChecksum = reader.GetString(10),
                SubjectChecksum = reader.GetString(11),
                DescriptionChecksum = reader.GetString(12),
                NotesChecksum = reader.GetString(13),
                ResultChecksum = reader.GetString(14),
                FullRecordChecksum = reader.GetString(15)
            };

            var isSoftDeleted = reader.GetInt64(16) == 1;
            if (isSoftDeleted)
            {
                record.MarkSoftDeleted(new SoftDeleteMetadata(
                    DeletedAtUtc: reader.IsDBNull(17) ? record.CreatedAtUtc : ParseUtc(reader.GetString(17)),
                    DeletedByUserId: reader.IsDBNull(18) ? Guid.Empty : Guid.Parse(reader.GetString(18)),
                    DeletedByUsername: reader.IsDBNull(19) ? "unknown" : reader.GetString(19),
                    Reason: reader.IsDBNull(20) ? string.Empty : reader.GetString(20)));
            }

            rows.Add(record);
        }

        return rows;
    }

    public IReadOnlyList<AuditLogRecord> LoadAuditLogs()
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT
                audit_id, timestamp_utc, actor_user_id, actor_username, action,
                entity_type, entity_id, project_id, outcome, details_ciphertext, details_checksum
            FROM audit_logs
            ORDER BY timestamp_utc DESC;
            """;

        using var reader = command.ExecuteReader();
        var rows = new List<AuditLogRecord>();
        while (reader.Read())
        {
            rows.Add(new AuditLogRecord(
                AuditId: Guid.Parse(reader.GetString(0)),
                TimestampUtc: ParseUtc(reader.GetString(1)),
                ActorUserId: reader.IsDBNull(2) ? null : Guid.Parse(reader.GetString(2)),
                ActorUsername: reader.GetString(3),
                Action: (AuditActionType)reader.GetInt32(4),
                EntityType: (AuditEntityType)reader.GetInt32(5),
                EntityId: reader.IsDBNull(6) ? null : reader.GetString(6),
                ProjectId: reader.IsDBNull(7) ? null : Guid.Parse(reader.GetString(7)),
                Outcome: (AuditOutcome)reader.GetInt32(8),
                DetailsCiphertext: reader.GetString(9),
                DetailsChecksum: reader.GetString(10)));
        }

        return rows;
    }

    public void UpsertJournalEntry(JournalEntryRecord record)
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO journal_entries (
                record_id, project_id, created_at_utc, created_by_user_id, created_by_username,
                category_ciphertext, subject_ciphertext, description_ciphertext, notes_ciphertext, result_ciphertext,
                category_checksum, subject_checksum, description_checksum, notes_checksum, result_checksum,
                full_record_checksum, is_soft_deleted, deleted_at_utc, deleted_by_user_id, deleted_by_username, delete_reason
            ) VALUES (
                $record_id, $project_id, $created_at_utc, $created_by_user_id, $created_by_username,
                $category_ciphertext, $subject_ciphertext, $description_ciphertext, $notes_ciphertext, $result_ciphertext,
                $category_checksum, $subject_checksum, $description_checksum, $notes_checksum, $result_checksum,
                $full_record_checksum, $is_soft_deleted, $deleted_at_utc, $deleted_by_user_id, $deleted_by_username, $delete_reason
            )
            ON CONFLICT(record_id) DO UPDATE SET
                project_id = excluded.project_id,
                created_at_utc = excluded.created_at_utc,
                created_by_user_id = excluded.created_by_user_id,
                created_by_username = excluded.created_by_username,
                category_ciphertext = excluded.category_ciphertext,
                subject_ciphertext = excluded.subject_ciphertext,
                description_ciphertext = excluded.description_ciphertext,
                notes_ciphertext = excluded.notes_ciphertext,
                result_ciphertext = excluded.result_ciphertext,
                category_checksum = excluded.category_checksum,
                subject_checksum = excluded.subject_checksum,
                description_checksum = excluded.description_checksum,
                notes_checksum = excluded.notes_checksum,
                result_checksum = excluded.result_checksum,
                full_record_checksum = excluded.full_record_checksum,
                is_soft_deleted = excluded.is_soft_deleted,
                deleted_at_utc = excluded.deleted_at_utc,
                deleted_by_user_id = excluded.deleted_by_user_id,
                deleted_by_username = excluded.deleted_by_username,
                delete_reason = excluded.delete_reason;
            """;

        BindJournalParameters(command, record);
        command.ExecuteNonQuery();
    }

    public void UpsertUser(StoredUserRow user)
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO app_users (user_id, username, display_name, role, is_local_account, password_hash, external_issuer, external_subject)
            VALUES ($user_id, $username, $display_name, $role, $is_local_account, $password_hash, $external_issuer, $external_subject)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                display_name = excluded.display_name,
                role = excluded.role,
                is_local_account = excluded.is_local_account,
                password_hash = excluded.password_hash,
                external_issuer = excluded.external_issuer,
                external_subject = excluded.external_subject;
            """;

        command.Parameters.AddWithValue("$user_id", user.UserId.ToString("D"));
        command.Parameters.AddWithValue("$username", user.Username);
        command.Parameters.AddWithValue("$display_name", user.DisplayName);
        command.Parameters.AddWithValue("$role", (int)user.Role);
        command.Parameters.AddWithValue("$is_local_account", user.IsLocalAccount ? 1 : 0);
        command.Parameters.AddWithValue("$password_hash", user.PasswordHash ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$external_issuer", user.ExternalIssuer ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$external_subject", user.ExternalSubject ?? (object)DBNull.Value);
        command.ExecuteNonQuery();
    }

    public void UpsertProject(StoredProjectRow project)
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO projects (project_id, code, name, description)
            VALUES ($project_id, $code, $name, $description)
            ON CONFLICT(project_id) DO UPDATE SET
                code = excluded.code,
                name = excluded.name,
                description = excluded.description;
            """;

        command.Parameters.AddWithValue("$project_id", project.ProjectId.ToString("D"));
        command.Parameters.AddWithValue("$code", project.Code);
        command.Parameters.AddWithValue("$name", project.Name);
        command.Parameters.AddWithValue("$description", project.Description);
        command.ExecuteNonQuery();
    }

    public void UpsertGroup(StoredGroupRow group)
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO groups_ref (group_id, name)
            VALUES ($group_id, $name)
            ON CONFLICT(group_id) DO UPDATE SET
                name = excluded.name;
            """;

        command.Parameters.AddWithValue("$group_id", group.GroupId.ToString("D"));
        command.Parameters.AddWithValue("$name", group.Name);
        command.ExecuteNonQuery();
    }

    public void AddUserToGroup(Guid userId, Guid groupId)
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT OR IGNORE INTO user_groups (user_id, group_id)
            VALUES ($user_id, $group_id);
            """;

        command.Parameters.AddWithValue("$user_id", userId.ToString("D"));
        command.Parameters.AddWithValue("$group_id", groupId.ToString("D"));
        command.ExecuteNonQuery();
    }

    public void AddGroupToProject(Guid projectId, Guid groupId)
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT OR IGNORE INTO project_groups (project_id, group_id)
            VALUES ($project_id, $group_id);
            """;

        command.Parameters.AddWithValue("$project_id", projectId.ToString("D"));
        command.Parameters.AddWithValue("$group_id", groupId.ToString("D"));
        command.ExecuteNonQuery();
    }

    public void InsertAuditLog(AuditLogRecord record)
    {
        Initialize();

        using var connection = OpenConnectionInternal();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO audit_logs (
                audit_id, timestamp_utc, actor_user_id, actor_username, action,
                entity_type, entity_id, project_id, outcome, details_ciphertext, details_checksum
            ) VALUES (
                $audit_id, $timestamp_utc, $actor_user_id, $actor_username, $action,
                $entity_type, $entity_id, $project_id, $outcome, $details_ciphertext, $details_checksum
            );
            """;

        command.Parameters.AddWithValue("$audit_id", record.AuditId.ToString("D"));
        command.Parameters.AddWithValue("$timestamp_utc", record.TimestampUtc.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$actor_user_id", record.ActorUserId?.ToString("D") ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$actor_username", record.ActorUsername);
        command.Parameters.AddWithValue("$action", (int)record.Action);
        command.Parameters.AddWithValue("$entity_type", (int)record.EntityType);
        command.Parameters.AddWithValue("$entity_id", record.EntityId ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$project_id", record.ProjectId?.ToString("D") ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$outcome", (int)record.Outcome);
        command.Parameters.AddWithValue("$details_ciphertext", record.DetailsCiphertext);
        command.Parameters.AddWithValue("$details_checksum", record.DetailsChecksum);
        command.ExecuteNonQuery();
    }

    private void BindJournalParameters(SqliteCommand command, JournalEntryRecord record)
    {
        command.Parameters.AddWithValue("$record_id", record.RecordId.ToString("D"));
        command.Parameters.AddWithValue("$project_id", record.ProjectId.ToString("D"));
        command.Parameters.AddWithValue("$created_at_utc", record.CreatedAtUtc.ToUniversalTime().ToString("O"));
        command.Parameters.AddWithValue("$created_by_user_id", record.CreatedByUserId.ToString("D"));
        command.Parameters.AddWithValue("$created_by_username", record.CreatedByUsername);
        command.Parameters.AddWithValue("$category_ciphertext", record.CategoryCiphertext);
        command.Parameters.AddWithValue("$subject_ciphertext", record.SubjectCiphertext);
        command.Parameters.AddWithValue("$description_ciphertext", record.DescriptionCiphertext);
        command.Parameters.AddWithValue("$notes_ciphertext", record.NotesCiphertext);
        command.Parameters.AddWithValue("$result_ciphertext", record.ResultCiphertext);
        command.Parameters.AddWithValue("$category_checksum", record.CategoryChecksum);
        command.Parameters.AddWithValue("$subject_checksum", record.SubjectChecksum);
        command.Parameters.AddWithValue("$description_checksum", record.DescriptionChecksum);
        command.Parameters.AddWithValue("$notes_checksum", record.NotesChecksum);
        command.Parameters.AddWithValue("$result_checksum", record.ResultChecksum);
        command.Parameters.AddWithValue("$full_record_checksum", record.FullRecordChecksum);
        command.Parameters.AddWithValue("$is_soft_deleted", record.IsSoftDeleted ? 1 : 0);
        command.Parameters.AddWithValue("$deleted_at_utc", record.SoftDelete?.DeletedAtUtc.ToUniversalTime().ToString("O") ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$deleted_by_user_id", record.SoftDelete?.DeletedByUserId.ToString("D") ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$deleted_by_username", record.SoftDelete?.DeletedByUsername ?? (object)DBNull.Value);
        command.Parameters.AddWithValue("$delete_reason", record.SoftDelete?.Reason ?? (object)DBNull.Value);
    }

    private SqliteConnection OpenConnectionInternal()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        return connection;
    }

    private void EnsureDatabaseDirectory()
    {
        var builder = new SqliteConnectionStringBuilder(_connectionString);
        if (string.IsNullOrWhiteSpace(builder.DataSource) || builder.DataSource == ":memory:")
        {
            return;
        }

        var fullPath = Path.GetFullPath(builder.DataSource);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    private static DateTime ParseUtc(string value)
        => DateTime.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind).ToUniversalTime();

    private static void EnsureAppUserExternalIdentityColumns(SqliteConnection connection)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA table_info(app_users);";
            using var reader = pragma.ExecuteReader();
            while (reader.Read())
            {
                if (!reader.IsDBNull(1))
                {
                    columns.Add(reader.GetString(1));
                }
            }
        }

        if (!columns.Contains("external_issuer"))
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "ALTER TABLE app_users ADD COLUMN external_issuer TEXT NULL;";
            cmd.ExecuteNonQuery();
        }

        if (!columns.Contains("external_subject"))
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = "ALTER TABLE app_users ADD COLUMN external_subject TEXT NULL;";
            cmd.ExecuteNonQuery();
        }
    }
}
