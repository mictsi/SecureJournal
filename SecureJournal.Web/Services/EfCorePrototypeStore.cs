using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.Data.SqlClient;
using SecureJournal.Core.Domain;
using SecureJournal.Web.Infrastructure.Persistence;

namespace SecureJournal.Web.Services;

public sealed class EfCorePrototypeStore : IPrototypeDataStore
{
    private readonly IDbContextFactory<SecureJournalAppDbContext> _dbFactory;
    private readonly object _initLock = new();
    private bool _initialized;

    public EfCorePrototypeStore(IDbContextFactory<SecureJournalAppDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
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

            using var db = _dbFactory.CreateDbContext();
            db.Database.EnsureCreated();
            _initialized = true;
        }
    }

    public IReadOnlyList<StoredUserRow> LoadUsers()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.AppUsers
            .AsNoTracking()
            .OrderBy(x => x.Username)
            .Select(x => new StoredUserRow(
                x.UserId,
                x.Username,
                x.DisplayName,
                (AppRole)x.Role,
                x.IsLocalAccount,
                x.PasswordHash))
            .ToList();
    }

    public IReadOnlyList<StoredProjectRow> LoadProjects()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.Projects
            .AsNoTracking()
            .OrderBy(x => x.Code)
            .Select(x => new StoredProjectRow(x.ProjectId, x.Code, x.Name, x.Description))
            .ToList();
    }

    public IReadOnlyList<StoredGroupRow> LoadGroups()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.Groups
            .AsNoTracking()
            .OrderBy(x => x.Name)
            .Select(x => new StoredGroupRow(x.GroupId, x.Name))
            .ToList();
    }

    public IReadOnlyList<StoredUserGroupRow> LoadUserGroups()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.UserGroups
            .AsNoTracking()
            .OrderBy(x => x.UserId)
            .ThenBy(x => x.GroupId)
            .Select(x => new StoredUserGroupRow(x.UserId, x.GroupId))
            .ToList();
    }

    public IReadOnlyList<StoredProjectGroupRow> LoadProjectGroups()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.ProjectGroups
            .AsNoTracking()
            .OrderBy(x => x.ProjectId)
            .ThenBy(x => x.GroupId)
            .Select(x => new StoredProjectGroupRow(x.ProjectId, x.GroupId))
            .ToList();
    }

    public IReadOnlyList<JournalEntryRecord> LoadJournalEntries()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var entities = db.JournalEntries
            .AsNoTracking()
            .OrderByDescending(x => x.CreatedAtUtc)
            .ToList();

        var rows = new List<JournalEntryRecord>(entities.Count);
        foreach (var x in entities)
        {
            var record = new JournalEntryRecord
            {
                RecordId = x.RecordId,
                ProjectId = x.ProjectId,
                CreatedAtUtc = DateTime.SpecifyKind(x.CreatedAtUtc, DateTimeKind.Utc).ToUniversalTime(),
                CreatedByUserId = x.CreatedByUserId,
                CreatedByUsername = x.CreatedByUsername,
                CategoryCiphertext = x.CategoryCiphertext,
                SubjectCiphertext = x.SubjectCiphertext,
                DescriptionCiphertext = x.DescriptionCiphertext,
                NotesCiphertext = x.NotesCiphertext,
                ResultCiphertext = x.ResultCiphertext,
                CategoryChecksum = x.CategoryChecksum,
                SubjectChecksum = x.SubjectChecksum,
                DescriptionChecksum = x.DescriptionChecksum,
                NotesChecksum = x.NotesChecksum,
                ResultChecksum = x.ResultChecksum,
                FullRecordChecksum = x.FullRecordChecksum
            };

            if (x.IsSoftDeleted)
            {
                record.MarkSoftDeleted(new SoftDeleteMetadata(
                    DeletedAtUtc: DateTime.SpecifyKind(x.DeletedAtUtc ?? x.CreatedAtUtc, DateTimeKind.Utc).ToUniversalTime(),
                    DeletedByUserId: x.DeletedByUserId ?? Guid.Empty,
                    DeletedByUsername: string.IsNullOrWhiteSpace(x.DeletedByUsername) ? "unknown" : x.DeletedByUsername!,
                    Reason: x.DeleteReason ?? string.Empty));
            }

            rows.Add(record);
        }

        return rows;
    }

    public IReadOnlyList<AuditLogRecord> LoadAuditLogs()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.AuditLogs
            .AsNoTracking()
            .OrderByDescending(x => x.TimestampUtc)
            .Select(x => new AuditLogRecord(
                x.AuditId,
                DateTime.SpecifyKind(x.TimestampUtc, DateTimeKind.Utc).ToUniversalTime(),
                x.ActorUserId,
                x.ActorUsername,
                (AuditActionType)x.Action,
                (AuditEntityType)x.EntityType,
                x.EntityId,
                x.ProjectId,
                (AuditOutcome)x.Outcome,
                x.DetailsCiphertext,
                x.DetailsChecksum))
            .ToList();
    }

    public void UpsertJournalEntry(JournalEntryRecord record)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var entity = db.JournalEntries.SingleOrDefault(x => x.RecordId == record.RecordId);
        if (entity is null)
        {
            entity = new JournalEntryEntity { RecordId = record.RecordId };
            db.JournalEntries.Add(entity);
        }

        Map(entity, record);
        db.SaveChanges();
    }

    public void UpsertUser(StoredUserRow user)
    {
        Initialize();

        try
        {
            UpsertUserCore(user);
        }
        catch (DbUpdateException ex) when (IsUniqueUsernameViolation(ex))
        {
            // Retry once with reconciliation logic from a fresh DbContext for race/migration edge cases.
            UpsertUserCore(user, forceReconcileByUsername: true);
        }
    }

    public void UpsertProject(StoredProjectRow project)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var entity = db.Projects.SingleOrDefault(x => x.ProjectId == project.ProjectId);
        if (entity is null)
        {
            entity = new ProjectEntity { ProjectId = project.ProjectId };
            db.Projects.Add(entity);
        }

        entity.Code = project.Code;
        entity.Name = project.Name;
        entity.Description = project.Description;
        db.SaveChanges();
    }

    public void UpsertGroup(StoredGroupRow group)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var entity = db.Groups.SingleOrDefault(x => x.GroupId == group.GroupId);
        if (entity is null)
        {
            entity = new GroupEntity { GroupId = group.GroupId };
            db.Groups.Add(entity);
        }

        entity.Name = group.Name;
        db.SaveChanges();
    }

    public void AddUserToGroup(Guid userId, Guid groupId)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var exists = db.UserGroups.Any(x => x.UserId == userId && x.GroupId == groupId);
        if (!exists)
        {
            db.UserGroups.Add(new UserGroupEntity { UserId = userId, GroupId = groupId });
            db.SaveChanges();
        }
    }

    public void AddGroupToProject(Guid projectId, Guid groupId)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var exists = db.ProjectGroups.Any(x => x.ProjectId == projectId && x.GroupId == groupId);
        if (!exists)
        {
            db.ProjectGroups.Add(new ProjectGroupEntity { ProjectId = projectId, GroupId = groupId });
            db.SaveChanges();
        }
    }

    public void InsertAuditLog(AuditLogRecord record)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        db.AuditLogs.Add(new AuditLogEntity
        {
            AuditId = record.AuditId,
            TimestampUtc = record.TimestampUtc.ToUniversalTime(),
            ActorUserId = record.ActorUserId,
            ActorUsername = record.ActorUsername,
            Action = (int)record.Action,
            EntityType = (int)record.EntityType,
            EntityId = record.EntityId,
            ProjectId = record.ProjectId,
            Outcome = (int)record.Outcome,
            DetailsCiphertext = record.DetailsCiphertext,
            DetailsChecksum = record.DetailsChecksum
        });
        db.SaveChanges();
    }

    private static void Map(JournalEntryEntity entity, JournalEntryRecord record)
    {
        entity.ProjectId = record.ProjectId;
        entity.CreatedAtUtc = record.CreatedAtUtc.ToUniversalTime();
        entity.CreatedByUserId = record.CreatedByUserId;
        entity.CreatedByUsername = record.CreatedByUsername;
        entity.CategoryCiphertext = record.CategoryCiphertext;
        entity.SubjectCiphertext = record.SubjectCiphertext;
        entity.DescriptionCiphertext = record.DescriptionCiphertext;
        entity.NotesCiphertext = record.NotesCiphertext;
        entity.ResultCiphertext = record.ResultCiphertext;
        entity.CategoryChecksum = record.CategoryChecksum;
        entity.SubjectChecksum = record.SubjectChecksum;
        entity.DescriptionChecksum = record.DescriptionChecksum;
        entity.NotesChecksum = record.NotesChecksum;
        entity.ResultChecksum = record.ResultChecksum;
        entity.FullRecordChecksum = record.FullRecordChecksum;
        entity.IsSoftDeleted = record.IsSoftDeleted;
        entity.DeletedAtUtc = record.SoftDelete?.DeletedAtUtc.ToUniversalTime();
        entity.DeletedByUserId = record.SoftDelete?.DeletedByUserId == Guid.Empty ? null : record.SoftDelete?.DeletedByUserId;
        entity.DeletedByUsername = record.SoftDelete?.DeletedByUsername;
        entity.DeleteReason = record.SoftDelete?.Reason;
    }

    private void UpsertUserCore(StoredUserRow user, bool forceReconcileByUsername = false)
    {
        using var strategyDb = _dbFactory.CreateDbContext();
        var strategy = strategyDb.Database.CreateExecutionStrategy();

        strategy.Execute(() =>
        {
            using var db = _dbFactory.CreateDbContext();
            using var tx = db.Database.BeginTransaction();

            var existingByUsername = db.AppUsers
                .AsNoTracking()
                .SingleOrDefault(x => x.Username == user.Username);

            if (forceReconcileByUsername && existingByUsername is not null && existingByUsername.UserId != user.UserId)
            {
                ReconcileUserIdForExistingUsername(db, existingByUsername.UserId, user.UserId);
                db.ChangeTracker.Clear();
            }
            else if (existingByUsername is not null && existingByUsername.UserId != user.UserId)
            {
                ReconcileUserIdForExistingUsername(db, existingByUsername.UserId, user.UserId);
                db.ChangeTracker.Clear();
            }

            var entity = db.AppUsers.SingleOrDefault(x => x.UserId == user.UserId);
            if (entity is null)
            {
                entity = new AppUserEntity { UserId = user.UserId };
                db.AppUsers.Add(entity);
            }

            entity.Username = user.Username;
            entity.DisplayName = user.DisplayName;
            entity.Role = (int)user.Role;
            entity.IsLocalAccount = user.IsLocalAccount;
            entity.PasswordHash = user.PasswordHash;
            db.SaveChanges();
            tx.Commit();
        });
    }

    private static void ReconcileUserIdForExistingUsername(SecureJournalAppDbContext db, Guid existingUserId, Guid replacementUserId)
    {
        if (existingUserId == replacementUserId)
        {
            return;
        }

        var existingUser = db.AppUsers.Single(x => x.UserId == existingUserId);

        var oldMemberships = db.UserGroups
            .Where(x => x.UserId == existingUserId)
            .ToList();
        foreach (var membership in oldMemberships)
        {
            var duplicateExists = db.UserGroups.Any(x => x.UserId == replacementUserId && x.GroupId == membership.GroupId);
            db.UserGroups.Remove(membership);
            if (!duplicateExists)
            {
                db.UserGroups.Add(new UserGroupEntity
                {
                    UserId = replacementUserId,
                    GroupId = membership.GroupId
                });
            }
        }

        foreach (var row in db.JournalEntries.Where(x => x.CreatedByUserId == existingUserId))
        {
            row.CreatedByUserId = replacementUserId;
        }

        foreach (var row in db.JournalEntries.Where(x => x.DeletedByUserId == existingUserId))
        {
            row.DeletedByUserId = replacementUserId;
        }

        foreach (var row in db.AuditLogs.Where(x => x.ActorUserId == existingUserId))
        {
            row.ActorUserId = replacementUserId;
        }

        db.AppUsers.Remove(existingUser);
        db.SaveChanges();
    }

    private static bool IsUniqueUsernameViolation(DbUpdateException ex)
        => (ex.InnerException is SqliteException sqlite
            && sqlite.SqliteErrorCode == 19
            && sqlite.Message.Contains("app_users.username", StringComparison.OrdinalIgnoreCase))
           || (ex.InnerException is SqlException sql
               && (sql.Number == 2601 || sql.Number == 2627)
               && sql.Message.Contains("app_users", StringComparison.OrdinalIgnoreCase)
               && sql.Message.Contains("username", StringComparison.OrdinalIgnoreCase));
}
