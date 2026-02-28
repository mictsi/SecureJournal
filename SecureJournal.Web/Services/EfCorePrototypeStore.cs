using Microsoft.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.Data.SqlClient;
using System.Data;
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
            db.Database.SetCommandTimeout(180);
            db.Database.EnsureCreated();
            EnsureAppUserColumns(db);
            EnsureProjectColumns(db);
            EnsureGroupColumns(db);
            EnsureUserRolesTable(db);
            EnsureQueryIndexes(db);
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
                x.PasswordHash,
                x.ExternalIssuer,
                x.ExternalSubject,
                x.IsDisabled))
            .ToList();
    }

    public IReadOnlyList<StoredProjectRow> LoadProjects()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.Projects
            .AsNoTracking()
            .OrderBy(x => x.Code)
            .Select(x => new StoredProjectRow(
                x.ProjectId,
                x.Code,
                x.Name,
                x.Description,
                x.ProjectOwnerName,
                x.ProjectEmail,
                x.ProjectPhone,
                x.ProjectOwner,
                x.Department))
            .ToList();
    }

    public IReadOnlyList<StoredUserRoleRow> LoadUserRoles()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.UserRoles
            .AsNoTracking()
            .OrderBy(x => x.UserId)
            .ThenBy(x => x.Role)
            .Select(x => new StoredUserRoleRow(x.UserId, (AppRole)x.Role))
            .ToList();
    }

    public IReadOnlyList<StoredGroupRow> LoadGroups()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        return db.Groups
            .AsNoTracking()
            .OrderBy(x => x.Name)
            .Select(x => new StoredGroupRow(x.GroupId, x.Name, x.Description))
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

    public StorePagedResult<StoredProjectRow> QueryProjects(StoreListQuery query, IReadOnlyCollection<Guid>? visibleProjectIds = null)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();

        IQueryable<ProjectEntity> baseQuery = db.Projects.AsNoTracking();

        var filter = query.FilterText?.Trim();
        if (!string.IsNullOrWhiteSpace(filter))
        {
            var pattern = $"%{EscapeLikeLikePattern(filter)}%";
            baseQuery = baseQuery.Where(x =>
                EF.Functions.Like(x.Name, pattern, "\\") ||
                EF.Functions.Like(x.Description, pattern, "\\"));
        }

        if (visibleProjectIds is not null)
        {
            if (visibleProjectIds.Count == 0)
            {
                return new StorePagedResult<StoredProjectRow>(Array.Empty<StoredProjectRow>(), 0);
            }

            baseQuery = baseQuery.Where(x => visibleProjectIds.Contains(x.ProjectId));
        }

        var totalCount = baseQuery.Count();
        var sorted = ApplyProjectSort(baseQuery, query.SortField, query.SortDescending);

        var items = sorted
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .Select(x => new StoredProjectRow(
                x.ProjectId,
                x.Code,
                x.Name,
                x.Description,
                x.ProjectOwnerName,
                x.ProjectEmail,
                x.ProjectPhone,
                x.ProjectOwner,
                x.Department))
            .ToList();

        return new StorePagedResult<StoredProjectRow>(items, totalCount);
    }

    public StorePagedResult<StoredUserRow> QueryUsers(StoreListQuery query)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();

        IQueryable<AppUserEntity> baseQuery = db.AppUsers.AsNoTracking();

        var filter = query.FilterText?.Trim();
        if (!string.IsNullOrWhiteSpace(filter))
        {
            var pattern = $"%{EscapeLikeLikePattern(filter)}%";
            baseQuery = baseQuery.Where(x =>
                EF.Functions.Like(x.Username, pattern, "\\") ||
                EF.Functions.Like(x.DisplayName, pattern, "\\"));
        }

        var totalCount = baseQuery.Count();
        var sorted = ApplyUserSort(baseQuery, query.SortField, query.SortDescending);

        var items = sorted
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .Select(x => new StoredUserRow(
                x.UserId,
                x.Username,
                x.DisplayName,
                (AppRole)x.Role,
                x.IsLocalAccount,
                x.PasswordHash,
                x.ExternalIssuer,
                x.ExternalSubject,
                x.IsDisabled))
            .ToList();

        return new StorePagedResult<StoredUserRow>(items, totalCount);
    }

    public StorePagedResult<StoredGroupRow> QueryGroups(StoreListQuery query)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();

        IQueryable<GroupEntity> baseQuery = db.Groups.AsNoTracking();

        var filter = query.FilterText?.Trim();
        if (!string.IsNullOrWhiteSpace(filter))
        {
            var pattern = $"%{EscapeLikeLikePattern(filter)}%";
            baseQuery = baseQuery.Where(x =>
                EF.Functions.Like(x.Name, pattern, "\\") ||
                EF.Functions.Like(x.Description, pattern, "\\"));
        }

        var totalCount = baseQuery.Count();
        var sorted = ApplyGroupSort(baseQuery, query.SortField, query.SortDescending);

        var items = sorted
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .Select(x => new StoredGroupRow(x.GroupId, x.Name, x.Description))
            .ToList();

        return new StorePagedResult<StoredGroupRow>(items, totalCount);
    }

    public StorePagedResult<StoredGroupAccessRow> QueryProjectGroups(Guid projectId, StoreListQuery query)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();

        var baseQuery = db.Groups
            .AsNoTracking()
            .Select(g => new
            {
                g.GroupId,
                g.Name,
                g.Description,
                IsAssigned = db.ProjectGroups.Any(pg => pg.ProjectId == projectId && pg.GroupId == g.GroupId)
            });

        var filter = query.FilterText?.Trim();
        if (!string.IsNullOrWhiteSpace(filter))
        {
            var pattern = $"%{EscapeLikeLikePattern(filter)}%";
            baseQuery = baseQuery.Where(x =>
                EF.Functions.Like(x.Name, pattern, "\\") ||
                EF.Functions.Like(x.Description, pattern, "\\"));
        }

        if (query.Assigned.HasValue)
        {
            baseQuery = baseQuery.Where(x => x.IsAssigned == query.Assigned.Value);
        }

        var totalCount = baseQuery.Count();
        var sorted = (query.SortField ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "assigned" or "isassigned" or "is_assigned" => query.SortDescending
                ? baseQuery.OrderByDescending(x => x.IsAssigned).ThenBy(x => x.GroupId)
                : baseQuery.OrderBy(x => x.IsAssigned).ThenBy(x => x.GroupId),
            _ => query.SortDescending
                ? baseQuery.OrderByDescending(x => x.Name).ThenBy(x => x.GroupId)
                : baseQuery.OrderBy(x => x.Name).ThenBy(x => x.GroupId)
        };

        var items = sorted
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .Select(x => new StoredGroupAccessRow(x.GroupId, x.Name, x.Description, x.IsAssigned))
            .ToList();

        return new StorePagedResult<StoredGroupAccessRow>(items, totalCount);
    }

    public StorePagedResult<StoredGroupAccessRow> QueryUserGroups(Guid userId, StoreListQuery query)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();

        var baseQuery = db.Groups
            .AsNoTracking()
            .Select(g => new
            {
                g.GroupId,
                g.Name,
                g.Description,
                IsAssigned = db.UserGroups.Any(ug => ug.UserId == userId && ug.GroupId == g.GroupId)
            });

        var filter = query.FilterText?.Trim();
        if (!string.IsNullOrWhiteSpace(filter))
        {
            var pattern = $"%{EscapeLikeLikePattern(filter)}%";
            baseQuery = baseQuery.Where(x =>
                EF.Functions.Like(x.Name, pattern, "\\") ||
                EF.Functions.Like(x.Description, pattern, "\\"));
        }

        if (query.Assigned.HasValue)
        {
            baseQuery = baseQuery.Where(x => x.IsAssigned == query.Assigned.Value);
        }

        var totalCount = baseQuery.Count();
        var sorted = (query.SortField ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "assigned" or "isassigned" or "is_assigned" => query.SortDescending
                ? baseQuery.OrderByDescending(x => x.IsAssigned).ThenBy(x => x.GroupId)
                : baseQuery.OrderBy(x => x.IsAssigned).ThenBy(x => x.GroupId),
            _ => query.SortDescending
                ? baseQuery.OrderByDescending(x => x.Name).ThenBy(x => x.GroupId)
                : baseQuery.OrderBy(x => x.Name).ThenBy(x => x.GroupId)
        };

        var items = sorted
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .Select(x => new StoredGroupAccessRow(x.GroupId, x.Name, x.Description, x.IsAssigned))
            .ToList();

        return new StorePagedResult<StoredGroupAccessRow>(items, totalCount);
    }

    public IReadOnlyList<StoredProjectGroupNameRow> LoadProjectGroupNamesForProjects(IReadOnlyCollection<Guid> projectIds)
    {
        Initialize();
        if (projectIds.Count == 0)
        {
            return Array.Empty<StoredProjectGroupNameRow>();
        }

        using var db = _dbFactory.CreateDbContext();
        var memberships = db.ProjectGroups
            .AsNoTracking()
            .Where(x => projectIds.Contains(x.ProjectId))
            .Select(x => new { x.ProjectId, x.GroupId })
            .ToList();

        var groupIds = memberships
            .Select(x => x.GroupId)
            .Distinct()
            .ToList();

        var groupNames = db.Groups
            .AsNoTracking()
            .Where(x => groupIds.Contains(x.GroupId))
            .Select(x => new { x.GroupId, x.Name })
            .ToDictionary(x => x.GroupId, x => x.Name);

        return memberships
            .Where(x => groupNames.ContainsKey(x.GroupId))
            .Select(x => new StoredProjectGroupNameRow(x.ProjectId, groupNames[x.GroupId]))
            .OrderBy(x => x.ProjectId)
            .ThenBy(x => x.GroupName)
            .ToList();
    }

    public IReadOnlyList<StoredUserGroupNameRow> LoadUserGroupNamesForUsers(IReadOnlyCollection<Guid> userIds)
    {
        Initialize();
        if (userIds.Count == 0)
        {
            return Array.Empty<StoredUserGroupNameRow>();
        }

        using var db = _dbFactory.CreateDbContext();
        var memberships = db.UserGroups
            .AsNoTracking()
            .Where(x => userIds.Contains(x.UserId))
            .Select(x => new { x.UserId, x.GroupId })
            .ToList();

        var groupIds = memberships
            .Select(x => x.GroupId)
            .Distinct()
            .ToList();

        var groupNames = db.Groups
            .AsNoTracking()
            .Where(x => groupIds.Contains(x.GroupId))
            .Select(x => new { x.GroupId, x.Name })
            .ToDictionary(x => x.GroupId, x => x.Name);

        return memberships
            .Where(x => groupNames.ContainsKey(x.GroupId))
            .Select(x => new StoredUserGroupNameRow(x.UserId, groupNames[x.GroupId]))
            .OrderBy(x => x.UserId)
            .ThenBy(x => x.GroupName)
            .ToList();
    }

    public IReadOnlyList<StoredUserRoleRow> LoadUserRolesForUsers(IReadOnlyCollection<Guid> userIds)
    {
        Initialize();
        if (userIds.Count == 0)
        {
            return Array.Empty<StoredUserRoleRow>();
        }

        using var db = _dbFactory.CreateDbContext();
        return db.UserRoles
            .AsNoTracking()
            .Where(x => userIds.Contains(x.UserId))
            .OrderBy(x => x.UserId)
            .ThenBy(x => x.Role)
            .Select(x => new StoredUserRoleRow(x.UserId, (AppRole)x.Role))
            .ToList();
    }

    public IReadOnlyList<StoredGroupMemberNameRow> LoadGroupMemberNames(IReadOnlyCollection<Guid> groupIds)
    {
        Initialize();
        if (groupIds.Count == 0)
        {
            return Array.Empty<StoredGroupMemberNameRow>();
        }

        using var db = _dbFactory.CreateDbContext();
        var memberships = db.UserGroups
            .AsNoTracking()
            .Where(x => groupIds.Contains(x.GroupId))
            .Select(x => new { x.GroupId, x.UserId })
            .ToList();

        var userIds = memberships
            .Select(x => x.UserId)
            .Distinct()
            .ToList();

        var userNames = db.AppUsers
            .AsNoTracking()
            .Where(x => userIds.Contains(x.UserId))
            .Select(x => new { x.UserId, x.DisplayName })
            .ToDictionary(x => x.UserId, x => x.DisplayName);

        return memberships
            .Where(x => userNames.ContainsKey(x.UserId))
            .Select(x => new StoredGroupMemberNameRow(x.GroupId, userNames[x.UserId]))
            .OrderBy(x => x.GroupId)
            .ThenBy(x => x.DisplayName)
            .ToList();
    }

    public IReadOnlyList<StoredGroupProjectCodeRow> LoadGroupProjectCodes(IReadOnlyCollection<Guid> groupIds)
    {
        Initialize();
        if (groupIds.Count == 0)
        {
            return Array.Empty<StoredGroupProjectCodeRow>();
        }

        using var db = _dbFactory.CreateDbContext();
        var mappings = db.ProjectGroups
            .AsNoTracking()
            .Where(x => groupIds.Contains(x.GroupId))
            .Select(x => new { x.GroupId, x.ProjectId })
            .ToList();

        var projectIds = mappings
            .Select(x => x.ProjectId)
            .Distinct()
            .ToList();

        var projectCodes = db.Projects
            .AsNoTracking()
            .Where(x => projectIds.Contains(x.ProjectId))
            .Select(x => new { x.ProjectId, x.Code })
            .ToDictionary(x => x.ProjectId, x => x.Code);

        return mappings
            .Where(x => projectCodes.ContainsKey(x.ProjectId))
            .Select(x => new StoredGroupProjectCodeRow(x.GroupId, projectCodes[x.ProjectId]))
            .OrderBy(x => x.GroupId)
            .ThenBy(x => x.ProjectCode)
            .ToList();
    }

    public IReadOnlyList<JournalEntryRecord> LoadJournalEntries()
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        db.Database.SetCommandTimeout(180);
        var entities = db.JournalEntries
            .AsNoTracking()
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
        db.Database.SetCommandTimeout(180);
        return db.AuditLogs
            .AsNoTracking()
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
        entity.ProjectOwnerName = project.ProjectOwnerName;
        entity.ProjectEmail = project.ProjectEmail;
        entity.ProjectPhone = project.ProjectPhone;
        entity.ProjectOwner = project.ProjectOwner;
        entity.Department = project.Department;
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
        entity.Description = group.Description;
        db.SaveChanges();
    }

    public void RemoveGroup(Guid groupId)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();

        var userMemberships = db.UserGroups.Where(x => x.GroupId == groupId).ToList();
        if (userMemberships.Count > 0)
        {
            db.UserGroups.RemoveRange(userMemberships);
        }

        var projectMemberships = db.ProjectGroups.Where(x => x.GroupId == groupId).ToList();
        if (projectMemberships.Count > 0)
        {
            db.ProjectGroups.RemoveRange(projectMemberships);
        }

        var group = db.Groups.SingleOrDefault(x => x.GroupId == groupId);
        if (group is not null)
        {
            db.Groups.Remove(group);
        }

        db.SaveChanges();
    }

    public void RemoveUser(Guid userId)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();

        var userMemberships = db.UserGroups.Where(x => x.UserId == userId).ToList();
        if (userMemberships.Count > 0)
        {
            db.UserGroups.RemoveRange(userMemberships);
        }

        var roleMemberships = db.UserRoles.Where(x => x.UserId == userId).ToList();
        if (roleMemberships.Count > 0)
        {
            db.UserRoles.RemoveRange(roleMemberships);
        }

        var user = db.AppUsers.SingleOrDefault(x => x.UserId == userId);
        if (user is not null)
        {
            db.AppUsers.Remove(user);
        }

        db.SaveChanges();
    }

    public void AddUserRole(Guid userId, AppRole role)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var roleValue = (int)role;
        var exists = db.UserRoles.Any(x => x.UserId == userId && x.Role == roleValue);
        if (!exists)
        {
            db.UserRoles.Add(new UserRoleEntity { UserId = userId, Role = roleValue });
            db.SaveChanges();
        }
    }

    public void RemoveUserRole(Guid userId, AppRole role)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var roleValue = (int)role;
        var membership = db.UserRoles.SingleOrDefault(x => x.UserId == userId && x.Role == roleValue);
        if (membership is not null)
        {
            db.UserRoles.Remove(membership);
            db.SaveChanges();
        }
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

    public void RemoveUserFromGroup(Guid userId, Guid groupId)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var membership = db.UserGroups.SingleOrDefault(x => x.UserId == userId && x.GroupId == groupId);
        if (membership is not null)
        {
            db.UserGroups.Remove(membership);
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

    public void RemoveGroupFromProject(Guid projectId, Guid groupId)
    {
        Initialize();
        using var db = _dbFactory.CreateDbContext();
        var membership = db.ProjectGroups.SingleOrDefault(x => x.ProjectId == projectId && x.GroupId == groupId);
        if (membership is not null)
        {
            db.ProjectGroups.Remove(membership);
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
            entity.IsDisabled = user.IsDisabled;
            entity.PasswordHash = user.PasswordHash;
            entity.ExternalIssuer = user.ExternalIssuer;
            entity.ExternalSubject = user.ExternalSubject;
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

    private static IOrderedQueryable<ProjectEntity> ApplyProjectSort(IQueryable<ProjectEntity> query, string? sortField, bool descending)
        => (sortField ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "name" => descending
                ? query.OrderByDescending(x => x.Name).ThenBy(x => x.ProjectId)
                : query.OrderBy(x => x.Name).ThenBy(x => x.ProjectId),
            "projectownername" or "project_owner_name" => descending
                ? query.OrderByDescending(x => x.ProjectOwnerName).ThenBy(x => x.ProjectId)
                : query.OrderBy(x => x.ProjectOwnerName).ThenBy(x => x.ProjectId),
            "projectemail" or "project_email" => descending
                ? query.OrderByDescending(x => x.ProjectEmail).ThenBy(x => x.ProjectId)
                : query.OrderBy(x => x.ProjectEmail).ThenBy(x => x.ProjectId),
            "projectphone" or "project_phone" => descending
                ? query.OrderByDescending(x => x.ProjectPhone).ThenBy(x => x.ProjectId)
                : query.OrderBy(x => x.ProjectPhone).ThenBy(x => x.ProjectId),
            "projectowner" or "project_owner" => descending
                ? query.OrderByDescending(x => x.ProjectOwner).ThenBy(x => x.ProjectId)
                : query.OrderBy(x => x.ProjectOwner).ThenBy(x => x.ProjectId),
            "department" => descending
                ? query.OrderByDescending(x => x.Department).ThenBy(x => x.ProjectId)
                : query.OrderBy(x => x.Department).ThenBy(x => x.ProjectId),
            _ => descending
                ? query.OrderByDescending(x => x.Code).ThenBy(x => x.ProjectId)
                : query.OrderBy(x => x.Code).ThenBy(x => x.ProjectId)
        };

    private static IOrderedQueryable<AppUserEntity> ApplyUserSort(IQueryable<AppUserEntity> query, string? sortField, bool descending)
        => (sortField ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "displayname" or "display_name" => descending
                ? query.OrderByDescending(x => x.DisplayName).ThenBy(x => x.UserId)
                : query.OrderBy(x => x.DisplayName).ThenBy(x => x.UserId),
            _ => descending
                ? query.OrderByDescending(x => x.Username).ThenBy(x => x.UserId)
                : query.OrderBy(x => x.Username).ThenBy(x => x.UserId)
        };

    private static IOrderedQueryable<GroupEntity> ApplyGroupSort(IQueryable<GroupEntity> query, string? sortField, bool descending)
        => (sortField ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "description" => descending
                ? query.OrderByDescending(x => x.Description).ThenBy(x => x.GroupId)
                : query.OrderBy(x => x.Description).ThenBy(x => x.GroupId),
            _ => descending
                ? query.OrderByDescending(x => x.Name).ThenBy(x => x.GroupId)
                : query.OrderBy(x => x.Name).ThenBy(x => x.GroupId)
        };

    private static IOrderedQueryable<StoredGroupAccessRow> ApplyGroupAccessSort(IQueryable<StoredGroupAccessRow> query, string? sortField, bool descending)
        => (sortField ?? string.Empty).Trim().ToLowerInvariant() switch
        {
            "assigned" or "isassigned" or "is_assigned" => descending
                ? query.OrderByDescending(x => x.IsAssigned).ThenBy(x => x.GroupId)
                : query.OrderBy(x => x.IsAssigned).ThenBy(x => x.GroupId),
            _ => descending
                ? query.OrderByDescending(x => x.Name).ThenBy(x => x.GroupId)
                : query.OrderBy(x => x.Name).ThenBy(x => x.GroupId)
        };

    private static string EscapeLikeLikePattern(string value)
        => value
            .Replace(@"\", @"\\", StringComparison.Ordinal)
            .Replace("%", @"\%", StringComparison.Ordinal)
            .Replace("_", @"\_", StringComparison.Ordinal);

    private static bool IsUniqueUsernameViolation(DbUpdateException ex)
        => (ex.InnerException is SqliteException sqlite
            && sqlite.SqliteErrorCode == 19
            && sqlite.Message.Contains("app_users.username", StringComparison.OrdinalIgnoreCase))
           || (ex.InnerException is SqlException sql
               && (sql.Number == 2601 || sql.Number == 2627)
               && sql.Message.Contains("app_users", StringComparison.OrdinalIgnoreCase)
               && sql.Message.Contains("username", StringComparison.OrdinalIgnoreCase));

    private static void EnsureAppUserColumns(SecureJournalAppDbContext db)
    {
        var provider = db.Database.ProviderName ?? string.Empty;
        if (provider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                IF COL_LENGTH('app_users', 'external_issuer') IS NULL
                    ALTER TABLE app_users ADD external_issuer nvarchar(512) NULL;
                IF COL_LENGTH('app_users', 'external_subject') IS NULL
                    ALTER TABLE app_users ADD external_subject nvarchar(512) NULL;
                IF COL_LENGTH('app_users', 'is_disabled') IS NULL
                    ALTER TABLE app_users ADD is_disabled bit NOT NULL CONSTRAINT DF_app_users_is_disabled DEFAULT (0);
                """);
            return;
        }

        if (provider.Contains("Npgsql", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                ALTER TABLE app_users ADD COLUMN IF NOT EXISTS external_issuer varchar(512) NULL;
                ALTER TABLE app_users ADD COLUMN IF NOT EXISTS external_subject varchar(512) NULL;
                ALTER TABLE app_users ADD COLUMN IF NOT EXISTS is_disabled boolean NOT NULL DEFAULT false;
                """);
            return;
        }

        if (provider.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
        {
            var connection = db.Database.GetDbConnection();
            var shouldClose = connection.State != ConnectionState.Open;
            if (shouldClose)
            {
                connection.Open();
            }

            try
            {
                var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using (var pragma = connection.CreateCommand())
                {
                    pragma.CommandText = "PRAGMA table_info(app_users);";
                    using var reader = pragma.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader["name"] is string name && !string.IsNullOrWhiteSpace(name))
                        {
                            columns.Add(name);
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

                if (!columns.Contains("is_disabled"))
                {
                    using var cmd = connection.CreateCommand();
                    cmd.CommandText = "ALTER TABLE app_users ADD COLUMN is_disabled INTEGER NOT NULL DEFAULT 0;";
                    cmd.ExecuteNonQuery();
                }
            }
            finally
            {
                if (shouldClose)
                {
                    connection.Close();
                }
            }
        }
    }

    private static void EnsureProjectColumns(SecureJournalAppDbContext db)
    {
        var provider = db.Database.ProviderName ?? string.Empty;
        if (provider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                IF COL_LENGTH('projects', 'project_owner_name') IS NULL
                    ALTER TABLE projects ADD project_owner_name nvarchar(100) NOT NULL CONSTRAINT DF_projects_project_owner_name DEFAULT ('');
                IF COL_LENGTH('projects', 'project_email') IS NULL
                    ALTER TABLE projects ADD project_email nvarchar(254) NOT NULL CONSTRAINT DF_projects_project_email DEFAULT ('');
                IF COL_LENGTH('projects', 'project_phone') IS NULL
                    ALTER TABLE projects ADD project_phone nvarchar(32) NOT NULL CONSTRAINT DF_projects_project_phone DEFAULT ('');
                IF COL_LENGTH('projects', 'project_owner') IS NULL
                    ALTER TABLE projects ADD project_owner nvarchar(100) NOT NULL CONSTRAINT DF_projects_project_owner DEFAULT ('');
                IF COL_LENGTH('projects', 'department') IS NULL
                    ALTER TABLE projects ADD department nvarchar(100) NOT NULL CONSTRAINT DF_projects_department DEFAULT ('');
                """);
            return;
        }

        if (provider.Contains("Npgsql", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                ALTER TABLE projects ADD COLUMN IF NOT EXISTS project_owner_name varchar(100) NOT NULL DEFAULT '';
                ALTER TABLE projects ADD COLUMN IF NOT EXISTS project_email varchar(254) NOT NULL DEFAULT '';
                ALTER TABLE projects ADD COLUMN IF NOT EXISTS project_phone varchar(32) NOT NULL DEFAULT '';
                ALTER TABLE projects ADD COLUMN IF NOT EXISTS project_owner varchar(100) NOT NULL DEFAULT '';
                ALTER TABLE projects ADD COLUMN IF NOT EXISTS department varchar(100) NOT NULL DEFAULT '';
                """);
            return;
        }

        if (provider.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
        {
            var connection = db.Database.GetDbConnection();
            var shouldClose = connection.State != ConnectionState.Open;
            if (shouldClose)
            {
                connection.Open();
            }

            try
            {
                var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using (var pragma = connection.CreateCommand())
                {
                    pragma.CommandText = "PRAGMA table_info(projects);";
                    using var reader = pragma.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader["name"] is string name && !string.IsNullOrWhiteSpace(name))
                        {
                            columns.Add(name);
                        }
                    }
                }

                if (!columns.Contains("project_owner_name"))
                {
                    using var cmd = connection.CreateCommand();
                    cmd.CommandText = "ALTER TABLE projects ADD COLUMN project_owner_name TEXT NOT NULL DEFAULT '';";
                    cmd.ExecuteNonQuery();
                }

                if (!columns.Contains("project_email"))
                {
                    using var cmd = connection.CreateCommand();
                    cmd.CommandText = "ALTER TABLE projects ADD COLUMN project_email TEXT NOT NULL DEFAULT '';";
                    cmd.ExecuteNonQuery();
                }

                if (!columns.Contains("project_phone"))
                {
                    using var cmd = connection.CreateCommand();
                    cmd.CommandText = "ALTER TABLE projects ADD COLUMN project_phone TEXT NOT NULL DEFAULT '';";
                    cmd.ExecuteNonQuery();
                }

                if (!columns.Contains("project_owner"))
                {
                    using var cmd = connection.CreateCommand();
                    cmd.CommandText = "ALTER TABLE projects ADD COLUMN project_owner TEXT NOT NULL DEFAULT '';";
                    cmd.ExecuteNonQuery();
                }

                if (!columns.Contains("department"))
                {
                    using var cmd = connection.CreateCommand();
                    cmd.CommandText = "ALTER TABLE projects ADD COLUMN department TEXT NOT NULL DEFAULT '';";
                    cmd.ExecuteNonQuery();
                }
            }
            finally
            {
                if (shouldClose)
                {
                    connection.Close();
                }
            }
        }
    }

    private static void EnsureGroupColumns(SecureJournalAppDbContext db)
    {
        var provider = db.Database.ProviderName ?? string.Empty;
        if (provider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                IF COL_LENGTH('groups_ref', 'description') IS NULL
                    ALTER TABLE groups_ref ADD description nvarchar(500) NOT NULL CONSTRAINT DF_groups_ref_description DEFAULT ('');
                """);
            return;
        }

        if (provider.Contains("Npgsql", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                ALTER TABLE groups_ref ADD COLUMN IF NOT EXISTS description varchar(500) NOT NULL DEFAULT '';
                """);
            return;
        }

        if (provider.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
        {
            var connection = db.Database.GetDbConnection();
            var shouldClose = connection.State != ConnectionState.Open;
            if (shouldClose)
            {
                connection.Open();
            }

            try
            {
                var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                using (var pragma = connection.CreateCommand())
                {
                    pragma.CommandText = "PRAGMA table_info(groups_ref);";
                    using var reader = pragma.ExecuteReader();
                    while (reader.Read())
                    {
                        if (reader["name"] is string name && !string.IsNullOrWhiteSpace(name))
                        {
                            columns.Add(name);
                        }
                    }
                }

                if (!columns.Contains("description"))
                {
                    using var cmd = connection.CreateCommand();
                    cmd.CommandText = "ALTER TABLE groups_ref ADD COLUMN description TEXT NOT NULL DEFAULT '';";
                    cmd.ExecuteNonQuery();
                }
            }
            finally
            {
                if (shouldClose)
                {
                    connection.Close();
                }
            }
        }
    }

    private static void EnsureQueryIndexes(SecureJournalAppDbContext db)
    {
        var provider = db.Database.ProviderName ?? string.Empty;
        if (provider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_projects_name' AND object_id = OBJECT_ID('projects'))
                    CREATE INDEX IX_projects_name ON projects(name);
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_projects_description' AND object_id = OBJECT_ID('projects'))
                    CREATE INDEX IX_projects_description ON projects(description);
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_app_users_display_name' AND object_id = OBJECT_ID('app_users'))
                    CREATE INDEX IX_app_users_display_name ON app_users(display_name);
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_groups_ref_description' AND object_id = OBJECT_ID('groups_ref'))
                    CREATE INDEX IX_groups_ref_description ON groups_ref(description);
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_user_groups_group_id' AND object_id = OBJECT_ID('user_groups'))
                    CREATE INDEX IX_user_groups_group_id ON user_groups(group_id);
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_project_groups_group_id' AND object_id = OBJECT_ID('project_groups'))
                    CREATE INDEX IX_project_groups_group_id ON project_groups(group_id);
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_journal_entries_created_at_utc' AND object_id = OBJECT_ID('journal_entries'))
                    CREATE INDEX IX_journal_entries_created_at_utc ON journal_entries(created_at_utc);
                IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_audit_logs_timestamp_utc' AND object_id = OBJECT_ID('audit_logs'))
                    CREATE INDEX IX_audit_logs_timestamp_utc ON audit_logs(timestamp_utc);
                """);
            return;
        }

        if (provider.Contains("Npgsql", StringComparison.OrdinalIgnoreCase) ||
            provider.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw("CREATE INDEX IF NOT EXISTS ix_projects_name ON projects(name);");
            db.Database.ExecuteSqlRaw("CREATE INDEX IF NOT EXISTS ix_projects_description ON projects(description);");
            db.Database.ExecuteSqlRaw("CREATE INDEX IF NOT EXISTS ix_app_users_display_name ON app_users(display_name);");
            db.Database.ExecuteSqlRaw("CREATE INDEX IF NOT EXISTS ix_groups_ref_description ON groups_ref(description);");
            db.Database.ExecuteSqlRaw("CREATE INDEX IF NOT EXISTS ix_user_groups_group_id ON user_groups(group_id);");
            db.Database.ExecuteSqlRaw("CREATE INDEX IF NOT EXISTS ix_project_groups_group_id ON project_groups(group_id);");
            db.Database.ExecuteSqlRaw("CREATE INDEX IF NOT EXISTS ix_journal_entries_created_at_utc ON journal_entries(created_at_utc);");
            db.Database.ExecuteSqlRaw("CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp_utc ON audit_logs(timestamp_utc);");
        }
    }

    private static void EnsureUserRolesTable(SecureJournalAppDbContext db)
    {
        var provider = db.Database.ProviderName ?? string.Empty;
        if (provider.Contains("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                IF OBJECT_ID('user_roles', 'U') IS NULL
                BEGIN
                    CREATE TABLE user_roles (
                        user_id uniqueidentifier NOT NULL,
                        role int NOT NULL,
                        CONSTRAINT PK_user_roles PRIMARY KEY (user_id, role)
                    );
                END
                """);
            return;
        }

        if (provider.Contains("Npgsql", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id uuid NOT NULL,
                    role integer NOT NULL,
                    PRIMARY KEY (user_id, role)
                );
                """);
            return;
        }

        if (provider.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
        {
            db.Database.ExecuteSqlRaw(
                """
                CREATE TABLE IF NOT EXISTS user_roles (
                    user_id TEXT NOT NULL,
                    role INTEGER NOT NULL,
                    PRIMARY KEY (user_id, role)
                );
                """);
        }
    }
}
