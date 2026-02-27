using Microsoft.EntityFrameworkCore;

namespace SecureJournal.Web.Infrastructure.Persistence;

public sealed class SecureJournalAppDbContext : DbContext
{
    public SecureJournalAppDbContext(DbContextOptions<SecureJournalAppDbContext> options)
        : base(options)
    {
    }

    public DbSet<AppUserEntity> AppUsers => Set<AppUserEntity>();
    public DbSet<ProjectEntity> Projects => Set<ProjectEntity>();
    public DbSet<GroupEntity> Groups => Set<GroupEntity>();
    public DbSet<UserRoleEntity> UserRoles => Set<UserRoleEntity>();
    public DbSet<UserGroupEntity> UserGroups => Set<UserGroupEntity>();
    public DbSet<ProjectGroupEntity> ProjectGroups => Set<ProjectGroupEntity>();
    public DbSet<JournalEntryEntity> JournalEntries => Set<JournalEntryEntity>();
    public DbSet<AuditLogEntity> AuditLogs => Set<AuditLogEntity>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<AppUserEntity>(entity =>
        {
            entity.ToTable("app_users");
            entity.HasKey(x => x.UserId);
            entity.Property(x => x.UserId).HasColumnName("user_id");
            entity.Property(x => x.Username).HasColumnName("username").HasMaxLength(100).IsRequired();
            entity.Property(x => x.DisplayName).HasColumnName("display_name").HasMaxLength(100).IsRequired();
            entity.Property(x => x.Role).HasColumnName("role").IsRequired();
            entity.Property(x => x.IsLocalAccount).HasColumnName("is_local_account").IsRequired();
            entity.Property(x => x.PasswordHash).HasColumnName("password_hash");
            entity.Property(x => x.ExternalIssuer).HasColumnName("external_issuer").HasMaxLength(512);
            entity.Property(x => x.ExternalSubject).HasColumnName("external_subject").HasMaxLength(512);
            entity.HasIndex(x => x.Username).IsUnique();
            entity.HasIndex(x => new { x.ExternalIssuer, x.ExternalSubject });
        });

        builder.Entity<ProjectEntity>(entity =>
        {
            entity.ToTable("projects");
            entity.HasKey(x => x.ProjectId);
            entity.Property(x => x.ProjectId).HasColumnName("project_id");
            entity.Property(x => x.Code).HasColumnName("code").HasMaxLength(20).IsRequired();
            entity.Property(x => x.Name).HasColumnName("name").HasMaxLength(100).IsRequired();
            entity.Property(x => x.Description).HasColumnName("description").HasMaxLength(500).IsRequired();
            entity.HasIndex(x => x.Code).IsUnique();
        });

        builder.Entity<GroupEntity>(entity =>
        {
            entity.ToTable("groups_ref");
            entity.HasKey(x => x.GroupId);
            entity.Property(x => x.GroupId).HasColumnName("group_id");
            entity.Property(x => x.Name).HasColumnName("name").HasMaxLength(100).IsRequired();
            entity.HasIndex(x => x.Name).IsUnique();
        });

        builder.Entity<UserGroupEntity>(entity =>
        {
            entity.ToTable("user_groups");
            entity.HasKey(x => new { x.UserId, x.GroupId });
            entity.Property(x => x.UserId).HasColumnName("user_id");
            entity.Property(x => x.GroupId).HasColumnName("group_id");
        });

        builder.Entity<UserRoleEntity>(entity =>
        {
            entity.ToTable("user_roles");
            entity.HasKey(x => new { x.UserId, x.Role });
            entity.Property(x => x.UserId).HasColumnName("user_id");
            entity.Property(x => x.Role).HasColumnName("role");
        });

        builder.Entity<ProjectGroupEntity>(entity =>
        {
            entity.ToTable("project_groups");
            entity.HasKey(x => new { x.ProjectId, x.GroupId });
            entity.Property(x => x.ProjectId).HasColumnName("project_id");
            entity.Property(x => x.GroupId).HasColumnName("group_id");
        });

        builder.Entity<JournalEntryEntity>(entity =>
        {
            entity.ToTable("journal_entries");
            entity.HasKey(x => x.RecordId);
            entity.Property(x => x.RecordId).HasColumnName("record_id");
            entity.Property(x => x.ProjectId).HasColumnName("project_id").IsRequired();
            entity.Property(x => x.CreatedAtUtc).HasColumnName("created_at_utc").IsRequired();
            entity.Property(x => x.CreatedByUserId).HasColumnName("created_by_user_id").IsRequired();
            entity.Property(x => x.CreatedByUsername).HasColumnName("created_by_username").IsRequired();
            entity.Property(x => x.CategoryCiphertext).HasColumnName("category_ciphertext").IsRequired();
            entity.Property(x => x.SubjectCiphertext).HasColumnName("subject_ciphertext").IsRequired();
            entity.Property(x => x.DescriptionCiphertext).HasColumnName("description_ciphertext").IsRequired();
            entity.Property(x => x.NotesCiphertext).HasColumnName("notes_ciphertext").IsRequired();
            entity.Property(x => x.ResultCiphertext).HasColumnName("result_ciphertext").IsRequired();
            entity.Property(x => x.CategoryChecksum).HasColumnName("category_checksum").IsRequired();
            entity.Property(x => x.SubjectChecksum).HasColumnName("subject_checksum").IsRequired();
            entity.Property(x => x.DescriptionChecksum).HasColumnName("description_checksum").IsRequired();
            entity.Property(x => x.NotesChecksum).HasColumnName("notes_checksum").IsRequired();
            entity.Property(x => x.ResultChecksum).HasColumnName("result_checksum").IsRequired();
            entity.Property(x => x.FullRecordChecksum).HasColumnName("full_record_checksum").IsRequired();
            entity.Property(x => x.IsSoftDeleted).HasColumnName("is_soft_deleted").IsRequired();
            entity.Property(x => x.DeletedAtUtc).HasColumnName("deleted_at_utc");
            entity.Property(x => x.DeletedByUserId).HasColumnName("deleted_by_user_id");
            entity.Property(x => x.DeletedByUsername).HasColumnName("deleted_by_username");
            entity.Property(x => x.DeleteReason).HasColumnName("delete_reason");
        });

        builder.Entity<AuditLogEntity>(entity =>
        {
            entity.ToTable("audit_logs");
            entity.HasKey(x => x.AuditId);
            entity.Property(x => x.AuditId).HasColumnName("audit_id");
            entity.Property(x => x.TimestampUtc).HasColumnName("timestamp_utc").IsRequired();
            entity.Property(x => x.ActorUserId).HasColumnName("actor_user_id");
            entity.Property(x => x.ActorUsername).HasColumnName("actor_username").IsRequired();
            entity.Property(x => x.Action).HasColumnName("action").IsRequired();
            entity.Property(x => x.EntityType).HasColumnName("entity_type").IsRequired();
            entity.Property(x => x.EntityId).HasColumnName("entity_id");
            entity.Property(x => x.ProjectId).HasColumnName("project_id");
            entity.Property(x => x.Outcome).HasColumnName("outcome").IsRequired();
            entity.Property(x => x.DetailsCiphertext).HasColumnName("details_ciphertext").IsRequired();
            entity.Property(x => x.DetailsChecksum).HasColumnName("details_checksum").IsRequired();
        });
    }
}

public sealed class AppUserEntity
{
    public Guid UserId { get; set; }
    public string Username { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public int Role { get; set; }
    public bool IsLocalAccount { get; set; }
    public string? PasswordHash { get; set; }
    public string? ExternalIssuer { get; set; }
    public string? ExternalSubject { get; set; }
}

public sealed class ProjectEntity
{
    public Guid ProjectId { get; set; }
    public string Code { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

public sealed class GroupEntity
{
    public Guid GroupId { get; set; }
    public string Name { get; set; } = string.Empty;
}

public sealed class UserGroupEntity
{
    public Guid UserId { get; set; }
    public Guid GroupId { get; set; }
}

public sealed class UserRoleEntity
{
    public Guid UserId { get; set; }
    public int Role { get; set; }
}

public sealed class ProjectGroupEntity
{
    public Guid ProjectId { get; set; }
    public Guid GroupId { get; set; }
}

public sealed class JournalEntryEntity
{
    public Guid RecordId { get; set; }
    public Guid ProjectId { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public Guid CreatedByUserId { get; set; }
    public string CreatedByUsername { get; set; } = string.Empty;
    public string CategoryCiphertext { get; set; } = string.Empty;
    public string SubjectCiphertext { get; set; } = string.Empty;
    public string DescriptionCiphertext { get; set; } = string.Empty;
    public string NotesCiphertext { get; set; } = string.Empty;
    public string ResultCiphertext { get; set; } = string.Empty;
    public string CategoryChecksum { get; set; } = string.Empty;
    public string SubjectChecksum { get; set; } = string.Empty;
    public string DescriptionChecksum { get; set; } = string.Empty;
    public string NotesChecksum { get; set; } = string.Empty;
    public string ResultChecksum { get; set; } = string.Empty;
    public string FullRecordChecksum { get; set; } = string.Empty;
    public bool IsSoftDeleted { get; set; }
    public DateTime? DeletedAtUtc { get; set; }
    public Guid? DeletedByUserId { get; set; }
    public string? DeletedByUsername { get; set; }
    public string? DeleteReason { get; set; }
}

public sealed class AuditLogEntity
{
    public Guid AuditId { get; set; }
    public DateTime TimestampUtc { get; set; }
    public Guid? ActorUserId { get; set; }
    public string ActorUsername { get; set; } = string.Empty;
    public int Action { get; set; }
    public int EntityType { get; set; }
    public string? EntityId { get; set; }
    public Guid? ProjectId { get; set; }
    public int Outcome { get; set; }
    public string DetailsCiphertext { get; set; } = string.Empty;
    public string DetailsChecksum { get; set; } = string.Empty;
}
