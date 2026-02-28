/*
    SecureJournal SQL Server high-volume test data seed script.

    Creates:
      - 200 users
      - 200 projects
      - 200 groups
      - journal entries for each project (10 to 100 per project)

    Notes:
      - Journal encrypted fields are set to empty payloads ("") so reads/decryption stay valid.
      - Use this for performance/load behavior testing, not for cryptographic checksum validation scenarios.

    Usage (sqlcmd example):
      sqlcmd -S <server>.database.windows.net -d <database> -G -i scripts/seed-load-testdata-sqlserver.sql
*/

SET NOCOUNT ON;
SET XACT_ABORT ON;

DECLARE @UserCount int = 200;
DECLARE @ProjectCount int = 200;
DECLARE @GroupCount int = 200;
DECLARE @MinEntriesPerProject int = 10;
DECLARE @MaxEntriesPerProject int = 100;

DECLARE @TimestampSuffix nvarchar(14) = REPLACE(REPLACE(REPLACE(CONVERT(varchar(19), SYSUTCDATETIME(), 120), '-', ''), ':', ''), ' ', '');
DECLARE @Prefix nvarchar(32) = CONCAT(N'load', @TimestampSuffix);

DECLARE @EmptySha256 char(64) = LOWER(CONVERT(char(64), HASHBYTES('SHA2_256', N''), 2));

BEGIN TRY
    BEGIN TRANSACTION;

    IF OBJECT_ID(N'dbo.app_users', N'U') IS NULL
        THROW 50001, 'Missing table dbo.app_users.', 1;
    IF OBJECT_ID(N'dbo.projects', N'U') IS NULL
        THROW 50001, 'Missing table dbo.projects.', 1;
    IF OBJECT_ID(N'dbo.groups_ref', N'U') IS NULL
        THROW 50001, 'Missing table dbo.groups_ref.', 1;
    IF OBJECT_ID(N'dbo.user_roles', N'U') IS NULL
        THROW 50001, 'Missing table dbo.user_roles.', 1;
    IF OBJECT_ID(N'dbo.user_groups', N'U') IS NULL
        THROW 50001, 'Missing table dbo.user_groups.', 1;
    IF OBJECT_ID(N'dbo.project_groups', N'U') IS NULL
        THROW 50001, 'Missing table dbo.project_groups.', 1;
    IF OBJECT_ID(N'dbo.journal_entries', N'U') IS NULL
        THROW 50001, 'Missing table dbo.journal_entries.', 1;

    DECLARE @Users TABLE
    (
        UserOrdinal int NOT NULL PRIMARY KEY,
        UserId uniqueidentifier NOT NULL,
        Username nvarchar(100) NOT NULL,
        DisplayName nvarchar(100) NOT NULL
    );

    DECLARE @Projects TABLE
    (
        ProjectOrdinal int NOT NULL PRIMARY KEY,
        ProjectId uniqueidentifier NOT NULL,
        Code nvarchar(20) NOT NULL,
        Name nvarchar(100) NOT NULL
    );

    DECLARE @Groups TABLE
    (
        GroupOrdinal int NOT NULL PRIMARY KEY,
        GroupId uniqueidentifier NOT NULL,
        Name nvarchar(100) NOT NULL
    );

    ;WITH seq AS
    (
        SELECT TOP (@UserCount) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n
        FROM sys.all_objects a
        CROSS JOIN sys.all_objects b
    )
    INSERT INTO @Users (UserOrdinal, UserId, Username, DisplayName)
    SELECT
        n,
        NEWID(),
        CONCAT(@Prefix, N'_u_', RIGHT(CONCAT('000', CAST(n AS varchar(3))), 3)),
        CONCAT(N'Load User ', n)
    FROM seq;

    INSERT INTO dbo.app_users (user_id, username, display_name, role, is_local_account, is_disabled, password_hash, external_issuer, external_subject)
    SELECT
        u.UserId,
        u.Username,
        u.DisplayName,
        2,
        0,
        0,
        NULL,
        NULL,
        NULL
    FROM @Users u;

    INSERT INTO dbo.user_roles (user_id, role)
    SELECT u.UserId, 2
    FROM @Users u;

    ;WITH seq AS
    (
        SELECT TOP (@ProjectCount) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n
        FROM sys.all_objects a
        CROSS JOIN sys.all_objects b
    )
    INSERT INTO @Projects (ProjectOrdinal, ProjectId, Code, Name)
    SELECT
        n,
        NEWID(),
        CONCAT(N'L', RIGHT(CONCAT('0000', CAST(n AS varchar(4))), 4), RIGHT(@TimestampSuffix, 3)),
        CONCAT(N'Load Project ', n)
    FROM seq;

    INSERT INTO dbo.projects (project_id, code, name, description)
    SELECT
        p.ProjectId,
        p.Code,
        p.Name,
        CONCAT(N'Generated load test project ', p.ProjectOrdinal, N' (', @Prefix, N')')
    FROM @Projects p;

    ;WITH seq AS
    (
        SELECT TOP (@GroupCount) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n
        FROM sys.all_objects a
        CROSS JOIN sys.all_objects b
    )
    INSERT INTO @Groups (GroupOrdinal, GroupId, Name)
    SELECT
        n,
        NEWID(),
        CONCAT(@Prefix, N'_g_', RIGHT(CONCAT('000', CAST(n AS varchar(3))), 3))
    FROM seq;

    INSERT INTO dbo.groups_ref (group_id, name)
    SELECT g.GroupId, g.Name
    FROM @Groups g;

    INSERT INTO dbo.user_groups (user_id, group_id)
    SELECT
        u.UserId,
        g.GroupId
    FROM @Users u
    INNER JOIN @Groups g
        ON g.GroupOrdinal = ((u.UserOrdinal - 1) % @GroupCount) + 1;

    INSERT INTO dbo.project_groups (project_id, group_id)
    SELECT
        p.ProjectId,
        g.GroupId
    FROM @Projects p
    INNER JOIN @Groups g
        ON g.GroupOrdinal IN
           (
               ((p.ProjectOrdinal - 1) % @GroupCount) + 1,
               ((p.ProjectOrdinal + 36 - 1) % @GroupCount) + 1,
               ((p.ProjectOrdinal + 91 - 1) % @GroupCount) + 1
           );

    DECLARE @ProjectEntryCounts TABLE
    (
        ProjectId uniqueidentifier NOT NULL PRIMARY KEY,
        EntryCount int NOT NULL
    );

    INSERT INTO @ProjectEntryCounts (ProjectId, EntryCount)
    SELECT
        p.ProjectId,
        @MinEntriesPerProject + (ABS(CHECKSUM(p.ProjectId)) % (@MaxEntriesPerProject - @MinEntriesPerProject + 1))
    FROM @Projects p;

    ;WITH entry_seq AS
    (
        SELECT TOP (@MaxEntriesPerProject) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n
        FROM sys.all_objects a
        CROSS JOIN sys.all_objects b
    )
    INSERT INTO dbo.journal_entries
    (
        record_id,
        project_id,
        created_at_utc,
        created_by_user_id,
        created_by_username,
        category_ciphertext,
        subject_ciphertext,
        description_ciphertext,
        notes_ciphertext,
        result_ciphertext,
        category_checksum,
        subject_checksum,
        description_checksum,
        notes_checksum,
        result_checksum,
        full_record_checksum,
        is_soft_deleted,
        deleted_at_utc,
        deleted_by_user_id,
        deleted_by_username,
        delete_reason
    )
    SELECT
        NEWID(),
        p.ProjectId,
        DATEADD(MINUTE, -((pec.EntryCount - es.n) * 3 + (ABS(CHECKSUM(p.ProjectId, es.n)) % 3)), SYSUTCDATETIME()),
        u.UserId,
        u.Username,
        N'',
        N'',
        N'',
        N'',
        N'',
        @EmptySha256,
        @EmptySha256,
        @EmptySha256,
        @EmptySha256,
        @EmptySha256,
        LOWER(CONVERT(char(64), HASHBYTES('SHA2_256', CONCAT(
            CONVERT(varchar(36), p.ProjectId), NCHAR(31),
            CONVERT(varchar(36), u.UserId), NCHAR(31),
            CONVERT(varchar(33), DATEADD(MINUTE, -((pec.EntryCount - es.n) * 3 + (ABS(CHECKSUM(p.ProjectId, es.n)) % 3)), SYSUTCDATETIME()), 127), N'Z', NCHAR(31),
            N'', NCHAR(31), N'', NCHAR(31), N'', NCHAR(31), N'', NCHAR(31), N''
        )), 2)),
        0,
        NULL,
        NULL,
        NULL,
        NULL
    FROM @Projects p
    INNER JOIN @ProjectEntryCounts pec
        ON pec.ProjectId = p.ProjectId
    INNER JOIN entry_seq es
        ON es.n <= pec.EntryCount
    INNER JOIN @Users u
        ON u.UserOrdinal = ((ABS(CHECKSUM(p.ProjectId, es.n)) % @UserCount) + 1);

    DECLARE @InsertedUsers int = (SELECT COUNT(*) FROM @Users);
    DECLARE @InsertedProjects int = (SELECT COUNT(*) FROM @Projects);
    DECLARE @InsertedGroups int = (SELECT COUNT(*) FROM @Groups);
    DECLARE @InsertedEntries int = (SELECT SUM(EntryCount) FROM @ProjectEntryCounts);

    COMMIT TRANSACTION;

    PRINT CONCAT('Seed prefix: ', @Prefix);
    PRINT CONCAT('Inserted users: ', @InsertedUsers);
    PRINT CONCAT('Inserted projects: ', @InsertedProjects);
    PRINT CONCAT('Inserted groups: ', @InsertedGroups);
    PRINT CONCAT('Inserted journal entries: ', @InsertedEntries);

    SELECT
        @Prefix AS seed_prefix,
        @InsertedUsers AS inserted_users,
        @InsertedProjects AS inserted_projects,
        @InsertedGroups AS inserted_groups,
        @InsertedEntries AS inserted_journal_entries,
        @MinEntriesPerProject AS min_entries_per_project,
        @MaxEntriesPerProject AS max_entries_per_project;
END TRY
BEGIN CATCH
    IF XACT_STATE() <> 0
        ROLLBACK TRANSACTION;

    DECLARE @ErrorMessage nvarchar(4000) = ERROR_MESSAGE();
    DECLARE @ErrorSeverity int = ERROR_SEVERITY();
    DECLARE @ErrorState int = ERROR_STATE();

    RAISERROR('Seed script failed: %s', @ErrorSeverity, @ErrorState, @ErrorMessage);
END CATCH;
