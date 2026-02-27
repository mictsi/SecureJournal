/*
    SecureJournal SQL Server cleanup script.

    Default behavior:
      - clears SecureJournal app runtime data
      - keeps ASP.NET Identity tables/users intact

    Optional behavior:
      - set @CleanupIdentityData = 1 to also clear Identity data

    Usage (sqlcmd example):
      sqlcmd -S <server>.database.windows.net -d <database> -G -i scripts/cleanup-sqlserver.sql
*/

SET NOCOUNT ON;
SET XACT_ABORT ON;

DECLARE @CleanupIdentityData bit = 0; -- 0 = keep AspNet* tables, 1 = clear AspNet* data too

BEGIN TRY
    BEGIN TRANSACTION;

    PRINT 'Starting SecureJournal cleanup...';

    /* SecureJournal app data (safe order). */
    IF OBJECT_ID(N'dbo.audit_logs', N'U') IS NOT NULL
    BEGIN
        DELETE FROM dbo.audit_logs;
        PRINT 'Cleared dbo.audit_logs';
    END;

    IF OBJECT_ID(N'dbo.journal_entries', N'U') IS NOT NULL
    BEGIN
        DELETE FROM dbo.journal_entries;
        PRINT 'Cleared dbo.journal_entries';
    END;

    IF OBJECT_ID(N'dbo.project_groups', N'U') IS NOT NULL
    BEGIN
        DELETE FROM dbo.project_groups;
        PRINT 'Cleared dbo.project_groups';
    END;

    IF OBJECT_ID(N'dbo.user_groups', N'U') IS NOT NULL
    BEGIN
        DELETE FROM dbo.user_groups;
        PRINT 'Cleared dbo.user_groups';
    END;

    IF OBJECT_ID(N'dbo.user_roles', N'U') IS NOT NULL
    BEGIN
        DELETE FROM dbo.user_roles;
        PRINT 'Cleared dbo.user_roles';
    END;

    IF OBJECT_ID(N'dbo.groups_ref', N'U') IS NOT NULL
    BEGIN
        DELETE FROM dbo.groups_ref;
        PRINT 'Cleared dbo.groups_ref';
    END;

    IF OBJECT_ID(N'dbo.projects', N'U') IS NOT NULL
    BEGIN
        DELETE FROM dbo.projects;
        PRINT 'Cleared dbo.projects';
    END;

    IF OBJECT_ID(N'dbo.app_users', N'U') IS NOT NULL
    BEGIN
        DELETE FROM dbo.app_users;
        PRINT 'Cleared dbo.app_users';
    END;

    /* Optional ASP.NET Identity cleanup. */
    IF @CleanupIdentityData = 1
    BEGIN
        PRINT 'CleanupIdentityData=1, clearing ASP.NET Identity tables...';

        IF OBJECT_ID(N'dbo.AspNetUserTokens', N'U') IS NOT NULL
        BEGIN
            DELETE FROM dbo.AspNetUserTokens;
            PRINT 'Cleared dbo.AspNetUserTokens';
        END;

        IF OBJECT_ID(N'dbo.AspNetUserRoles', N'U') IS NOT NULL
        BEGIN
            DELETE FROM dbo.AspNetUserRoles;
            PRINT 'Cleared dbo.AspNetUserRoles';
        END;

        IF OBJECT_ID(N'dbo.AspNetUserClaims', N'U') IS NOT NULL
        BEGIN
            DELETE FROM dbo.AspNetUserClaims;
            PRINT 'Cleared dbo.AspNetUserClaims';
        END;

        IF OBJECT_ID(N'dbo.AspNetUserLogins', N'U') IS NOT NULL
        BEGIN
            DELETE FROM dbo.AspNetUserLogins;
            PRINT 'Cleared dbo.AspNetUserLogins';
        END;

        IF OBJECT_ID(N'dbo.AspNetRoleClaims', N'U') IS NOT NULL
        BEGIN
            DELETE FROM dbo.AspNetRoleClaims;
            PRINT 'Cleared dbo.AspNetRoleClaims';
        END;

        IF OBJECT_ID(N'dbo.AspNetUsers', N'U') IS NOT NULL
        BEGIN
            DELETE FROM dbo.AspNetUsers;
            PRINT 'Cleared dbo.AspNetUsers';
        END;

        IF OBJECT_ID(N'dbo.AspNetRoles', N'U') IS NOT NULL
        BEGIN
            DELETE FROM dbo.AspNetRoles;
            PRINT 'Cleared dbo.AspNetRoles';
        END;
    END;
    ELSE
    BEGIN
        PRINT 'CleanupIdentityData=0, ASP.NET Identity data preserved.';
    END;

    COMMIT TRANSACTION;
    PRINT 'SecureJournal cleanup completed successfully.';
END TRY
BEGIN CATCH
    IF XACT_STATE() <> 0
    BEGIN
        ROLLBACK TRANSACTION;
    END;

    DECLARE @ErrorMessage nvarchar(4000) = ERROR_MESSAGE();
    DECLARE @ErrorSeverity int = ERROR_SEVERITY();
    DECLARE @ErrorState int = ERROR_STATE();

    RAISERROR('SecureJournal cleanup failed: %s', @ErrorSeverity, @ErrorState, @ErrorMessage);
END CATCH;
