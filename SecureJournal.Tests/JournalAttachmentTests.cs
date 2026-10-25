using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using System.ComponentModel.DataAnnotations;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;
using SecureJournal.Web.Infrastructure.Persistence;
using SecureJournal.Web.Services;
using Xunit;

namespace SecureJournal.Tests;

public sealed class JournalAttachmentTests
{
    [Fact]
    public void Save_DoesNotReadAttachmentMetadata_AndListsAndExportsBatchTheirMetadataReads()
    {
        using var ctx = new AttachmentContext(true);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Batched files" });
        ctx.Reads.FailMetadataReads = true;
        for (var i = 0; i < 3; i++)
        {
            // A metadata read failure after commit used to turn a successful save
            // into a UI error. Creation must return its prepared metadata directly.
            var entry = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = $"{i}.txt", Content = new byte[] { 1 } });
            Assert.Single(entry.Attachments);
        }
        Assert.Equal(0, ctx.Reads.MetadataReads);
        Assert.Equal(0, ctx.Reads.BodyReads);
        ctx.Reads.FailMetadataReads = false;
        var rows = ctx.App.GetJournalEntries(project.ProjectId);
        Assert.Equal(3, rows.Count);
        Assert.All(rows, row => Assert.Single(row.Attachments));
        Assert.Equal(1, ctx.Reads.MetadataReads);
        Assert.Equal(0, ctx.Reads.BodyReads);
        var exported = ctx.App.ExportJournalEntries(new JournalExportRequest
        {
            IncludeAttachments = true, Filter = new JournalExportFilter { ProjectId = project.ProjectId }
        });
        Assert.Equal(3, exported.RowCount);
        Assert.Equal(2, ctx.Reads.MetadataReads);
        Assert.Equal(3, ctx.Reads.BodyReads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void BulkMetadata_ReadsAcrossParameterBatchesWithoutLoadingBodies(bool ef)
    {
        using var ctx = new AttachmentContext(ef);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Batch boundary" });
        var first = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "first.txt", Content = new byte[] { 1 } });
        var last = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "last.txt", Content = new byte[] { 2 } });
        var requestedIds = new[] { first.RecordId }.Concat(Enumerable.Range(0, 499).Select(_ => Guid.NewGuid())).Append(last.RecordId).ToArray();
        var result = ctx.Store.LoadJournalAttachmentMetadata(requestedIds);
        Assert.Equal(2, result.Count);
        Assert.Contains(result, a => a.EntryId == first.RecordId);
        Assert.Contains(result, a => a.EntryId == last.RecordId);
        Assert.All(result, a => Assert.Empty(a.ContentCiphertext));
        if (ef)
        {
            Assert.Equal(2, ctx.Reads.MetadataReads);
            Assert.Equal(0, ctx.Reads.BodyReads);
        }
    }

    [Theory]
    [InlineData("../../räkningar-ÅÄÖ.pdf", "räkningar-ÅÄÖ.pdf")]
    [InlineData("C:\\upload\\证据.txt", "证据.txt")]
    [InlineData("...", "attachment")]
    [InlineData("CON.txt", "file-CON.txt")]
    [InlineData("unsafe\r\nname:script.html", "unsafe__name_script.html")]
    public void FileNames_PreserveInternationalLettersAndRemoveUnsafePathCharacters(string source, string expected)
        => Assert.Equal(expected, SecureJournalAppService.SafeAttachmentFileName(source));

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Attachments_AreEncryptedDurableAndBoundToTheirEntry(bool ef)
    {
        using var ctx = new AttachmentContext(ef);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Files" });
        var bytes = Encoding.UTF8.GetBytes("private-file-body-482759");
        var entry = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "../../private-evidence.txt", Content = bytes });
        var metadata = Assert.Single(entry.Attachments);
        Assert.Equal("private-evidence.txt", metadata.FileName);
        Assert.Equal(bytes.Length, metadata.SizeBytes);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)), metadata.Sha256);
        var stored = ctx.Store.LoadJournalAttachment(metadata.AttachmentId)!;
        Assert.DoesNotContain(metadata.FileName, stored.FileNameCiphertext);
        Assert.DoesNotContain(Encoding.UTF8.GetString(bytes), stored.ContentCiphertext);
        Assert.Empty(Assert.Single(ctx.Store.LoadJournalAttachmentMetadata(entry.RecordId)).ContentCiphertext);

        var restarted = ctx.CreateApp();
        Assert.True(restarted.TryLocalLogin("admin", "AdminPass123!").Success);
        Assert.Equal(bytes, restarted.DownloadJournalAttachment(metadata.AttachmentId).Content);
        Assert.Single(restarted.GetJournalEntries(project.ProjectId).Single().Attachments);
        Assert.Contains(restarted.SearchAuditLogs(new AuditSearchFilter { ProjectId = project.ProjectId }),
            a => a.EntityType == AuditEntityType.Attachment && a.Action == AuditActionType.Read);

        var other = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "other.txt", Content = bytes });
        var otherStored = ctx.Store.LoadJournalAttachment(other.Attachments.Single().AttachmentId)!;
        using var connection = ctx.OpenConnection();
        using var tamper = connection.CreateCommand();
        tamper.CommandText = "UPDATE journal_attachments SET content_ciphertext = $body WHERE lower(attachment_id) = lower($id)";
        tamper.Parameters.AddWithValue("$body", otherStored.ContentCiphertext);
        tamper.Parameters.AddWithValue("$id", metadata.AttachmentId.ToString("D"));
        Assert.Equal(1, tamper.ExecuteNonQuery());
        Assert.Throws<CryptographicException>(() => restarted.DownloadJournalAttachment(metadata.AttachmentId));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FailedAttachmentOrAuditWrite_RollsBackWholeEntryAndCanRetry(bool ef)
    {
        using var ctx = new AttachmentContext(ef);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Atomic" });
        var request = new CreateJournalEntryRequest
        {
            ProjectId = project.ProjectId, Subject = "Atomic entry", Description = "Must save together",
            Attachments = new[] { new JournalAttachmentUpload { FileName = "proof.txt", Content = new byte[] { 1, 2, 3 } } }
        };
        foreach (var table in new[] { "journal_attachments", "audit_logs" })
        {
            using var connection = ctx.OpenConnection();
            using var command = connection.CreateCommand();
            command.CommandText = $"CREATE TRIGGER reject_save BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'Simulated storage failure'); END;";
            command.ExecuteNonQuery();
            Assert.ThrowsAny<Exception>(() => ctx.App.CreateJournalEntry(request));
            Assert.Empty(ctx.App.GetJournalEntries(project.ProjectId));
            command.CommandText = "SELECT COUNT(*) FROM journal_attachments";
            Assert.Equal(0L, (long)command.ExecuteScalar()!);
            command.CommandText = "DROP TRIGGER reject_save";
            command.ExecuteNonQuery();
        }
        var saved = ctx.App.CreateJournalEntry(request);
        Assert.Single(ctx.App.GetJournalEntries(project.ProjectId));
        Assert.Single(saved.Attachments);
        Assert.Equal(2, ctx.App.SearchAuditLogs(new AuditSearchFilter { ProjectId = project.ProjectId })
            .Count(a => a.EntityType is AuditEntityType.JournalEntry or AuditEntityType.Attachment && a.Action == AuditActionType.Create));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Initialization_UpgradesExistingDatabaseWithoutLosingEntries(bool ef)
    {
        using var ctx = new AttachmentContext(ef);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Before upgrade" });
        var previous = ctx.Save(project.ProjectId);
        using (var connection = ctx.OpenConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "DROP TABLE journal_attachments";
            command.ExecuteNonQuery();
        }
        var upgraded = ctx.CreateApp();
        Assert.True(upgraded.TryLocalLogin("admin", "AdminPass123!").Success);
        Assert.Equal(previous.RecordId, Assert.Single(upgraded.GetJournalEntries(project.ProjectId)).RecordId);
        var entry = upgraded.CreateJournalEntry(new CreateJournalEntryRequest
        {
            ProjectId = project.ProjectId, Subject = "After upgrade", Description = "With a file",
            Attachments = new[] { new JournalAttachmentUpload { FileName = "new.txt", Content = new byte[] { 1 } } }
        });
        Assert.Equal(new byte[] { 1 }, upgraded.DownloadJournalAttachment(entry.Attachments.Single().AttachmentId).Content);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void FiveMiBSchema_UpgradesExistingFilesAndAcceptsTenMiBWithoutLosingConstraints(bool ef)
    {
        using var ctx = new AttachmentContext(ef);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "File size upgrade" });
        var oldEntry = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "before.txt", Content = "existing encrypted file"u8.ToArray() });
        var oldFile = oldEntry.Attachments.Single();
        var before = ctx.Store.LoadJournalAttachment(oldFile.AttachmentId);
        CreateLegacyFiveMiBSchema(ctx, ef);

        var upgraded = ctx.CreateApp();
        Assert.True(upgraded.TryLocalLogin("admin", "AdminPass123!").Success);
        Assert.Equal(before, ctx.Store.LoadJournalAttachment(oldFile.AttachmentId));
        Assert.Equal("existing encrypted file"u8.ToArray(), upgraded.DownloadJournalAttachment(oldFile.AttachmentId).Content);

        var tenMiB = new byte[10 * 1024 * 1024];
        tenMiB[0] = 27;
        tenMiB[^1] = 91;
        var entry = upgraded.CreateJournalEntry(new CreateJournalEntryRequest
        {
            ProjectId = project.ProjectId, Subject = "Ten MiB", Description = "New file limit",
            Attachments = [new JournalAttachmentUpload { FileName = "ten-mib.bin", Content = tenMiB }]
        });
        Assert.Equal(10 * 1024 * 1024, entry.Attachments.Single().SizeBytes);
        Assert.Equal(tenMiB, upgraded.DownloadJournalAttachment(entry.Attachments.Single().AttachmentId).Content);
        var error = Assert.Throws<ValidationException>(() => upgraded.CreateJournalEntry(new CreateJournalEntryRequest
        {
            ProjectId = project.ProjectId, Subject = "Too large", Description = "Must not save",
            Attachments = [new JournalAttachmentUpload { FileName = "too-large.bin", Content = new byte[10 * 1024 * 1024 + 1] }]
        }));
        Assert.Contains("10 MiB", error.Message);
        Assert.Equal(2, upgraded.GetJournalEntries(project.ProjectId).Count);

        using (var connection = ctx.OpenConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE name IN ('ix_journal_attachments_entry_id', 'attachment_sha_index', 'attachment_update_guard')";
            Assert.Equal(3L, command.ExecuteScalar());
            // The database boundary remains enforced independently of service validation.
            command.CommandText = "UPDATE journal_attachments SET size_bytes = 10485761";
            Assert.Throws<SqliteException>(() => command.ExecuteNonQuery());
            command.CommandText = "PRAGMA foreign_key_check(journal_attachments)";
            using var reader = command.ExecuteReader();
            Assert.False(reader.Read());
        }

        var restarted = ctx.CreateApp();
        Assert.True(restarted.TryLocalLogin("admin", "AdminPass123!").Success);
        Assert.Equal(before, ctx.Store.LoadJournalAttachment(oldFile.AttachmentId));
        Assert.Equal(2, restarted.GetJournalEntries(project.ProjectId).Count);
        ctx.Store.RemoveProject(project.ProjectId);
        Assert.Null(ctx.Store.LoadJournalAttachment(oldFile.AttachmentId));
        Assert.Null(ctx.Store.LoadJournalAttachment(entry.Attachments.Single().AttachmentId));
    }

    [Fact]
    public void FileSizeUpgrade_RollsBackAndRestoresForeignKeysOnFailure()
    {
        using var ctx = new AttachmentContext(false);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Interrupted file size upgrade" });
        var entry = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "before.txt", Content = new byte[] { 8, 13, 21 } });
        var id = entry.Attachments.Single().AttachmentId;
        var original = ctx.Store.LoadJournalAttachment(id);
        CreateLegacyFiveMiBSchema(ctx, false);
        using var connection = ctx.OpenConnection();
        using var command = connection.CreateCommand();
        // Force the final index creation to fail, after the replacement table has
        // been populated. The original table and encrypted data must roll back.
        command.CommandText = "DROP INDEX ix_journal_attachments_entry_id; CREATE TABLE ix_journal_attachments_entry_id (id INTEGER);";
        command.ExecuteNonQuery();
        Assert.Throws<SqliteException>(() => JournalAttachmentSchema.EnsureSqlite(connection));
        command.CommandText = "PRAGMA foreign_keys";
        Assert.Equal(1L, command.ExecuteScalar());
        command.CommandText = "SELECT sql FROM sqlite_master WHERE name = 'journal_attachments'";
        Assert.Contains("5242880", (string)command.ExecuteScalar()!);
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE name = 'journal_attachments_size_upgrade'";
        Assert.Equal(0L, command.ExecuteScalar());
        Assert.Equal(original, ctx.Store.LoadJournalAttachment(id));

        command.CommandText = "DROP TABLE ix_journal_attachments_entry_id";
        command.ExecuteNonQuery();
        JournalAttachmentSchema.EnsureSqlite(connection);
        command.CommandText = "PRAGMA foreign_keys";
        Assert.Equal(1L, command.ExecuteScalar());
        Assert.Equal(original, ctx.Store.LoadJournalAttachment(id));
    }

    private static void CreateLegacyFiveMiBSchema(AttachmentContext ctx, bool tableConstraint)
    {
        using var connection = ctx.OpenConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        var columnCheck = tableConstraint ? "" : "CHECK (size_bytes >= 0 AND size_bytes <= 5242880)";
        var namedCheck = tableConstraint ? ", CONSTRAINT CK_journal_attachments_size CHECK (size_bytes >= 0 AND size_bytes <= 5242880)" : "";
        command.CommandText = $"""
            ALTER TABLE journal_attachments RENAME TO attachments_new_limit;
            CREATE TABLE journal_attachments (
                attachment_id TEXT NOT NULL PRIMARY KEY,
                entry_id TEXT NOT NULL REFERENCES journal_entries(record_id) ON DELETE CASCADE,
                file_name_ciphertext TEXT NOT NULL,
                size_bytes INTEGER NOT NULL {columnCheck},
                sha256 TEXT NOT NULL,
                content_ciphertext TEXT NOT NULL
                {namedCheck}
            );
            INSERT INTO journal_attachments SELECT * FROM attachments_new_limit;
            DROP TABLE attachments_new_limit;
            CREATE INDEX ix_journal_attachments_entry_id ON journal_attachments(entry_id);
            CREATE INDEX attachment_sha_index ON journal_attachments(sha256);
            CREATE TRIGGER attachment_update_guard BEFORE UPDATE OF size_bytes ON journal_attachments
                WHEN NEW.size_bytes < 0 BEGIN SELECT RAISE(ABORT, 'File sizes cannot be negative'); END;
            """;
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void PermanentlyRemovingAProject_RemovesItsEncryptedFiles(bool ef)
    {
        using var ctx = new AttachmentContext(ef);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Remove files" });
        var entry = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "removed.txt", Content = new byte[] { 1 } });
        ctx.Store.RemoveProject(project.ProjectId);
        Assert.Null(ctx.Store.LoadJournalAttachment(entry.Attachments.Single().AttachmentId));
    }

    [Fact]
    public void Archive_RejectsOversizedMetadataBeforeLoadingFileBodies()
    {
        using var ctx = new AttachmentContext(false);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Export limits" });
        for (var i = 0; i < 3; i++)
            ctx.Save(project.ProjectId, Enumerable.Range(0, 4).Select(n => new JournalAttachmentUpload { FileName = $"{n}.txt", Content = new byte[] { 1 } }).ToArray());
        using (var connection = ctx.OpenConnection())
        using (var command = connection.CreateCommand())
        {
            // Declared sizes alone exceed the bound; bodies must never be fetched/decrypted.
            command.CommandText = "UPDATE journal_attachments SET size_bytes = 5242880, content_ciphertext = 'invalid-body'";
            command.ExecuteNonQuery();
        }
        var error = Assert.Throws<ValidationException>(() => ctx.App.ExportJournalEntries(new JournalExportRequest { IncludeAttachments = true }));
        Assert.Contains("50 MiB", error.Message);
    }

    [Fact]
    public void Files_RequireCurrentMembershipAndRespectRoleAndSoftDeletion()
    {
        using var ctx = new AttachmentContext(false);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Membership" });
        var group = ctx.App.CreateGroup(new CreateGroupRequest { Name = "Writers" });
        var user = ctx.App.CreateUser(new CreateUserRequest { Username = "writer", DisplayName = "Writer", Role = AppRole.ProjectUser, IsLocalAccount = true, LocalPassword = "WriterPass123!" });
        var membership = new AssignUserToGroupRequest { UserId = user.UserId, GroupId = group.GroupId };
        ctx.App.AssignUserToGroup(membership);
        ctx.App.AssignGroupToProject(new AssignGroupToProjectRequest { GroupId = group.GroupId, ProjectId = project.ProjectId });
        var entry = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "proof.html", Content = "<script>bad()</script>"u8.ToArray() });
        var id = entry.Attachments.Single().AttachmentId;
        ctx.App.LogoutCurrentUser();
        Assert.Throws<UnauthorizedAccessException>(() => ctx.App.DownloadJournalAttachment(id));
        Assert.True(ctx.App.TryLocalLogin("writer", "WriterPass123!").Success);
        Assert.NotEmpty(ctx.App.DownloadJournalAttachment(id).Content);
        Assert.Throws<UnauthorizedAccessException>(() => ctx.App.ExportJournalEntries(new JournalExportRequest { IncludeAttachments = true }));
        ctx.App.LogoutCurrentUser();
        ctx.Login();
        ctx.App.RemoveUserFromGroup(membership);
        ctx.App.LogoutCurrentUser();
        Assert.True(ctx.App.TryLocalLogin("writer", "WriterPass123!").Success);
        Assert.Throws<UnauthorizedAccessException>(() => ctx.App.GetJournalAttachments(entry.RecordId));
        Assert.Throws<UnauthorizedAccessException>(() => ctx.App.DownloadJournalAttachment(id));
        ctx.App.LogoutCurrentUser();
        ctx.Login();
        ctx.App.AssignUserToGroup(membership);
        ctx.App.SoftDeleteJournalEntry(entry.RecordId);
        ctx.App.LogoutCurrentUser();
        Assert.True(ctx.App.TryLocalLogin("writer", "WriterPass123!").Success);
        Assert.Throws<UnauthorizedAccessException>(() => ctx.App.DownloadJournalAttachment(id));
        ctx.App.LogoutCurrentUser();
        ctx.Login();
        var auditor = ctx.App.CreateUser(new CreateUserRequest { Username = "auditor", DisplayName = "Auditor", Role = AppRole.Auditor, IsLocalAccount = true, LocalPassword = "AuditorPass123!" });
        ctx.App.LogoutCurrentUser();
        Assert.True(ctx.App.TryLocalLogin("auditor", "AuditorPass123!").Success);
        Assert.Throws<UnauthorizedAccessException>(() => ctx.App.DownloadJournalAttachment(id));
    }

    [Theory]
    [InlineData("count")]
    [InlineData("file")]
    [InlineData("total")]
    public void UploadLimits_AreEnforcedBeforeAnythingIsSaved(string limit)
    {
        using var ctx = new AttachmentContext(false);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Limits" });
        var count = limit == "count" ? AttachmentLimits.MaxFilesPerEntry + 1 : limit == "total" ? 5 : 1;
        var length = limit == "file" ? (int)AttachmentLimits.MaxFileBytes + 1 : limit == "total" ? (int)AttachmentLimits.MaxFileBytes : 1;
        var body = new byte[length];
        var files = Enumerable.Range(0, count).Select(i => new JournalAttachmentUpload { FileName = $"{i}.bin", Content = body }).ToArray();
        Assert.Throws<ValidationException>(() => ctx.Save(project.ProjectId, files));
        Assert.Empty(ctx.App.GetJournalEntries(project.ProjectId));
    }

    [Theory]
    [InlineData(ExportFormat.Json)]
    [InlineData(ExportFormat.Csv)]
    public void Archive_ContainsOnlyFilteredEntriesAndFilesWithSafePaths(ExportFormat format)
    {
        using var ctx = new AttachmentContext(false);
        var project = ctx.App.CreateProject(new CreateProjectRequest { Name = "Selected" });
        var excludedProject = ctx.App.CreateProject(new CreateProjectRequest { Name = "Excluded" });
        var included = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "../../evidence.txt", Content = "included"u8.ToArray() }, new JournalAttachmentUpload { FileName = "../../evidence.txt", Content = "second"u8.ToArray() });
        var deleted = ctx.Save(project.ProjectId, new JournalAttachmentUpload { FileName = "deleted.txt", Content = "excluded"u8.ToArray() });
        ctx.App.SoftDeleteJournalEntry(deleted.RecordId);
        ctx.Save(excludedProject.ProjectId, new JournalAttachmentUpload { FileName = "outside.txt", Content = "excluded"u8.ToArray() });
        var result = ctx.App.ExportJournalEntries(new JournalExportRequest { Format = format, IncludeAttachments = true, Filter = new JournalExportFilter { ProjectId = project.ProjectId } });
        Assert.Equal("application/zip", result.ContentType);
        Assert.Equal(1, result.RowCount);
        using var archive = new ZipArchive(new MemoryStream(result.ContentBytes!));
        Assert.Equal(4, archive.Entries.Count);
        Assert.All(archive.Entries, e => { Assert.DoesNotContain("..", e.FullName); Assert.DoesNotContain('\\', e.FullName); Assert.False(e.FullName.StartsWith('/')); });
        Assert.Equal(2, archive.Entries.Count(e => e.FullName.StartsWith($"attachments/{included.RecordId:N}/")));
        using var manifest = JsonDocument.Parse(archive.GetEntry("manifest.json")!.Open());
        Assert.Equal(2, manifest.RootElement.GetProperty("AttachmentCount").GetInt32());
        Assert.All(manifest.RootElement.GetProperty("Files").EnumerateArray(), f => Assert.Equal(included.RecordId, f.GetProperty("EntryId").GetGuid()));
        Assert.NotNull(archive.GetEntry(format == ExportFormat.Json ? "journal.json" : "journal.csv"));
        var empty = ctx.App.ExportJournalEntries(new JournalExportRequest { IncludeAttachments = true, Filter = new JournalExportFilter { FromUtc = DateTime.UtcNow.AddDays(1) } });
        Assert.Equal(0, empty.RowCount);
        using var emptyArchive = new ZipArchive(new MemoryStream(empty.ContentBytes!));
        Assert.Equal(2, emptyArchive.Entries.Count);
    }

    private sealed class AttachmentContext : IDisposable
    {
        private readonly bool _ef;
        private readonly string _path = Path.Combine(Path.GetTempPath(), $"securejournal-files-{Guid.NewGuid():N}.db");
        private readonly IConfiguration _configuration;
        public AttachmentReadCounter Reads { get; } = new();
        public IPrototypeDataStore Store { get; private set; } = null!;
        public SecureJournalAppService App { get; }
        public AttachmentContext(bool ef)
        {
            _ef = ef;
            _configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:SecureJournalSqlite"] = $"Data Source={_path};Foreign Keys=True",
                ["Security:JournalEncryptionKey"] = "tests-journal-key",
                ["Security:LocalPasswordMinLength"] = "8",
                ["BootstrapAdmin:Username"] = "admin", ["BootstrapAdmin:DisplayName"] = "Admin",
                ["BootstrapAdmin:Password"] = "AdminPass123!"
            }).Build();
            App = CreateApp();
            Login();
        }
        public SecureJournalAppService CreateApp()
        {
            Store = _ef ? new EfCorePrototypeStore(new TestDbFactory($"Data Source={_path};Foreign Keys=True", Reads)) : new SqlitePrototypeStore(_configuration);
            var checksum = new Sha256ChecksumService();
            var journal = new JournalFieldEncryptor(EncryptionKeyParser.GetKeyBytes("tests-journal-key", "journal"));
            var audit = new PlaintextAuditFieldEncryptor();
            return new SecureJournalAppService(checksum, audit, new JournalEntryRecordFactory(checksum, journal),
                new AuditLogRecordFactory(audit, checksum), new RecordViewMapper(journal, audit), new ExportContentFormatter(), Store,
                new PrototypeSharedState(), _configuration, NullLogger<SecureJournalAppService>.Instance);
        }
        public void Login() => Assert.True(App.TryLocalLogin("admin", "AdminPass123!").Success);
        public JournalEntryView Save(Guid projectId, params JournalAttachmentUpload[] files)
            => App.CreateJournalEntry(new CreateJournalEntryRequest { ProjectId = projectId, Subject = "Evidence", Description = "Entry with files", Attachments = files });
        public SqliteConnection OpenConnection() { var connection = new SqliteConnection($"Data Source={_path};Foreign Keys=True"); connection.Open(); return connection; }
        public void Dispose() { SqliteConnection.ClearAllPools(); File.Delete(_path); }
    }
    private sealed class TestDbFactory(string connectionString, AttachmentReadCounter reads) : IDbContextFactory<SecureJournalAppDbContext>
    {
        public SecureJournalAppDbContext CreateDbContext() => new(new DbContextOptionsBuilder<SecureJournalAppDbContext>().UseSqlite(connectionString).AddInterceptors(reads).Options);
    }

    private sealed class AttachmentReadCounter : DbCommandInterceptor
    {
        public int MetadataReads { get; private set; }
        public int BodyReads { get; private set; }
        public bool FailMetadataReads { get; set; }

        public override InterceptionResult<DbDataReader> ReaderExecuting(DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result)
        {
            if (command.CommandText.TrimStart().StartsWith("SELECT", StringComparison.OrdinalIgnoreCase)
                && command.CommandText.Contains("journal_attachments", StringComparison.OrdinalIgnoreCase))
            {
                if (command.CommandText.Contains("content_ciphertext", StringComparison.OrdinalIgnoreCase)) BodyReads++;
                else
                {
                    MetadataReads++;
                    if (FailMetadataReads) throw new InvalidOperationException("Simulated metadata read failure.");
                }
            }
            return result;
        }
    }
}
