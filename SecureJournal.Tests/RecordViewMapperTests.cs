using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;
using SecureJournal.Web.Services;
using Xunit;

namespace SecureJournal.Tests;

public sealed class RecordViewMapperTests
{
    [Fact]
    public void MapJournalEntry_MapsProjectFieldsAndDecryptsContent()
    {
        var mapper = new RecordViewMapper(new PrefixDecryptJournalEncryptor(), new PrefixDecryptAuditEncryptor());
        var projectId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var recordId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        var deletedAt = new DateTime(2026, 3, 1, 1, 2, 3, DateTimeKind.Utc);
        var record = new JournalEntryRecord
        {
            RecordId = recordId,
            ProjectId = projectId,
            CreatedAtUtc = new DateTime(2026, 2, 1, 4, 5, 6, DateTimeKind.Utc),
            CreatedByUserId = Guid.NewGuid(),
            CreatedByUsername = "alice",
            SubjectCiphertext = "subject-cipher",
            DescriptionCiphertext = "description-cipher",
            NotesCiphertext = "notes-cipher",
            FullRecordChecksum = "CHK-J"
        };
        record.MarkSoftDeleted(new SoftDeleteMetadata(deletedAt, Guid.NewGuid(), "admin", "cleanup"));

        var view = mapper.MapJournalEntry(record, [new Project(projectId, "PRJ1", "Project One", "Desc", "", "", "", "")]);

        Assert.Equal(recordId, view.RecordId);
        Assert.Equal("PRJ1", view.ProjectCode);
        Assert.Equal("Project One", view.ProjectName);
        Assert.Equal("journal:subject-cipher", view.Subject);
        Assert.Equal("journal:description-cipher", view.Description);
        Assert.Equal("journal:notes-cipher", view.Notes);
        Assert.True(view.IsSoftDeleted);
        Assert.Equal(deletedAt, view.DeletedAtUtc);
        Assert.Equal("admin", view.DeletedBy);
        Assert.Equal("cleanup", view.DeleteReason);
        Assert.Equal("CHK-J", view.FullRecordChecksum);
    }

    [Fact]
    public void MapAuditLog_MapsProjectAndRelatedJournalEntry()
    {
        var mapper = new RecordViewMapper(new PrefixDecryptJournalEncryptor(), new PrefixDecryptAuditEncryptor());
        var projectId = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var recordId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        var journalRecord = new JournalEntryRecord
        {
            RecordId = recordId,
            ProjectId = projectId,
            CreatedAtUtc = new DateTime(2026, 2, 2, 2, 3, 4, DateTimeKind.Utc),
            CreatedByUserId = Guid.NewGuid(),
            CreatedByUsername = "bob",
            SubjectCiphertext = "subject",
            DescriptionCiphertext = "description",
            NotesCiphertext = "notes",
            FullRecordChecksum = "CHK-R"
        };
        var auditRecord = new AuditLogRecord(
            Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
            new DateTime(2026, 2, 3, 3, 4, 5, DateTimeKind.Utc),
            Guid.NewGuid(),
            "auditor",
            AuditActionType.Read,
            AuditEntityType.JournalEntry,
            recordId.ToString("D"),
            projectId,
            AuditOutcome.Success,
            "details-cipher",
            "CHK-A");

        var view = mapper.MapAuditLog(
            auditRecord,
            [new Project(projectId, "PRJ2", "Project Two", "Desc", "", "", "", "")],
            [journalRecord]);

        Assert.Equal("PRJ2", view.ProjectCode);
        Assert.Equal("audit:details-cipher", view.Details);
        Assert.NotNull(view.RelatedJournalEntry);
        Assert.Equal(recordId, view.RelatedJournalEntry!.RecordId);
        Assert.Equal("PRJ2", view.RelatedJournalEntry.ProjectCode);
        Assert.Equal("journal:subject", view.RelatedJournalEntry.Subject);
        Assert.Equal("journal:description", view.RelatedJournalEntry.Description);
        Assert.Equal("journal:notes", view.RelatedJournalEntry.Notes);
    }

    [Fact]
    public void MapAuditLog_ReturnsNullRelatedJournalEntryWhenAuditRecordDoesNotReferenceValidJournalEntry()
    {
        var mapper = new RecordViewMapper(new PrefixDecryptJournalEncryptor(), new PrefixDecryptAuditEncryptor());
        var auditRecord = new AuditLogRecord(
            Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            new DateTime(2026, 2, 4, 4, 5, 6, DateTimeKind.Utc),
            Guid.NewGuid(),
            "auditor",
            AuditActionType.Read,
            AuditEntityType.Project,
            "not-a-guid",
            null,
            AuditOutcome.Success,
            "details",
            "CHK-B");

        var view = mapper.MapAuditLog(auditRecord, [], []);

        Assert.Null(view.ProjectCode);
        Assert.Equal("audit:details", view.Details);
        Assert.Null(view.RelatedJournalEntry);
    }

    private sealed class PrefixDecryptJournalEncryptor : IJournalFieldEncryptor
    {
        public string Encrypt(string plaintext) => $"enc:{plaintext}";

        public string Decrypt(string ciphertext) => $"journal:{ciphertext}";
    }

    private sealed class PrefixDecryptAuditEncryptor : IAuditFieldEncryptor
    {
        public string Encrypt(string plaintext) => $"enc:{plaintext}";

        public string Decrypt(string ciphertext) => $"audit:{ciphertext}";
    }
}
