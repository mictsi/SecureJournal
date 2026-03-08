using System.Text.Json;
using SecureJournal.Core.Application;
using SecureJournal.Core.Domain;
using SecureJournal.Web.Services;
using Xunit;

namespace SecureJournal.Tests;

public sealed class ExportContentFormatterTests
{
    [Fact]
    public void BuildJournalCsv_IncludesMetadataAndNeutralizesSpreadsheetFormulas()
    {
        var formatter = new ExportContentFormatter();
        var projectId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var filter = new JournalExportFilter
        {
            ProjectId = projectId,
            FromUtc = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc),
            ToUtc = new DateTime(2026, 1, 31, 23, 59, 59, DateTimeKind.Utc),
            IncludeSoftDeleted = true
        };
        var rows = new[]
        {
            new JournalEntryView(
                Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                projectId,
                "PRJ1",
                "Project One",
                new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
                "alice",
                "=2+2",
                "desc \"quoted\"",
                "@note",
                IsSoftDeleted: true,
                DeletedAtUtc: new DateTime(2026, 1, 3, 4, 5, 6, DateTimeKind.Utc),
                DeletedBy: "admin",
                DeleteReason: "-cleanup",
                FullRecordChecksum: "CHK1")
        };

        var csv = formatter.BuildJournalCsv(filter, rows);

        Assert.Contains("# ExportType=JournalEntries", csv, StringComparison.Ordinal);
        Assert.Contains($"# ProjectId={projectId}", csv, StringComparison.Ordinal);
        Assert.Contains("# IncludeSoftDeleted=True", csv, StringComparison.Ordinal);
        Assert.Contains("RecordId,CreatedAtUtc,CreatedBy,ProjectCode,ProjectName,Subject,Description,Notes,IsSoftDeleted,DeletedAtUtc,DeletedBy,DeleteReason,FullRecordChecksum", csv, StringComparison.Ordinal);
        Assert.Contains("\"'=2+2\"", csv, StringComparison.Ordinal);
        Assert.Contains("\"desc \"\"quoted\"\"\"", csv, StringComparison.Ordinal);
        Assert.Contains("\"'@note\"", csv, StringComparison.Ordinal);
        Assert.Contains("\"'-cleanup\"", csv, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildAuditCsv_IncludesOptionalFilterMetadata()
    {
        var formatter = new ExportContentFormatter();
        var filter = new AuditSearchFilter
        {
            ActorUsername = "alice",
            Action = AuditActionType.Export,
            EntityType = AuditEntityType.Export,
            Outcome = AuditOutcome.Success
        };
        var rows = new[]
        {
            new AuditLogView(
                Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                new DateTime(2026, 2, 1, 1, 2, 3, DateTimeKind.Utc),
                "alice",
                AuditActionType.Export,
                AuditEntityType.Export,
                "entity-1",
                null,
                null,
                AuditOutcome.Success,
                "=exported",
                "CHK2",
                RelatedJournalEntry: null)
        };

        var csv = formatter.BuildAuditCsv(filter, rows);

        Assert.Contains("# ActorUsername=\"alice\"", csv, StringComparison.Ordinal);
        Assert.Contains("# Action=Export", csv, StringComparison.Ordinal);
        Assert.Contains("# EntityType=Export", csv, StringComparison.Ordinal);
        Assert.Contains("# Outcome=Success", csv, StringComparison.Ordinal);
        Assert.Contains("\"'=exported\"", csv, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildAuditJson_WritesExpectedPayloadShape()
    {
        var formatter = new ExportContentFormatter();
        var projectId = Guid.Parse("33333333-3333-3333-3333-333333333333");
        var filter = new AuditSearchFilter
        {
            ActorUsername = "alice",
            ProjectId = projectId,
            Action = AuditActionType.Read
        };
        var rows = new[]
        {
            new AuditLogView(
                Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
                new DateTime(2026, 2, 2, 2, 3, 4, DateTimeKind.Utc),
                "alice",
                AuditActionType.Read,
                AuditEntityType.Project,
                "entity-2",
                projectId,
                "PRJ2",
                AuditOutcome.Success,
                "Viewed project",
                "CHK3",
                RelatedJournalEntry: null)
        };

        var json = formatter.BuildAuditJson(filter, rows);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        Assert.Equal("AuditLogs", root.GetProperty("exportType").GetString());
        Assert.Equal(1, root.GetProperty("rowCount").GetInt32());
        Assert.Equal("alice", root.GetProperty("filter").GetProperty("ActorUsername").GetString());
        Assert.Equal(projectId.ToString(), root.GetProperty("filter").GetProperty("ProjectId").GetString());
        Assert.Equal("Viewed project", root.GetProperty("rows")[0].GetProperty("Details").GetString());
    }
}
