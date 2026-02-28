using System.Text;
using System.Text.Json;
using SecureJournal.Core.Application;

namespace SecureJournal.Web.Services;

public sealed class ExportContentFormatter : IExportContentFormatter
{
    public string BuildJournalCsv(JournalExportFilter filter, IReadOnlyList<JournalEntryView> rows)
    {
        var sb = new StringBuilder();
        AppendCsvMetadata(sb, "JournalEntries", filter.ProjectId, filter.FromUtc, filter.ToUtc, filter.IncludeSoftDeleted);
        sb.AppendLine("RecordId,CreatedAtUtc,CreatedBy,ProjectCode,ProjectName,Subject,Description,Notes,IsSoftDeleted,DeletedAtUtc,DeletedBy,DeleteReason,FullRecordChecksum");

        foreach (var row in rows)
        {
            sb.AppendLine(string.Join(',',
                Csv(row.RecordId),
                Csv(row.CreatedAtUtc.ToString("O")),
                Csv(row.CreatedBy),
                Csv(row.ProjectCode),
                Csv(row.ProjectName),
                Csv(row.Subject),
                Csv(row.Description),
                Csv(row.Notes),
                Csv(row.IsSoftDeleted),
                Csv(row.DeletedAtUtc?.ToString("O") ?? string.Empty),
                Csv(row.DeletedBy ?? string.Empty),
                Csv(row.DeleteReason ?? string.Empty),
                Csv(row.FullRecordChecksum)));
        }

        return sb.ToString();
    }

    public string BuildJournalJson(JournalExportFilter filter, IReadOnlyList<JournalEntryView> rows)
    {
        var payload = new
        {
            exportType = "JournalEntries",
            exportedAtUtc = DateTime.UtcNow,
            filter = new
            {
                filter.ProjectId,
                filter.FromUtc,
                filter.ToUtc,
                filter.IncludeSoftDeleted
            },
            rowCount = rows.Count,
            rows
        };

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    public string BuildAuditCsv(AuditSearchFilter filter, IReadOnlyList<AuditLogView> rows)
    {
        var sb = new StringBuilder();
        AppendCsvMetadata(sb, "AuditLogs", filter.ProjectId, filter.FromUtc, filter.ToUtc, includeSoftDeleted: null);
        if (!string.IsNullOrWhiteSpace(filter.ActorUsername))
        {
            sb.AppendLine($"# ActorUsername={CsvString(filter.ActorUsername)}");
        }

        if (filter.Action.HasValue)
        {
            sb.AppendLine($"# Action={filter.Action.Value}");
        }

        if (filter.EntityType.HasValue)
        {
            sb.AppendLine($"# EntityType={filter.EntityType.Value}");
        }

        if (filter.Outcome.HasValue)
        {
            sb.AppendLine($"# Outcome={filter.Outcome.Value}");
        }

        sb.AppendLine("AuditId,TimestampUtc,ActorUsername,Action,EntityType,EntityId,ProjectId,ProjectCode,Outcome,Details,DetailsChecksum");

        foreach (var row in rows)
        {
            sb.AppendLine(string.Join(',',
                Csv(row.AuditId),
                Csv(row.TimestampUtc.ToString("O")),
                Csv(row.ActorUsername),
                Csv(row.Action),
                Csv(row.EntityType),
                Csv(row.EntityId ?? string.Empty),
                Csv(row.ProjectId?.ToString() ?? string.Empty),
                Csv(row.ProjectCode ?? string.Empty),
                Csv(row.Outcome),
                Csv(row.Details),
                Csv(row.DetailsChecksum)));
        }

        return sb.ToString();
    }

    public string BuildAuditJson(AuditSearchFilter filter, IReadOnlyList<AuditLogView> rows)
    {
        var payload = new
        {
            exportType = "AuditLogs",
            exportedAtUtc = DateTime.UtcNow,
            filter = new
            {
                filter.FromUtc,
                filter.ToUtc,
                filter.ActorUsername,
                filter.ProjectId,
                filter.Action,
                filter.EntityType,
                filter.Outcome
            },
            rowCount = rows.Count,
            rows
        };

        return JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }

    private static void AppendCsvMetadata(
        StringBuilder sb,
        string exportType,
        Guid? projectId,
        DateTime? fromUtc,
        DateTime? toUtc,
        bool? includeSoftDeleted)
    {
        sb.AppendLine($"# ExportType={exportType}");
        sb.AppendLine($"# ExportedAtUtc={DateTime.UtcNow:O}");
        sb.AppendLine($"# ProjectId={(projectId?.ToString() ?? "Any")}");
        sb.AppendLine($"# FromUtc={(fromUtc?.ToString("O") ?? "Any")}");
        sb.AppendLine($"# ToUtc={(toUtc?.ToString("O") ?? "Any")}");
        if (includeSoftDeleted.HasValue)
        {
            sb.AppendLine($"# IncludeSoftDeleted={includeSoftDeleted.Value}");
        }
    }

    private static string Csv(object? value)
        => CsvString(value?.ToString() ?? string.Empty);

    private static string CsvString(string value)
    {
        var safe = NeutralizeSpreadsheetFormula(value);
        var escaped = safe.Replace("\"", "\"\"", StringComparison.Ordinal);
        return $"\"{escaped}\"";
    }

    private static string NeutralizeSpreadsheetFormula(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        var firstNonWhitespace = -1;
        for (var i = 0; i < value.Length; i++)
        {
            if (!char.IsWhiteSpace(value[i]))
            {
                firstNonWhitespace = i;
                break;
            }
        }

        if (firstNonWhitespace < 0)
        {
            return value;
        }

        return value[firstNonWhitespace] is '=' or '+' or '-' or '@'
            ? $"'{value}"
            : value;
    }
}
