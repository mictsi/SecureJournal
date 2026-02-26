namespace SecureJournal.Core.Application;

public enum ExportFormat
{
    Csv = 1,
    Json = 2
}

public sealed class JournalExportFilter
{
    public Guid? ProjectId { get; set; }
    public DateTime? FromUtc { get; set; }
    public DateTime? ToUtc { get; set; }
    public bool IncludeSoftDeleted { get; set; }
}

public sealed class JournalExportRequest
{
    public ExportFormat Format { get; set; } = ExportFormat.Json;
    public JournalExportFilter Filter { get; set; } = new();
}

public sealed class AuditExportRequest
{
    public ExportFormat Format { get; set; } = ExportFormat.Json;
    public AuditSearchFilter Filter { get; set; } = new();
}

public sealed record ExportFileResult(
    string FileName,
    string ContentType,
    string ContentText,
    int RowCount,
    string Summary);
