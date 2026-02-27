using SecureJournal.Core.Application;

namespace SecureJournal.Web.Services;

public interface IExportContentFormatter
{
    string BuildJournalCsv(JournalExportFilter filter, IReadOnlyList<JournalEntryView> rows);
    string BuildJournalJson(JournalExportFilter filter, IReadOnlyList<JournalEntryView> rows);
    string BuildAuditCsv(AuditSearchFilter filter, IReadOnlyList<AuditLogView> rows);
    string BuildAuditJson(AuditSearchFilter filter, IReadOnlyList<AuditLogView> rows);
}
