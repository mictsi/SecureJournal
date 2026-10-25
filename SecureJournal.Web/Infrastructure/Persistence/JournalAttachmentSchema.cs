using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Text.RegularExpressions;
using SecureJournal.Core.Application;

namespace SecureJournal.Web.Infrastructure.Persistence;

internal static class JournalAttachmentSchema
{
    // SQLite cannot ALTER a CHECK constraint. Rebuild only the known 0.22.0
    // limit, copying ciphertext verbatim and retaining the original schema.
    private static readonly Regex LegacySizeLimit = new(
        "(?<column>\\bsize_bytes\\b[\\\"\\]]?\\s*<=\\s*)5242880\\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static void EnsureSqlite(DbConnection connection)
    {
        var openedHere = connection.State != ConnectionState.Open;
        if (openedHere) connection.Open();
        try
        {
            var foreignKeys = Convert.ToInt32(Scalar(connection, null, "PRAGMA foreign_keys"), CultureInfo.InvariantCulture) != 0;
            if (foreignKeys) Execute(connection, null, "PRAGMA foreign_keys = OFF");
            try
            {
                using var transaction = connection.BeginTransaction();
                var schema = Scalar(connection, transaction,
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'journal_attachments'") as string;
                if (schema is null)
                {
                    Execute(connection, transaction, $"""
                        CREATE TABLE journal_attachments (
                            attachment_id TEXT NOT NULL PRIMARY KEY,
                            entry_id TEXT NOT NULL REFERENCES journal_entries(record_id) ON DELETE CASCADE,
                            file_name_ciphertext TEXT NOT NULL,
                            size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= {AttachmentLimits.MaxFileBytes}),
                            sha256 TEXT NOT NULL,
                            content_ciphertext TEXT NOT NULL
                        );
                        """);
                }
                else if (LegacySizeLimit.IsMatch(schema))
                {
                    var relatedObjects = ReadStrings(connection, transaction,
                        "SELECT sql FROM sqlite_master WHERE tbl_name = 'journal_attachments' AND type IN ('index', 'trigger') AND sql IS NOT NULL");
                    var columns = ReadStrings(connection, transaction, "SELECT name FROM pragma_table_info('journal_attachments')")
                        .Select(name => '"' + name.Replace("\"", "\"\"") + '"');
                    var columnList = string.Join(", ", columns);
                    var definition = LegacySizeLimit.Replace(schema[schema.IndexOf('(')..],
                        match => match.Groups["column"].Value + AttachmentLimits.MaxFileBytes.ToString(CultureInfo.InvariantCulture));
                    Execute(connection, transaction, "CREATE TABLE journal_attachments_size_upgrade " + definition);
                    Execute(connection, transaction, $"INSERT INTO journal_attachments_size_upgrade ({columnList}) SELECT {columnList} FROM journal_attachments");
                    Execute(connection, transaction, "DROP TABLE journal_attachments");
                    Execute(connection, transaction, "ALTER TABLE journal_attachments_size_upgrade RENAME TO journal_attachments");
                    foreach (var sql in relatedObjects) Execute(connection, transaction, sql);
                }
                Execute(connection, transaction,
                    "CREATE INDEX IF NOT EXISTS ix_journal_attachments_entry_id ON journal_attachments(entry_id)");
                using (var check = connection.CreateCommand())
                {
                    check.Transaction = transaction;
                    check.CommandText = "PRAGMA foreign_key_check(journal_attachments)";
                    using var reader = check.ExecuteReader();
                    if (reader.Read()) throw new InvalidOperationException("Attachment schema upgrade failed its foreign key check.");
                }
                transaction.Commit();
            }
            finally
            {
                // This also runs after rollback, including for pooled EF connections.
                if (foreignKeys) Execute(connection, null, "PRAGMA foreign_keys = ON");
            }
        }
        finally
        {
            if (openedHere) connection.Close();
        }
    }

    private static object? Scalar(DbConnection connection, DbTransaction? transaction, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static void Execute(DbConnection connection, DbTransaction? transaction, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static List<string> ReadStrings(DbConnection connection, DbTransaction transaction, string sql)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        using var reader = command.ExecuteReader();
        var result = new List<string>();
        while (reader.Read()) result.Add(reader.GetString(0));
        return result;
    }
}
