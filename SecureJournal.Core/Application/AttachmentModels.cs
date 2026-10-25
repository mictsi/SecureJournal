namespace SecureJournal.Core.Application;

public static class AttachmentLimits
{
    public const int MaxFilesPerEntry = 10;
    public const long MaxFileBytes = 10 * 1024 * 1024;
    public const long MaxTotalBytes = 20 * 1024 * 1024;
    public const long MaxExportBytes = 50 * 1024 * 1024;
    public const int MaxExportFiles = 1000;
    public const int MaxExportRows = 10000;
}

public sealed class JournalAttachmentUpload
{
    public string FileName { get; init; } = string.Empty;
    public string ContentType { get; init; } = "application/octet-stream";
    public byte[] Content { get; init; } = Array.Empty<byte>();
}

public sealed record JournalAttachmentView(Guid AttachmentId, Guid EntryId, string FileName, long SizeBytes, string Sha256);
public sealed record JournalAttachmentDownload(string FileName, byte[] Content);
