namespace SecureJournal.Core.Domain;

public sealed class JournalEntryRecord
{
    public Guid RecordId { get; init; }
    public Guid ProjectId { get; init; }
    public DateTime CreatedAtUtc { get; init; }
    public Guid CreatedByUserId { get; init; }
    public string CreatedByUsername { get; init; } = string.Empty;

    public string SubjectCiphertext { get; init; } = string.Empty;
    public string DescriptionCiphertext { get; init; } = string.Empty;
    public string NotesCiphertext { get; init; } = string.Empty;
    public string ResultCiphertext { get; init; } = string.Empty;

    public string SubjectChecksum { get; init; } = string.Empty;
    public string DescriptionChecksum { get; init; } = string.Empty;
    public string NotesChecksum { get; init; } = string.Empty;
    public string ResultChecksum { get; init; } = string.Empty;
    public string FullRecordChecksum { get; init; } = string.Empty;

    public SoftDeleteMetadata? SoftDelete { get; private set; }

    public bool IsSoftDeleted => SoftDelete is not null;

    public void MarkSoftDeleted(SoftDeleteMetadata metadata)
    {
        SoftDelete ??= metadata;
    }
}
