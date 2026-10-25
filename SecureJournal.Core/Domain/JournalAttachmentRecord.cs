namespace SecureJournal.Core.Domain;

// File names and content are encrypted with the journal key. Content is loaded
// separately from metadata, so browsing entries never loads attachment bodies.
public sealed record JournalAttachmentRecord(
    Guid AttachmentId, Guid EntryId, string FileNameCiphertext, long SizeBytes,
    string Sha256, string ContentCiphertext = "");
