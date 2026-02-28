using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;

namespace SecureJournal.Web.Services;

public sealed class JournalEntryRecordFactory : IJournalEntryRecordFactory
{
    private readonly IChecksumService _checksum;
    private readonly IJournalFieldEncryptor _encryptor;

    public JournalEntryRecordFactory(IChecksumService checksum, IJournalFieldEncryptor encryptor)
    {
        _checksum = checksum;
        _encryptor = encryptor;
    }

    public JournalEntryRecord Create(
        Guid projectId,
        Guid createdByUserId,
        string createdByUsername,
        DateTime createdAtUtc,
        string subject,
        string description,
        string notes,
        string result)
    {
        return new JournalEntryRecord
        {
            RecordId = Guid.NewGuid(),
            ProjectId = projectId,
            CreatedAtUtc = createdAtUtc,
            CreatedByUserId = createdByUserId,
            CreatedByUsername = createdByUsername,
            SubjectCiphertext = _encryptor.Encrypt(subject),
            DescriptionCiphertext = _encryptor.Encrypt(description),
            NotesCiphertext = _encryptor.Encrypt(notes),
            ResultCiphertext = _encryptor.Encrypt(result),
            SubjectChecksum = _checksum.ComputeHex(subject),
            DescriptionChecksum = _checksum.ComputeHex(description),
            NotesChecksum = _checksum.ComputeHex(notes),
            ResultChecksum = _checksum.ComputeHex(result),
            FullRecordChecksum = _checksum.ComputeHex(BuildFullRecordChecksumMaterial(
                projectId,
                createdByUserId,
                createdAtUtc,
                subject,
                description,
                notes,
                result))
        };
    }

    private static string BuildFullRecordChecksumMaterial(
        Guid projectId,
        Guid createdByUserId,
        DateTime createdAtUtc,
        string subject,
        string description,
        string notes,
        string result)
        => string.Join('\u001F', new[]
        {
            projectId.ToString("D"),
            createdByUserId.ToString("D"),
            createdAtUtc.ToUniversalTime().ToString("O"),
            subject,
            description,
            notes,
            result
        });
}
