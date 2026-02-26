namespace SecureJournal.Core.Security;

public sealed class JournalFieldEncryptor : IJournalFieldEncryptor
{
    private readonly AesGcmStringEncryptor _inner;

    public JournalFieldEncryptor(byte[] key)
    {
        _inner = new AesGcmStringEncryptor(key);
    }

    public string Encrypt(string plaintext) => _inner.Encrypt(plaintext);

    public string Decrypt(string ciphertext) => _inner.Decrypt(ciphertext);
}

public sealed class AuditFieldEncryptor : IAuditFieldEncryptor
{
    private readonly AesGcmStringEncryptor _inner;

    public AuditFieldEncryptor(byte[] key)
    {
        _inner = new AesGcmStringEncryptor(key);
    }

    public string Encrypt(string plaintext) => _inner.Encrypt(plaintext);

    public string Decrypt(string ciphertext) => _inner.Decrypt(ciphertext);
}

public sealed class PlaintextAuditFieldEncryptor : IAuditFieldEncryptor
{
    public string Encrypt(string plaintext) => plaintext ?? string.Empty;

    public string Decrypt(string ciphertext) => ciphertext ?? string.Empty;
}
