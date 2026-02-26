namespace SecureJournal.Core.Security;

public interface IJournalFieldEncryptor
{
    string Encrypt(string plaintext);
    string Decrypt(string ciphertext);
}

public interface IAuditFieldEncryptor
{
    string Encrypt(string plaintext);
    string Decrypt(string ciphertext);
}
