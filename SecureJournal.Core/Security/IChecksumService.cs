namespace SecureJournal.Core.Security;

public interface IChecksumService
{
    string ComputeHex(string value);
}
