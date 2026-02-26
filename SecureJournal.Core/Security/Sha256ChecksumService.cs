using System.Security.Cryptography;
using System.Text;

namespace SecureJournal.Core.Security;

public sealed class Sha256ChecksumService : IChecksumService
{
    public string ComputeHex(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes);
    }
}
