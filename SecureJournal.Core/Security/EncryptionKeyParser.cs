using System.Security.Cryptography;
using System.Text;

namespace SecureJournal.Core.Security;

public static class EncryptionKeyParser
{
    public static byte[] GetKeyBytes(string? configuredValue, string purpose)
    {
        if (string.IsNullOrWhiteSpace(configuredValue))
        {
            return SHA256.HashData(Encoding.UTF8.GetBytes($"SecureJournal::{purpose}::dev-fallback"));
        }

        try
        {
            var decoded = Convert.FromBase64String(configuredValue);
            if (decoded.Length == 32)
            {
                return decoded;
            }

            return SHA256.HashData(decoded);
        }
        catch (FormatException)
        {
            return SHA256.HashData(Encoding.UTF8.GetBytes(configuredValue));
        }
    }
}
