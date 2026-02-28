using System.Security.Cryptography;
using System.Text;

namespace SecureJournal.Core.Security;

public static class EncryptionKeyParser
{
    public static byte[] GetKeyBytes(string? configuredValue, string purpose)
    {
        var normalized = configuredValue?.Trim() ?? string.Empty;
        var isMissing = string.IsNullOrWhiteSpace(normalized);
        var isPlaceholder = !isMissing && normalized.StartsWith('<') && normalized.EndsWith('>');

        if (isMissing || isPlaceholder)
        {
            throw new InvalidOperationException(
                $"Security key for '{purpose}' is required. Set a non-placeholder value for 'Security:JournalEncryptionKey'.");
        }

        try
        {
            var decoded = Convert.FromBase64String(normalized);
            if (decoded.Length == 32)
            {
                return decoded;
            }

            return SHA256.HashData(decoded);
        }
        catch (FormatException)
        {
            return SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        }
    }
}
