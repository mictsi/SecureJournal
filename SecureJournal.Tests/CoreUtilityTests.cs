using System.Security.Cryptography;
using System.Text;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Security;
using SecureJournal.Core.Validation;
using Xunit;

namespace SecureJournal.Tests;

public sealed class InputNormalizerTests
{
    [Fact]
    public void NormalizeRequired_TrimsAndNormalizesCompatibilityCharacters()
    {
        var result = InputNormalizer.NormalizeRequired("  Ａｌｉｃｅ  ", "Name", 20);

        Assert.Equal("Alice", result);
    }

    [Fact]
    public void NormalizeRequired_ThrowsWhenValueIsMissing()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => InputNormalizer.NormalizeRequired("   ", "Name", 20));

        Assert.Equal("Name is required.", ex.Message);
    }

    [Fact]
    public void NormalizeOptional_ThrowsWhenValueExceedsMaxLength()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => InputNormalizer.NormalizeOptional("abcdef", 5));

        Assert.Equal("Value exceeds max length 5.", ex.Message);
    }

    [Fact]
    public void Normalize_ReturnsEmptyStringForNull()
    {
        Assert.Equal(string.Empty, InputNormalizer.Normalize(null));
    }
}

public sealed class EncryptionKeyParserTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("<replace-me>")]
    public void GetKeyBytes_ThrowsForMissingOrPlaceholderValues(string? configuredValue)
    {
        var ex = Assert.Throws<InvalidOperationException>(() => EncryptionKeyParser.GetKeyBytes(configuredValue, "journal"));

        Assert.Contains("Security key for 'journal' is required.", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void GetKeyBytes_ReturnsDecodedBytesFor32ByteBase64Payload()
    {
        var expected = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var configured = Convert.ToBase64String(expected);

        var actual = EncryptionKeyParser.GetKeyBytes(configured, "journal");

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void GetKeyBytes_HashesDecodedBytesWhenBase64PayloadIsNot32Bytes()
    {
        var decoded = Encoding.UTF8.GetBytes("short-key");
        var configured = Convert.ToBase64String(decoded);

        var actual = EncryptionKeyParser.GetKeyBytes(configured, "journal");

        Assert.Equal(SHA256.HashData(decoded), actual);
    }

    [Fact]
    public void GetKeyBytes_HashesUtf8BytesWhenValueIsNotBase64()
    {
        const string configured = "plain-text-key";

        var actual = EncryptionKeyParser.GetKeyBytes(configured, "journal");

        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(configured)), actual);
    }
}

public sealed class AesGcmStringEncryptorTests
{
    [Fact]
    public void Constructor_ThrowsWhenKeyLengthIsInvalid()
    {
        var ex = Assert.Throws<ArgumentException>(() => new AesGcmStringEncryptor(new byte[31]));

        Assert.Contains("32 bytes", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EncryptAndDecrypt_RoundTripsPlaintext()
    {
        var encryptor = new AesGcmStringEncryptor(Enumerable.Repeat((byte)7, 32).ToArray());

        var ciphertext = encryptor.Encrypt("journal entry");
        var plaintext = encryptor.Decrypt(ciphertext);

        Assert.StartsWith("v1.", ciphertext, StringComparison.Ordinal);
        Assert.Equal("journal entry", plaintext);
    }

    [Fact]
    public void Encrypt_UsesRandomNonceForSamePlaintext()
    {
        var encryptor = new AesGcmStringEncryptor(Enumerable.Repeat((byte)9, 32).ToArray());

        var first = encryptor.Encrypt("same");
        var second = encryptor.Encrypt("same");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void Decrypt_ReturnsEmptyStringForBlankPayload()
    {
        var encryptor = new AesGcmStringEncryptor(Enumerable.Repeat((byte)3, 32).ToArray());

        Assert.Equal(string.Empty, encryptor.Decrypt(" "));
    }

    [Fact]
    public void Decrypt_ThrowsForInvalidPayloadFormat()
    {
        var encryptor = new AesGcmStringEncryptor(Enumerable.Repeat((byte)5, 32).ToArray());

        var ex = Assert.Throws<InvalidOperationException>(() => encryptor.Decrypt("not-a-valid-payload"));

        Assert.Equal("Encrypted payload format is invalid.", ex.Message);
    }
}

public sealed class AuditChecksumMaterialBuilderTests
{
    [Fact]
    public void Build_NormalizesFieldsAndUsesExpectedOrdering()
    {
        var timestampUtc = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);

        var material = AuditChecksumMaterialBuilder.Build(
            timestampUtc,
            "  Ａlice  ",
            AuditActionType.Export,
            AuditEntityType.JournalEntry,
            "  rec-1  ",
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            AuditOutcome.Success,
            "  line one  ");

        var parts = material.Split('\u001F');

        Assert.Equal(8, parts.Length);
        Assert.Equal("2026-01-02T03:04:05.0000000Z", parts[0]);
        Assert.Equal("Alice", parts[1]);
        Assert.Equal(nameof(AuditActionType.Export), parts[2]);
        Assert.Equal(nameof(AuditEntityType.JournalEntry), parts[3]);
        Assert.Equal("rec-1", parts[4]);
        Assert.Equal("11111111-1111-1111-1111-111111111111", parts[5]);
        Assert.Equal(nameof(AuditOutcome.Success), parts[6]);
        Assert.Equal("line one", parts[7]);
    }
}
