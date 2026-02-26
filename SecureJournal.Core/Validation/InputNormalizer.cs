using System.Text;

namespace SecureJournal.Core.Validation;

public static class InputNormalizer
{
    public static string NormalizeRequired(string? value, string fieldName, int maxLength)
    {
        var normalized = Normalize(value);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new InvalidOperationException($"{fieldName} is required.");
        }

        if (normalized.Length > maxLength)
        {
            throw new InvalidOperationException($"{fieldName} exceeds max length {maxLength}.");
        }

        return normalized;
    }

    public static string NormalizeOptional(string? value, int maxLength)
    {
        var normalized = Normalize(value);
        if (normalized.Length > maxLength)
        {
            throw new InvalidOperationException($"Value exceeds max length {maxLength}.");
        }

        return normalized;
    }

    public static string Normalize(string? value)
        => (value ?? string.Empty).Trim().Normalize(NormalizationForm.FormKC);
}
