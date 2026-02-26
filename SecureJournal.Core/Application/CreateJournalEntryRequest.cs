using System.ComponentModel.DataAnnotations;
using SecureJournal.Core.Validation;

namespace SecureJournal.Core.Application;

public sealed class CreateJournalEntryRequest
{
    public Guid ProjectId { get; set; }

    [Required]
    [StringLength(FieldLimits.CategoryMax)]
    public string Action { get; set; } = string.Empty;

    [Required]
    [StringLength(FieldLimits.SubjectMax)]
    public string Subject { get; set; } = string.Empty;

    [Required]
    [StringLength(FieldLimits.DescriptionMax)]
    public string Description { get; set; } = string.Empty;

    [StringLength(FieldLimits.NotesMax)]
    public string? Notes { get; set; } = string.Empty;
}
