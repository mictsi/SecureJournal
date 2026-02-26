using Microsoft.AspNetCore.Identity;

namespace SecureJournal.Web.Infrastructure.Identity;

public class SecureJournalIdentityUser : IdentityUser
{
    public string DisplayName { get; set; } = string.Empty;
    public bool IsBootstrapAdmin { get; set; }
}
