using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureJournal.Web.Infrastructure.Identity;

namespace SecureJournal.Web.Infrastructure.Persistence;

public sealed class SecureJournalIdentityDbContext
    : IdentityDbContext<SecureJournalIdentityUser, IdentityRole, string>
{
    public SecureJournalIdentityDbContext(DbContextOptions<SecureJournalIdentityDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<SecureJournalIdentityUser>(entity =>
        {
            entity.Property(x => x.DisplayName).HasMaxLength(200);
            entity.Property(x => x.IsBootstrapAdmin).HasDefaultValue(false);
        });
    }
}
