using System.ComponentModel.DataAnnotations;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Validation;

namespace SecureJournal.Core.Application;

public sealed class CreateProjectRequest
{
    [StringLength(20)]
    public string Code { get; set; } = string.Empty;

    [Required]
    [StringLength(100)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string Description { get; set; } = string.Empty;
}

public sealed class CreateUserRequest
{
    [Required]
    [StringLength(100)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [StringLength(100)]
    public string DisplayName { get; set; } = string.Empty;

    public AppRole Role { get; set; } = AppRole.ProjectUser;

    public bool IsLocalAccount { get; set; } = true;

    [StringLength(FieldLimits.SubjectMax)]
    public string LocalPassword { get; set; } = string.Empty;
}

public sealed class CreateGroupRequest
{
    [Required]
    [StringLength(100)]
    public string Name { get; set; } = string.Empty;
}

public sealed class AssignUserToGroupRequest
{
    public Guid UserId { get; set; }
    public Guid GroupId { get; set; }
}

public sealed class UserRoleMembershipRequest
{
    public Guid UserId { get; set; }
    public AppRole Role { get; set; } = AppRole.ProjectUser;
}

public sealed class AssignGroupToProjectRequest
{
    public Guid GroupId { get; set; }
    public Guid ProjectId { get; set; }
}

public sealed class ChangePasswordRequest
{
    [Required]
    [StringLength(FieldLimits.SubjectMax)]
    public string CurrentPassword { get; set; } = string.Empty;

    [Required]
    [StringLength(FieldLimits.SubjectMax)]
    public string NewPassword { get; set; } = string.Empty;
}

public sealed class AdminResetPasswordRequest
{
    public Guid UserId { get; set; }

    [Required]
    [StringLength(FieldLimits.SubjectMax)]
    public string NewPassword { get; set; } = string.Empty;
}

public sealed record LoginResult(
    bool Success,
    string Message,
    UserContext? User);

public sealed record PasswordChangeResult(
    bool Success,
    string Message);
