using System.ComponentModel.DataAnnotations;
using SecureJournal.Core.Domain;
using SecureJournal.Core.Validation;

namespace SecureJournal.Core.Application;

public sealed class CreateProjectRequest
{
    [StringLength(FieldLimits.ProjectCodeMax)]
    public string Code { get; set; } = string.Empty;

    [Required]
    [StringLength(FieldLimits.ProjectNameMax)]
    public string Name { get; set; } = string.Empty;

    [StringLength(FieldLimits.DescriptionMax)]
    public string Description { get; set; } = string.Empty;

    [StringLength(FieldLimits.DisplayNameMax)]
    public string ProjectOwnerName { get; set; } = string.Empty;

    [StringLength(FieldLimits.EmailMax)]
    public string ProjectEmail { get; set; } = string.Empty;

    [StringLength(FieldLimits.PhoneMax)]
    public string ProjectPhone { get; set; } = string.Empty;

    [StringLength(FieldLimits.DisplayNameMax)]
    public string ProjectOwner { get; set; } = string.Empty;

    [StringLength(FieldLimits.DepartmentMax)]
    public string Department { get; set; } = string.Empty;
}

public sealed class UpdateProjectRequest
{
    public Guid ProjectId { get; set; }

    [Required]
    [StringLength(FieldLimits.ProjectNameMax)]
    public string Name { get; set; } = string.Empty;

    [StringLength(FieldLimits.DescriptionMax)]
    public string Description { get; set; } = string.Empty;

    [StringLength(FieldLimits.DisplayNameMax)]
    public string ProjectOwnerName { get; set; } = string.Empty;

    [StringLength(FieldLimits.EmailMax)]
    public string ProjectEmail { get; set; } = string.Empty;

    [StringLength(FieldLimits.PhoneMax)]
    public string ProjectPhone { get; set; } = string.Empty;

    [StringLength(FieldLimits.DisplayNameMax)]
    public string ProjectOwner { get; set; } = string.Empty;

    [StringLength(FieldLimits.DepartmentMax)]
    public string Department { get; set; } = string.Empty;
}

public sealed class CreateUserRequest
{
    [Required]
    [StringLength(FieldLimits.UsernameMax)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [StringLength(FieldLimits.DisplayNameMax)]
    public string DisplayName { get; set; } = string.Empty;

    public AppRole Role { get; set; } = AppRole.ProjectUser;

    public bool IsLocalAccount { get; set; } = true;

    [StringLength(FieldLimits.SubjectMax)]
    public string LocalPassword { get; set; } = string.Empty;
}

public sealed class CreateGroupRequest
{
    [Required]
    [StringLength(FieldLimits.GroupNameMax)]
    public string Name { get; set; } = string.Empty;

    [StringLength(FieldLimits.DescriptionMax)]
    public string Description { get; set; } = string.Empty;
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
