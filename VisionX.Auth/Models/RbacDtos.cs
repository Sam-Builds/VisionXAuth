using System.ComponentModel.DataAnnotations;

namespace VisionX.Auth.Models;

public class PermissionDto
{
    public Guid Id { get; set; }
    public string Code { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Module { get; set; } = string.Empty;
    public bool IsActive { get; set; }
}

public class RoleDto
{
    public Guid Id { get; set; }
    public string Code { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsSystemRole { get; set; }
    public bool IsActive { get; set; }
    public List<string> PermissionCodes { get; set; } = new();
    public int ActiveAssignmentCount { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public class SaveRoleRequestDto
{
    [Required]
    [MaxLength(64)]
    public string Code { get; set; } = string.Empty;

    [Required]
    [MaxLength(120)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? Description { get; set; }

    public bool IsActive { get; set; } = true;
    public List<string> PermissionCodes { get; set; } = new();
}

public class UpdateRolePermissionsRequestDto
{
    [Required]
    public List<string> PermissionCodes { get; set; } = new();

    [MaxLength(300)]
    public string? Reason { get; set; }
}

public class ScopedRoleAssignmentDto
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string UserEmail { get; set; } = string.Empty;
    public Guid RoleId { get; set; }
    public string RoleCode { get; set; } = string.Empty;
    public string RoleName { get; set; } = string.Empty;
    public Guid? DepartmentId { get; set; }
    public string? DepartmentCode { get; set; }
    public Guid? AcademicTermId { get; set; }
    public Guid? SectionId { get; set; }
    public Guid? CourseOfferingId { get; set; }
    public bool IsActive { get; set; }
    public string AssignedBy { get; set; } = string.Empty;
    public DateTime AssignedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? RevokedBy { get; set; }
    public string? AssignmentReason { get; set; }
}

public class AssignUserRoleRequestDto
{
    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public string RoleCode { get; set; } = string.Empty;

    public Guid? DepartmentId { get; set; }

    [MaxLength(32)]
    public string? DepartmentCode { get; set; }

    public Guid? AcademicTermId { get; set; }
    public Guid? SectionId { get; set; }
    public Guid? CourseOfferingId { get; set; }
    public DateTime? ExpiresAt { get; set; }

    [MaxLength(300)]
    public string? Reason { get; set; }
}

public class RevokeRoleAssignmentRequestDto
{
    [MaxLength(300)]
    public string? Reason { get; set; }
}

public class RoleAssignmentHistoryDto
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string? UserEmail { get; set; }
    public Guid RoleId { get; set; }
    public string RoleCode { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string? PreviousValuesJson { get; set; }
    public string? NewValuesJson { get; set; }
    public string PerformedBy { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string? Reason { get; set; }
}

public class EffectiveAuthorizationDto
{
    public string UserId { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailVerified { get; set; }
    public bool Banned { get; set; }
    public bool Immunity { get; set; }
    public bool IsSuperAdmin { get; set; }
    public bool HasManagementAccess { get; set; }
    public List<string> Roles { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
    public List<ScopedRoleAssignmentDto> Assignments { get; set; } = new();
    public DateTime EvaluatedAtUtc { get; set; } = DateTime.UtcNow;
}

public class UserLookupItemDto
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailVerified { get; set; }
    public bool Immunity { get; set; }
    public bool Banned { get; set; }
    public string? UserDetails { get; set; }
    public DateTime CreatedAt { get; set; }
    public List<string> ActiveRoles { get; set; } = new();
}
