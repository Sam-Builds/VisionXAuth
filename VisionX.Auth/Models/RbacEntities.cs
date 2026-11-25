namespace VisionX.Auth.Models;

public class RoleEntity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Code { get; set; } // e.g., "SYSTEM_ADMIN", "HOD", "FACULTY"
    public required string Name { get; set; }
    public string? Description { get; set; }
    public bool IsSystemRole { get; set; }
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
    public ICollection<UserRoleAssignment> UserAssignments { get; set; } = new List<UserRoleAssignment>();
}

public class PermissionEntity
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Code { get; set; } // e.g., "attendance.mark"
    public required string Name { get; set; }
    public string? Description { get; set; }
    public required string Module { get; set; } // e.g., "Attendance", "Students", "RBAC"
    public bool IsActive { get; set; } = true;

    public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
}

public class RolePermission
{
    public Guid RoleId { get; set; }
    public RoleEntity? Role { get; set; }
    public Guid PermissionId { get; set; }
    public PermissionEntity? Permission { get; set; }
}

public class UserRoleAssignment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string UserId { get; set; }
    public ApplicationUser? User { get; set; }
    public Guid RoleId { get; set; }
    public RoleEntity? Role { get; set; }

    public Guid? DepartmentId { get; set; }
    public string? DepartmentCode { get; set; }
    public Guid? AcademicTermId { get; set; }
    public Guid? SectionId { get; set; }
    public Guid? CourseOfferingId { get; set; }

    public bool IsActive { get; set; } = true;
    public required string AssignedBy { get; set; }
    public DateTime AssignedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? RevokedBy { get; set; }
    public string? AssignmentReason { get; set; }
}

public class RoleAssignmentHistory
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string UserId { get; set; }
    public Guid RoleId { get; set; }
    public required string RoleCode { get; set; }
    public required string Action { get; set; } // "Assigned", "Revoked", "Updated", "PermissionChanged"
    public string? PreviousValuesJson { get; set; }
    public string? NewValuesJson { get; set; }
    public required string PerformedBy { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? Reason { get; set; }
}
