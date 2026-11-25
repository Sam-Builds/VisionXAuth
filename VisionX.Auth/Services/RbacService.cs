using System.Text.Json;
using VisionX.Auth.Data;
using VisionX.Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace VisionX.Auth.Services;

public sealed class RbacService
{
    public static readonly (string Code, string Name, string Module, string Description)[] DefaultPermissions =
    {
        ("department.read", "View Departments", "Structure", "View department catalog and overview metrics."),
        ("department.manage", "Manage Departments", "Structure", "Create, edit, enable, or archive departments."),
        ("students.read", "View Students", "Students", "Search and view student directory and academic profiles."),
        ("students.manage", "Manage Students", "Students", "Edit student records, sections, and academic info state."),
        ("students.verify", "Verify Students", "Students", "Approve, deny, or request review on student verification."),
        ("faculty.read", "View Faculty", "Faculty", "View faculty directory and current teaching assignments."),
        ("faculty.manage", "Manage Faculty Records", "Faculty", "Create and edit faculty directory profiles."),
        ("faculty.assign", "Allocate Faculty", "Faculty", "Assign faculty to course offerings, subjects, and scoped roles."),
        ("curriculum.read", "View Curriculum", "Structure", "View programmes, curriculum versions, and subject mappings."),
        ("curriculum.manage", "Manage Curriculum", "Structure", "Create and edit programmes, curriculum versions, subjects, and mappings."),
        ("academic_terms.read", "View Academic Terms", "Terms", "View academic years, terms, and sections."),
        ("academic_terms.manage", "Manage Academic Terms", "Terms", "Create/activate/close academic terms and sections."),
        ("progression.read", "View Progression", "Progression", "View student term enrollments, backlogs, and progression history."),
        ("progression.evaluate", "Evaluate Progression", "Progression", "Preview semester transitions and generate proposed progression/backlog states."),
        ("progression.approve", "Approve Progression", "Progression", "Approve year-back decisions and commit semester transitions."),
        ("course_offerings.read", "View Course Offerings", "Structure", "View term-based subject and section offerings."),
        ("course_offerings.manage", "Manage Course Offerings", "Structure", "Create and manage course offerings for academic terms."),
        ("assignments.read", "View Assignments", "Academics", "View assignments in authorized offerings."),
        ("assignments.create", "Create Assignments", "Academics", "Create assignments for assigned course offerings."),
        ("assignments.update", "Update Assignments", "Academics", "Edit assignments in assigned offerings."),
        ("assignments.publish", "Publish Assignments", "Academics", "Publish, close, or archive assignments."),
        ("attendance.read", "View Attendance", "Academics", "View class sessions and student attendance totals."),
        ("attendance.mark", "Mark Attendance", "Academics", "Record class attendance sessions for assigned offerings."),
        ("attendance.modify", "Modify Finalized Attendance", "Academics", "Correct finalized attendance sessions with audit reason."),
        ("internals.read", "View Internal Assessment", "Academics", "View internal assessment components and marks."),
        ("internals.manage", "Manage Internal Assessment", "Academics", "Create assessment components, enter marks, and finalize."),
        ("results.read", "View Results", "Academics", "View draft and published course results and GPA summaries."),
        ("results.manage", "Manage Results", "Academics", "Enter and review course results and manage grading scales."),
        ("results.publish", "Publish Results", "Academics", "Approve and publish finalized results and update backlogs."),
        ("timetable.read", "View Timetable", "Timetable", "View schedules by faculty, section, and semester."),
        ("timetable.manage", "Manage Timetable", "Timetable", "Create/edit timetable slots and resolve scheduling conflicts."),
        ("audit.read", "View Audit Logs", "Governance", "Inspect immutable audit logs of sensitive academic operations."),
        ("users.read", "Lookup Users", "Governance", "Search shared Auth accounts by email to grant access."),
        ("rbac.read", "View Roles & Permissions", "Governance", "View role definitions, permission matrix, and assignments."),
        ("rbac.manage", "Manage Roles & Permissions", "Governance", "Create custom roles, edit role permissions, and manage global assignments."),
        ("notifications.read", "View Notifications", "Notifications", "View notifications metrics, delivery history, and user inboxes."),
        ("notifications.send", "Send Notifications", "Notifications", "Dispatch direct and test push notifications."),
        ("notifications.campaigns.manage", "Manage Campaigns", "Notifications", "Create, schedule, preview, and cancel notification campaigns."),
        ("notifications.devices.manage", "Manage Devices", "Notifications", "Inspect and deactivate user device registrations.")
    };

    private static readonly string[] HodDefaultPermissions =
    {
        "department.read", "students.read", "students.manage", "students.verify",
        "faculty.read", "faculty.manage", "faculty.assign",
        "curriculum.read", "curriculum.manage", "academic_terms.read", "academic_terms.manage",
        "progression.read", "progression.evaluate", "progression.approve",
        "course_offerings.read", "course_offerings.manage",
        "assignments.read", "assignments.create", "assignments.update", "assignments.publish",
        "attendance.read", "attendance.mark", "attendance.modify",
        "internals.read", "internals.manage", "results.read", "results.manage", "results.publish",
        "timetable.read", "timetable.manage", "audit.read", "users.read", "rbac.read"
    };

    private static readonly string[] FacultyDefaultPermissions =
    {
        "department.read", "students.read", "curriculum.read", "academic_terms.read",
        "course_offerings.read",
        "assignments.read", "assignments.create", "assignments.update", "assignments.publish",
        "attendance.read", "attendance.mark",
        "internals.read", "internals.manage", "results.read", "timetable.read"
    };

    private readonly AuthDbContext _dbContext;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ISessionEventPublisher _eventPublisher;
    private readonly IConfiguration _configuration;

    public RbacService(
        AuthDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        ISessionEventPublisher eventPublisher,
        IConfiguration configuration)
    {
        _dbContext = dbContext;
        _userManager = userManager;
        _eventPublisher = eventPublisher;
        _configuration = configuration;
    }

    public async Task SeedDefaultRolesAndPermissionsAsync()
    {
        var existingPermissions = await _dbContext.Permissions.ToDictionaryAsync(x => x.Code, StringComparer.OrdinalIgnoreCase);
        foreach (var (code, name, module, desc) in DefaultPermissions)
        {
            if (!existingPermissions.ContainsKey(code))
            {
                var p = new PermissionEntity
                {
                    Code = code,
                    Name = name,
                    Module = module,
                    Description = desc,
                    IsActive = true
                };
                _dbContext.Permissions.Add(p);
                existingPermissions[code] = p;
            }
        }
        await _dbContext.SaveChangesAsync();

        await EnsureRoleAsync("SYSTEM_ADMIN", "System Administrator", "Full institution-wide management access.", true, DefaultPermissions.Select(p => p.Code), existingPermissions);
        await EnsureRoleAsync("HOD", "Head of Department", "Department-scoped administrative, progression, faculty allocation, and academic authority.", true, HodDefaultPermissions, existingPermissions);
        await EnsureRoleAsync("FACULTY", "Faculty Member", "Course-offering and section-scoped teaching authority for assignments, attendance, internals, and timetable.", true, FacultyDefaultPermissions, existingPermissions);
    }

    private async Task EnsureRoleAsync(
        string code,
        string name,
        string description,
        bool isSystem,
        IEnumerable<string> defaultPermCodes,
        Dictionary<string, PermissionEntity> allPermissions)
    {
        var role = await _dbContext.Roles
            .Include(r => r.RolePermissions)
            .FirstOrDefaultAsync(r => r.Code == code);

        if (role is null)
        {
            role = new RoleEntity
            {
                Code = code,
                Name = name,
                Description = description,
                IsSystemRole = isSystem,
                IsActive = true
            };
            _dbContext.Roles.Add(role);
            await _dbContext.SaveChangesAsync();

            foreach (var pCode in defaultPermCodes.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (allPermissions.TryGetValue(pCode, out var perm))
                {
                    _dbContext.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionId = perm.Id });
                }
            }
            await _dbContext.SaveChangesAsync();
            return;
        }

        // Add any newly introduced permissions for SYSTEM_ADMIN automatically so upgrades stay coherent.
        if (code == "SYSTEM_ADMIN")
        {
            var existingPermIds = role.RolePermissions.Select(rp => rp.PermissionId).ToHashSet();
            var added = false;
            foreach (var perm in allPermissions.Values)
            {
                if (!existingPermIds.Contains(perm.Id))
                {
                    _dbContext.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionId = perm.Id });
                    added = true;
                }
            }
            if (added) await _dbContext.SaveChangesAsync();
        }
    }

    public async Task<bool> IsSuperAdminUserAsync(ApplicationUser user)
    {
        var adminEmail = _configuration["Admin:Email"];
        if (!string.IsNullOrWhiteSpace(adminEmail)
            && string.Equals(user.Email, adminEmail, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var claims = await _userManager.GetClaimsAsync(user);
        if (claims.Any(c => c.Type == "role" && string.Equals(c.Value, "admin", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        var now = DateTime.UtcNow;
        return await _dbContext.UserRoleAssignments
            .Include(a => a.Role)
            .AnyAsync(a => a.UserId == user.Id
                && a.IsActive
                && a.RevokedAt == null
                && (a.ExpiresAt == null || a.ExpiresAt > now)
                && a.Role != null && a.Role.IsActive && a.Role.Code == "SYSTEM_ADMIN");
    }

    public async Task<EffectiveAuthorizationDto> GetEffectiveAuthorizationAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            throw new AuthDomainException("USER_NOT_FOUND", "User not found.", 404);
        }

        if (user.Banned)
        {
            return new EffectiveAuthorizationDto
            {
                UserId = user.Id,
                Email = user.Email ?? string.Empty,
                EmailVerified = user.EmailVerified,
                Banned = true,
                Immunity = user.Immunity,
                IsSuperAdmin = false,
                HasManagementAccess = false
            };
        }

        var now = DateTime.UtcNow;
        var activeAssignments = await _dbContext.UserRoleAssignments
            .AsNoTracking()
            .Include(a => a.Role)
                .ThenInclude(r => r!.RolePermissions)
                    .ThenInclude(rp => rp.Permission)
            .Where(a => a.UserId == user.Id
                && a.IsActive
                && a.RevokedAt == null
                && (a.ExpiresAt == null || a.ExpiresAt > now)
                && a.Role != null
                && a.Role.IsActive)
            .OrderByDescending(a => a.AssignedAt)
            .ToListAsync();

        var isSuperAdmin = await IsSuperAdminUserAsync(user);
        var roles = activeAssignments
            .Select(a => a.Role!.Code)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (isSuperAdmin && !roles.Contains("SYSTEM_ADMIN", StringComparer.OrdinalIgnoreCase))
        {
            roles.Insert(0, "SYSTEM_ADMIN");
        }

        HashSet<string> perms;
        if (isSuperAdmin)
        {
            var allActivePerms = await _dbContext.Permissions
                .AsNoTracking()
                .Where(p => p.IsActive)
                .Select(p => p.Code)
                .ToListAsync();
            perms = allActivePerms.ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (perms.Count == 0)
            {
                perms = DefaultPermissions.Select(p => p.Code).ToHashSet(StringComparer.OrdinalIgnoreCase);
            }
        }
        else
        {
            perms = activeAssignments
                .SelectMany(a => a.Role!.RolePermissions)
                .Where(rp => rp.Permission != null && rp.Permission.IsActive)
                .Select(rp => rp.Permission!.Code)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        var dtoAssignments = activeAssignments.Select(a => new ScopedRoleAssignmentDto
        {
            Id = a.Id,
            UserId = a.UserId,
            UserEmail = user.Email ?? string.Empty,
            RoleId = a.RoleId,
            RoleCode = a.Role!.Code,
            RoleName = a.Role.Name,
            DepartmentId = a.DepartmentId,
            DepartmentCode = a.DepartmentCode,
            AcademicTermId = a.AcademicTermId,
            SectionId = a.SectionId,
            CourseOfferingId = a.CourseOfferingId,
            IsActive = a.IsActive,
            AssignedBy = a.AssignedBy,
            AssignedAt = a.AssignedAt,
            ExpiresAt = a.ExpiresAt,
            RevokedAt = a.RevokedAt,
            RevokedBy = a.RevokedBy,
            AssignmentReason = a.AssignmentReason
        }).ToList();

        return new EffectiveAuthorizationDto
        {
            UserId = user.Id,
            Email = user.Email ?? string.Empty,
            EmailVerified = user.EmailVerified,
            Banned = user.Banned,
            Immunity = user.Immunity,
            IsSuperAdmin = isSuperAdmin,
            HasManagementAccess = isSuperAdmin || dtoAssignments.Count > 0,
            Roles = roles,
            Permissions = perms.OrderBy(p => p).ToList(),
            Assignments = dtoAssignments,
            EvaluatedAtUtc = DateTime.UtcNow
        };
    }

    public async Task<List<PermissionDto>> GetPermissionsAsync()
    {
        return await _dbContext.Permissions
            .AsNoTracking()
            .OrderBy(p => p.Module).ThenBy(p => p.Code)
            .Select(p => new PermissionDto
            {
                Id = p.Id,
                Code = p.Code,
                Name = p.Name,
                Description = p.Description,
                Module = p.Module,
                IsActive = p.IsActive
            })
            .ToListAsync();
    }

    public async Task<List<RoleDto>> GetRolesAsync()
    {
        var now = DateTime.UtcNow;
        var roles = await _dbContext.Roles
            .AsNoTracking()
            .Include(r => r.RolePermissions).ThenInclude(rp => rp.Permission)
            .Include(r => r.UserAssignments)
            .OrderBy(r => r.IsSystemRole ? 0 : 1).ThenBy(r => r.Code)
            .ToListAsync();

        return roles.Select(r => new RoleDto
        {
            Id = r.Id,
            Code = r.Code,
            Name = r.Name,
            Description = r.Description,
            IsSystemRole = r.IsSystemRole,
            IsActive = r.IsActive,
            PermissionCodes = r.RolePermissions
                .Where(rp => rp.Permission != null && rp.Permission.IsActive)
                .Select(rp => rp.Permission!.Code)
                .OrderBy(c => c)
                .ToList(),
            ActiveAssignmentCount = r.UserAssignments.Count(a => a.IsActive && a.RevokedAt == null && (a.ExpiresAt == null || a.ExpiresAt > now)),
            CreatedAt = r.CreatedAt,
            UpdatedAt = r.UpdatedAt
        }).ToList();
    }

    public async Task<RoleDto> CreateCustomRoleAsync(SaveRoleRequestDto request, string actorIdentifier)
    {
        var code = request.Code.Trim().ToUpperInvariant().Replace(' ', '_');
        if (string.IsNullOrWhiteSpace(code))
            throw new AuthDomainException("INVALID_ROLE_CODE", "Role code is required.", 400);

        if (await _dbContext.Roles.AnyAsync(r => r.Code == code))
            throw new AuthDomainException("ROLE_EXISTS", $"Role '{code}' already exists.", 409);

        var perms = await ValidatePermissionCodesAsync(request.PermissionCodes);

        var role = new RoleEntity
        {
            Code = code,
            Name = request.Name.Trim(),
            Description = request.Description?.Trim(),
            IsSystemRole = false,
            IsActive = request.IsActive,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        _dbContext.Roles.Add(role);
        await _dbContext.SaveChangesAsync();

        foreach (var p in perms)
        {
            _dbContext.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionId = p.Id });
        }
        _dbContext.RoleAssignmentHistories.Add(new RoleAssignmentHistory
        {
            UserId = actorIdentifier,
            RoleId = role.Id,
            RoleCode = role.Code,
            Action = "RoleCreated",
            NewValuesJson = JsonSerializer.Serialize(new { role.Code, role.Name, Permissions = perms.Select(x => x.Code) }),
            PerformedBy = actorIdentifier,
            Reason = "Created custom role"
        });
        await _dbContext.SaveChangesAsync();

        var all = await GetRolesAsync();
        return all.First(r => r.Id == role.Id);
    }

    public async Task<RoleDto> UpdateRolePermissionsAsync(Guid roleId, UpdateRolePermissionsRequestDto request, string actorIdentifier)
    {
        var role = await _dbContext.Roles
            .Include(r => r.RolePermissions).ThenInclude(rp => rp.Permission)
            .FirstOrDefaultAsync(r => r.Id == roleId);
        if (role is null)
            throw new AuthDomainException("ROLE_NOT_FOUND", "Role not found.", 404);

        if (role.Code == "SYSTEM_ADMIN")
            throw new AuthDomainException("SYSTEM_ROLE_LOCKED", "SYSTEM_ADMIN permissions cannot be reduced.", 400);

        var previous = role.RolePermissions
            .Where(rp => rp.Permission != null)
            .Select(rp => rp.Permission!.Code)
            .OrderBy(c => c)
            .ToList();

        var newPerms = await ValidatePermissionCodesAsync(request.PermissionCodes);
        _dbContext.RolePermissions.RemoveRange(role.RolePermissions);
        foreach (var p in newPerms)
        {
            _dbContext.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionId = p.Id });
        }
        role.UpdatedAt = DateTime.UtcNow;

        _dbContext.RoleAssignmentHistories.Add(new RoleAssignmentHistory
        {
            UserId = actorIdentifier,
            RoleId = role.Id,
            RoleCode = role.Code,
            Action = "PermissionChanged",
            PreviousValuesJson = JsonSerializer.Serialize(previous),
            NewValuesJson = JsonSerializer.Serialize(newPerms.Select(p => p.Code).OrderBy(c => c)),
            PerformedBy = actorIdentifier,
            Reason = request.Reason?.Trim()
        });

        await _dbContext.SaveChangesAsync();
        await _eventPublisher.QueueSessionEventAsync("authorization.changed", role.Id.ToString(), "*", "Allowed", $"RolePermissionsUpdated:{role.Code}");
        await _dbContext.SaveChangesAsync();

        var all = await GetRolesAsync();
        return all.First(r => r.Id == role.Id);
    }

    private async Task<List<PermissionEntity>> ValidatePermissionCodesAsync(IEnumerable<string> codes)
    {
        var requested = codes.Where(c => !string.IsNullOrWhiteSpace(c)).Select(c => c.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var existing = await _dbContext.Permissions.Where(p => p.IsActive && requested.Contains(p.Code)).ToListAsync();
        if (existing.Count != requested.Count)
        {
            var found = existing.Select(p => p.Code).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var unknown = requested.Where(c => !found.Contains(c));
            throw new AuthDomainException("INVALID_PERMISSIONS", $"Unknown permission code(s): {string.Join(", ", unknown)}", 400);
        }
        return existing;
    }

    public async Task<List<UserLookupItemDto>> LookupUsersAsync(string? search, int limit = 25)
    {
        var bounded = Math.Clamp(limit, 1, 100);
        var now = DateTime.UtcNow;
        var query = _dbContext.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim().ToLower();
            query = query.Where(u => (u.Email != null && u.Email.ToLower().Contains(term)) || u.Id.ToLower().Contains(term));
        }

        var users = await query.OrderBy(u => u.Email).Take(bounded).ToListAsync();
        var userIds = users.Select(u => u.Id).ToList();
        var activeAssignments = await _dbContext.UserRoleAssignments
            .AsNoTracking()
            .Include(a => a.Role)
            .Where(a => userIds.Contains(a.UserId) && a.IsActive && a.RevokedAt == null && (a.ExpiresAt == null || a.ExpiresAt > now) && a.Role != null && a.Role.IsActive)
            .ToListAsync();

        var rolesByUser = activeAssignments
            .GroupBy(a => a.UserId)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Role!.Code).Distinct(StringComparer.OrdinalIgnoreCase).ToList());

        return users.Select(u => new UserLookupItemDto
        {
            Id = u.Id,
            Email = u.Email ?? string.Empty,
            EmailVerified = u.EmailVerified,
            Immunity = u.Immunity,
            Banned = u.Banned,
            UserDetails = u.UserDetails,
            CreatedAt = u.CreatedAt,
            ActiveRoles = rolesByUser.TryGetValue(u.Id, out var r) ? r : new List<string>()
        }).ToList();
    }

    public async Task<List<ScopedRoleAssignmentDto>> GetAssignmentsAsync(string? userId = null, Guid? departmentId = null, string? roleCode = null, bool activeOnly = false)
    {
        var query = _dbContext.UserRoleAssignments
            .AsNoTracking()
            .Include(a => a.User)
            .Include(a => a.Role)
            .AsQueryable();

        if (!string.IsNullOrWhiteSpace(userId))
            query = query.Where(a => a.UserId == userId.Trim());
        if (departmentId.HasValue)
            query = query.Where(a => a.DepartmentId == departmentId.Value);
        if (!string.IsNullOrWhiteSpace(roleCode))
            query = query.Where(a => a.Role != null && a.Role.Code == roleCode.Trim().ToUpperInvariant());
        if (activeOnly)
        {
            var now = DateTime.UtcNow;
            query = query.Where(a => a.IsActive && a.RevokedAt == null && (a.ExpiresAt == null || a.ExpiresAt > now));
        }

        return await query
            .OrderByDescending(a => a.AssignedAt)
            .Take(200)
            .Select(a => new ScopedRoleAssignmentDto
            {
                Id = a.Id,
                UserId = a.UserId,
                UserEmail = a.User != null ? (a.User.Email ?? string.Empty) : string.Empty,
                RoleId = a.RoleId,
                RoleCode = a.Role != null ? a.Role.Code : string.Empty,
                RoleName = a.Role != null ? a.Role.Name : string.Empty,
                DepartmentId = a.DepartmentId,
                DepartmentCode = a.DepartmentCode,
                AcademicTermId = a.AcademicTermId,
                SectionId = a.SectionId,
                CourseOfferingId = a.CourseOfferingId,
                IsActive = a.IsActive && a.RevokedAt == null && (a.ExpiresAt == null || a.ExpiresAt > DateTime.UtcNow),
                AssignedBy = a.AssignedBy,
                AssignedAt = a.AssignedAt,
                ExpiresAt = a.ExpiresAt,
                RevokedAt = a.RevokedAt,
                RevokedBy = a.RevokedBy,
                AssignmentReason = a.AssignmentReason
            })
            .ToListAsync();
    }

    public async Task<ScopedRoleAssignmentDto> AssignUserRoleAsync(
        AssignUserRoleRequestDto request,
        string actorUserId,
        string actorEmail,
        bool actorCanManageAllRoles,
        HashSet<Guid> actorHodDepartmentIds)
    {
        var user = await _userManager.FindByIdAsync(request.UserId.Trim());
        if (user is null)
            throw new AuthDomainException("USER_NOT_FOUND", "Target user not found in Auth Service.", 404);
        if (user.Banned)
            throw new AuthDomainException("ACCOUNT_BANNED", "Cannot grant management roles to a banned user.", 400);

        var normalizedRoleCode = request.RoleCode.Trim().ToUpperInvariant();
        var role = await _dbContext.Roles.FirstOrDefaultAsync(r => r.Code == normalizedRoleCode && r.IsActive);
        if (role is null)
            throw new AuthDomainException("ROLE_NOT_FOUND", $"Active role '{normalizedRoleCode}' not found.", 404);

        if (!actorCanManageAllRoles)
        {
            // HOD policy enforcement: HOD can only grant FACULTY role within their own active HOD department.
            if (normalizedRoleCode != "FACULTY")
                throw new AuthDomainException("FORBIDDEN_ROLE_ESCALATION", "Department HODs may only assign the FACULTY role within their department.", 403);
            if (!request.DepartmentId.HasValue || !actorHodDepartmentIds.Contains(request.DepartmentId.Value))
                throw new AuthDomainException("FORBIDDEN_DEPARTMENT_SCOPE", "You may only assign faculty roles within your authorized department.", 403);
        }

        var duplicateExists = await _dbContext.UserRoleAssignments.AnyAsync(a =>
            a.UserId == user.Id
            && a.RoleId == role.Id
            && a.DepartmentId == request.DepartmentId
            && a.AcademicTermId == request.AcademicTermId
            && a.SectionId == request.SectionId
            && a.CourseOfferingId == request.CourseOfferingId
            && a.IsActive
            && a.RevokedAt == null);

        if (duplicateExists)
            throw new AuthDomainException("ASSIGNMENT_EXISTS", "This exact active role assignment already exists for the user.", 409);

        var assignment = new UserRoleAssignment
        {
            UserId = user.Id,
            RoleId = role.Id,
            DepartmentId = request.DepartmentId,
            DepartmentCode = request.DepartmentCode?.Trim().ToUpperInvariant(),
            AcademicTermId = request.AcademicTermId,
            SectionId = request.SectionId,
            CourseOfferingId = request.CourseOfferingId,
            IsActive = true,
            AssignedBy = actorEmail,
            AssignedAt = DateTime.UtcNow,
            ExpiresAt = request.ExpiresAt,
            AssignmentReason = request.Reason?.Trim()
        };

        _dbContext.UserRoleAssignments.Add(assignment);
        _dbContext.RoleAssignmentHistories.Add(new RoleAssignmentHistory
        {
            UserId = user.Id,
            RoleId = role.Id,
            RoleCode = role.Code,
            Action = "Assigned",
            NewValuesJson = JsonSerializer.Serialize(new
            {
                assignment.DepartmentId,
                assignment.DepartmentCode,
                assignment.AcademicTermId,
                assignment.SectionId,
                assignment.CourseOfferingId,
                assignment.ExpiresAt
            }),
            PerformedBy = actorEmail,
            Reason = request.Reason?.Trim()
        });

        await _dbContext.SaveChangesAsync();
        await _eventPublisher.QueueSessionEventAsync("authorization.changed", assignment.Id.ToString(), user.Id, "Allowed", $"RoleAssigned:{role.Code}");
        await _dbContext.SaveChangesAsync();

        return new ScopedRoleAssignmentDto
        {
            Id = assignment.Id,
            UserId = assignment.UserId,
            UserEmail = user.Email ?? string.Empty,
            RoleId = assignment.RoleId,
            RoleCode = role.Code,
            RoleName = role.Name,
            DepartmentId = assignment.DepartmentId,
            DepartmentCode = assignment.DepartmentCode,
            AcademicTermId = assignment.AcademicTermId,
            SectionId = assignment.SectionId,
            CourseOfferingId = assignment.CourseOfferingId,
            IsActive = true,
            AssignedBy = assignment.AssignedBy,
            AssignedAt = assignment.AssignedAt,
            ExpiresAt = assignment.ExpiresAt,
            AssignmentReason = assignment.AssignmentReason
        };
    }

    public async Task RevokeUserRoleAssignmentAsync(
        Guid assignmentId,
        string? reason,
        string actorEmail,
        bool actorCanManageAllRoles,
        HashSet<Guid> actorHodDepartmentIds)
    {
        var assignment = await _dbContext.UserRoleAssignments
            .Include(a => a.Role)
            .FirstOrDefaultAsync(a => a.Id == assignmentId);

        if (assignment is null)
            throw new AuthDomainException("ASSIGNMENT_NOT_FOUND", "Role assignment not found.", 404);

        if (!actorCanManageAllRoles)
        {
            if (assignment.Role?.Code != "FACULTY" || !assignment.DepartmentId.HasValue || !actorHodDepartmentIds.Contains(assignment.DepartmentId.Value))
                throw new AuthDomainException("FORBIDDEN_REVOKE", "You may only revoke FACULTY assignments within your own department.", 403);
        }

        var prev = JsonSerializer.Serialize(new { assignment.IsActive, assignment.DepartmentId, assignment.CourseOfferingId });
        assignment.IsActive = false;
        assignment.RevokedAt = DateTime.UtcNow;
        assignment.RevokedBy = actorEmail;

        _dbContext.RoleAssignmentHistories.Add(new RoleAssignmentHistory
        {
            UserId = assignment.UserId,
            RoleId = assignment.RoleId,
            RoleCode = assignment.Role?.Code ?? string.Empty,
            Action = "Revoked",
            PreviousValuesJson = prev,
            NewValuesJson = JsonSerializer.Serialize(new { IsActive = false, assignment.RevokedAt }),
            PerformedBy = actorEmail,
            Reason = reason?.Trim()
        });

        await _dbContext.SaveChangesAsync();
        await _eventPublisher.QueueSessionEventAsync("authorization.changed", assignment.Id.ToString(), assignment.UserId, "Allowed", $"RoleRevoked:{assignment.Role?.Code}");
        await _dbContext.SaveChangesAsync();
    }

    public async Task<List<RoleAssignmentHistoryDto>> GetHistoryAsync(string? userId = null, int limit = 100)
    {
        var bounded = Math.Clamp(limit, 1, 200);
        var query = _dbContext.RoleAssignmentHistories.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(userId))
            query = query.Where(h => h.UserId == userId.Trim());

        var rows = await query.OrderByDescending(h => h.Timestamp).Take(bounded).ToListAsync();
        var uids = rows.Select(r => r.UserId).Distinct().ToList();
        var emails = await _dbContext.Users
            .AsNoTracking()
            .Where(u => uids.Contains(u.Id))
            .ToDictionaryAsync(u => u.Id, u => u.Email);

        return rows.Select(h => new RoleAssignmentHistoryDto
        {
            Id = h.Id,
            UserId = h.UserId,
            UserEmail = emails.TryGetValue(h.UserId, out var em) ? em : null,
            RoleId = h.RoleId,
            RoleCode = h.RoleCode,
            Action = h.Action,
            PreviousValuesJson = h.PreviousValuesJson,
            NewValuesJson = h.NewValuesJson,
            PerformedBy = h.PerformedBy,
            Timestamp = h.Timestamp,
            Reason = h.Reason
        }).ToList();
    }
}
