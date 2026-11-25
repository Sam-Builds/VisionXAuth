using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using VisionX.Auth.Models;
using VisionX.Auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace VisionX.Auth.Controllers;

[ApiController]
public sealed class RbacController : ControllerBase
{
    private readonly RbacService _rbacService;
    private readonly IConfiguration _configuration;

    public RbacController(RbacService rbacService, IConfiguration configuration)
    {
        _rbacService = rbacService;
        _configuration = configuration;
    }

    private string? GetActorUserId()
    {
        return User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
    }

    [HttpGet("api/auth/authorization/me")]
    [Authorize]
    public async Task<IActionResult> GetMyAuthorization()
    {
        var userId = GetActorUserId();
        if (string.IsNullOrWhiteSpace(userId))
        {
            return Unauthorized(new AuthErrorResponseDto { Success = false, Code = "UNAUTHORIZED", Message = "Missing identity claim." });
        }

        try
        {
            var effective = await _rbacService.GetEffectiveAuthorizationAsync(userId);
            return Ok(effective);
        }
        catch (AuthDomainException ex)
        {
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
    }

    [HttpGet("api/internal/authz/users/{userId}")]
    [AllowAnonymous]
    public async Task<IActionResult> GetInternalUserAuthorization(string userId)
    {
        var isAuthenticatedAdmin = User.Identity?.IsAuthenticated == true &&
            string.Equals(User.FindFirstValue("role"), "admin", StringComparison.OrdinalIgnoreCase);

        if (!isAuthenticatedAdmin && !HasValidInternalSecret())
        {
            return Unauthorized(new AuthErrorResponseDto { Success = false, Code = "INTERNAL_AUTH_REQUIRED", Message = "Invalid internal authorization credential." });
        }

        try
        {
            var effective = await _rbacService.GetEffectiveAuthorizationAsync(userId);
            return Ok(effective);
        }
        catch (AuthDomainException ex)
        {
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
    }

    [HttpGet("api/admin/rbac/permissions")]
    [Authorize]
    public async Task<IActionResult> GetPermissions()
    {
        var (authz, err) = await RequireAnyPermissionAsync("rbac.read", "rbac.manage");
        if (err is not null) return err;
        return Ok(await _rbacService.GetPermissionsAsync());
    }

    [HttpGet("api/admin/rbac/roles")]
    [Authorize]
    public async Task<IActionResult> GetRoles()
    {
        var (authz, err) = await RequireAnyPermissionAsync("rbac.read", "rbac.manage", "faculty.assign");
        if (err is not null) return err;
        var allRoles = await _rbacService.GetRolesAsync();
        if (!authz!.IsSuperAdmin && !authz.Permissions.Contains("rbac.manage", StringComparer.OrdinalIgnoreCase))
        {
            // HOD / departmental allocators can inspect assignable non-system-admin roles cleanly
            allRoles = allRoles.Where(r => r.Code != "SYSTEM_ADMIN").ToList();
        }
        return Ok(allRoles);
    }

    [HttpPost("api/admin/rbac/roles")]
    [Authorize]
    public async Task<IActionResult> CreateRole([FromBody] SaveRoleRequestDto request)
    {
        var (authz, err) = await RequireAnyPermissionAsync("rbac.manage");
        if (err is not null) return err;

        try
        {
            var created = await _rbacService.CreateCustomRoleAsync(request, authz!.UserId);
            return StatusCode(StatusCodes.Status201Created, created);
        }
        catch (AuthDomainException ex)
        {
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
    }

    [HttpPut("api/admin/rbac/roles/{roleId:guid}/permissions")]
    [Authorize]
    public async Task<IActionResult> UpdateRolePermissions(Guid roleId, [FromBody] UpdateRolePermissionsRequestDto request)
    {
        var (authz, err) = await RequireAnyPermissionAsync("rbac.manage");
        if (err is not null) return err;

        try
        {
            var updated = await _rbacService.UpdateRolePermissionsAsync(roleId, request, authz!.Email);
            return Ok(updated);
        }
        catch (AuthDomainException ex)
        {
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
    }

    [HttpGet("api/admin/rbac/users/lookup")]
    [Authorize]
    public async Task<IActionResult> LookupUsers([FromQuery] string? search = null, [FromQuery] int limit = 25)
    {
        var (_, err) = await RequireAnyPermissionAsync("users.read", "rbac.read", "rbac.manage", "faculty.assign");
        if (err is not null) return err;
        return Ok(await _rbacService.LookupUsersAsync(search, limit));
    }

    [HttpGet("api/admin/rbac/assignments")]
    [Authorize]
    public async Task<IActionResult> GetAssignments(
        [FromQuery] string? userId = null,
        [FromQuery] Guid? departmentId = null,
        [FromQuery] string? roleCode = null,
        [FromQuery] bool activeOnly = false)
    {
        var (authz, err) = await RequireAnyPermissionAsync("rbac.read", "rbac.manage", "faculty.assign");
        if (err is not null) return err;

        var rows = await _rbacService.GetAssignmentsAsync(userId, departmentId, roleCode, activeOnly);
        if (!authz!.IsSuperAdmin && !authz.Permissions.Contains("rbac.manage", StringComparer.OrdinalIgnoreCase))
        {
            var hodDepts = GetHodDepartmentIds(authz);
            rows = rows.Where(a => a.DepartmentId.HasValue && hodDepts.Contains(a.DepartmentId.Value)).ToList();
        }
        return Ok(rows);
    }

    [HttpPost("api/admin/rbac/assignments")]
    [Authorize]
    public async Task<IActionResult> AssignRole([FromBody] AssignUserRoleRequestDto request)
    {
        var (authz, err) = await RequireAnyPermissionAsync("rbac.manage", "faculty.assign");
        if (err is not null) return err;

        var canManageAll = authz!.IsSuperAdmin || authz.Permissions.Contains("rbac.manage", StringComparer.OrdinalIgnoreCase);
        var hodDepts = GetHodDepartmentIds(authz);

        try
        {
            var created = await _rbacService.AssignUserRoleAsync(request, authz.UserId, authz.Email, canManageAll, hodDepts);
            return StatusCode(StatusCodes.Status201Created, created);
        }
        catch (AuthDomainException ex)
        {
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
    }

    [HttpPost("api/admin/rbac/assignments/{assignmentId:guid}/revoke")]
    [Authorize]
    public async Task<IActionResult> RevokeAssignment(Guid assignmentId, [FromBody] RevokeRoleAssignmentRequestDto? request = null)
    {
        var (authz, err) = await RequireAnyPermissionAsync("rbac.manage", "faculty.assign");
        if (err is not null) return err;

        var canManageAll = authz!.IsSuperAdmin || authz.Permissions.Contains("rbac.manage", StringComparer.OrdinalIgnoreCase);
        var hodDepts = GetHodDepartmentIds(authz);

        try
        {
            await _rbacService.RevokeUserRoleAssignmentAsync(assignmentId, request?.Reason, authz.Email, canManageAll, hodDepts);
            return Ok(new { message = "Role assignment revoked." });
        }
        catch (AuthDomainException ex)
        {
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
    }

    [HttpGet("api/admin/rbac/history")]
    [Authorize]
    public async Task<IActionResult> GetAssignmentHistory([FromQuery] string? userId = null, [FromQuery] int limit = 100)
    {
        var (authz, err) = await RequireAnyPermissionAsync("rbac.read", "rbac.manage", "audit.read");
        if (err is not null) return err;

        if (!authz!.IsSuperAdmin && !authz.Permissions.Contains("rbac.manage", StringComparer.OrdinalIgnoreCase))
        {
            var hodDepts = GetHodDepartmentIds(authz);
            var allAssignments = await _rbacService.GetAssignmentsAsync();
            var allowedUserIds = allAssignments
                .Where(a => a.DepartmentId.HasValue && hodDepts.Contains(a.DepartmentId.Value))
                .Select(u => u.UserId)
                .ToHashSet();
            var rows = await _rbacService.GetHistoryAsync(userId, limit);
            return Ok(rows.Where(h => allowedUserIds.Contains(h.UserId)).ToList());
        }

        return Ok(await _rbacService.GetHistoryAsync(userId, limit));
    }

    private async Task<(EffectiveAuthorizationDto? Authz, IActionResult? Error)> RequireAnyPermissionAsync(params string[] requiredPermissions)
    {
        var userId = GetActorUserId();
        if (string.IsNullOrWhiteSpace(userId))
        {
            return (null, Unauthorized(new AuthErrorResponseDto { Success = false, Code = "UNAUTHORIZED", Message = "Missing user identity." }));
        }

        try
        {
            var authz = await _rbacService.GetEffectiveAuthorizationAsync(userId);
            if (authz.Banned)
            {
                return (null, StatusCode(403, new AuthErrorResponseDto { Success = false, Code = "ACCOUNT_BANNED", Message = "This account is banned." }));
            }
            if (authz.IsSuperAdmin)
            {
                return (authz, null);
            }
            var hasPerm = requiredPermissions.Any(req => authz.Permissions.Contains(req, StringComparer.OrdinalIgnoreCase));
            if (!hasPerm)
            {
                return (null, StatusCode(403, new AuthErrorResponseDto { Success = false, Code = "FORBIDDEN", Message = "Insufficient role permissions." }));
            }
            return (authz, null);
        }
        catch (AuthDomainException ex)
        {
            return (null, StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message }));
        }
    }

    private static HashSet<Guid> GetHodDepartmentIds(EffectiveAuthorizationDto authz)
    {
        return authz.Assignments
            .Where(a => a.IsActive && string.Equals(a.RoleCode, "HOD", StringComparison.OrdinalIgnoreCase) && a.DepartmentId.HasValue)
            .Select(a => a.DepartmentId!.Value)
            .ToHashSet();
    }

    private bool HasValidInternalSecret()
    {
        var provided = Request.Headers["X-Internal-Secret"].FirstOrDefault()?.Trim();
        if (string.IsNullOrWhiteSpace(provided)) return false;

        var configuredSecrets = new List<string>();
        var single = _configuration["Internal:SharedSecret"];
        if (!string.IsNullOrWhiteSpace(single)) configuredSecrets.Add(single);

        var apps = _configuration.GetSection("SessionEvents:Applications").GetChildren();
        foreach (var app in apps)
        {
            var sec = app["Secret"];
            if (!string.IsNullOrWhiteSpace(sec)) configuredSecrets.Add(sec);
        }
        if (configuredSecrets.Count == 0)
        {
            configuredSecrets.Add("change-me-webhook-secret");
        }

        var providedBytes = Encoding.UTF8.GetBytes(provided);
        return configuredSecrets.Any(secret =>
        {
            var expectedBytes = Encoding.UTF8.GetBytes(secret);
            return providedBytes.Length == expectedBytes.Length &&
                   CryptographicOperations.FixedTimeEquals(providedBytes, expectedBytes);
        });
    }
}
