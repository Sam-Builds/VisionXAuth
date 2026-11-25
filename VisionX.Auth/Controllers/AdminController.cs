using VisionX.Auth.Models;
using VisionX.Auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace VisionX.Auth.Controllers;

[ApiController]
[Route("api/admin")]
[Authorize(Policy = "AdminOnly")]
public class AdminController : ControllerBase
{
    private readonly AdminService _adminService;
    private readonly AdminDbService _adminDbService;

    public AdminController(AdminService adminService, AdminDbService adminDbService)
    {
        _adminService = adminService;
        _adminDbService = adminDbService;
    }

    [HttpGet("endpoints")]
    public IActionResult GetEndpointInventory()
    {
        var endpoints = new[]
        {
            new { method = "POST", path = "/api/auth/signup/request" },
            new { method = "POST", path = "/api/auth/signup/confirm" },
            new { method = "POST", path = "/api/auth/login" },
            new { method = "POST", path = "/api/auth/refresh" },
            new { method = "POST", path = "/api/auth/logout" },
            new { method = "GET", path = "/api/auth/me" },
            new { method = "GET", path = "/.well-known/jwks.json" },
            new { method = "GET", path = "/api/meta/version" },
            new { method = "GET", path = "/api/admin/config/domains" },
            new { method = "POST", path = "/api/admin/config/domains" },
            new { method = "GET", path = "/api/admin/users?search=&limit=50&offset=0" },
            new { method = "GET", path = "/api/admin/users/{userId}/sessions" },
            new { method = "POST", path = "/api/admin/users/{userId}/sessions/{sessionId}/revoke" },
            new { method = "POST", path = "/api/admin/users/{userId}/sessions/revoke-all" },
            new { method = "POST", path = "/api/admin/users/{userId}/ban" },
            new { method = "POST", path = "/api/admin/users/{userId}/unban" },
            new { method = "GET", path = "/api/admin/outbox?status=&limit=50&offset=0" },
            new { method = "POST", path = "/api/admin/outbox/{id}/retry" },
            new { method = "GET", path = "/api/admin/security" },
            new { method = "GET", path = "/api/admin/db/tables" },
            new { method = "GET", path = "/api/admin/db/tables/{table}/rows?limit=50&offset=0" },
            new { method = "POST", path = "/api/admin/db/tables/{table}/rows" },
            new { method = "PUT", path = "/api/admin/db/tables/{table}/rows" },
            new { method = "DELETE", path = "/api/admin/db/tables/{table}/rows" },
            new { method = "GET", path = "/api/auth/authorization/me" },
            new { method = "GET", path = "/api/admin/rbac/permissions" },
            new { method = "GET", path = "/api/admin/rbac/roles" },
            new { method = "POST", path = "/api/admin/rbac/roles" },
            new { method = "PUT", path = "/api/admin/rbac/roles/{roleId}/permissions" },
            new { method = "GET", path = "/api/admin/rbac/users/lookup?search=" },
            new { method = "GET", path = "/api/admin/rbac/assignments" },
            new { method = "POST", path = "/api/admin/rbac/assignments" },
            new { method = "POST", path = "/api/admin/rbac/assignments/{id}/revoke" },
            new { method = "GET", path = "/api/admin/rbac/history" }
        };

        return Ok(endpoints);
    }

    [HttpGet("config/domains")]
    public async Task<IActionResult> GetAllowedDomains()
    {
        var domains = await _adminService.GetAllowedDomainsAsync();
        return Ok(new AllowedDomainsResponseDto { Domains = domains });
    }

    [HttpPost("config/domains")]
    public async Task<IActionResult> SetAllowedDomains([FromBody] List<string> domains)
    {
        var updated = await _adminService.SetAllowedDomainsAsync(domains);
        return Ok(new AllowedDomainsResponseDto { Domains = updated });
    }

    [HttpGet("users")]
    public async Task<IActionResult> GetUsers([FromQuery] string? search = null, [FromQuery] int limit = 50, [FromQuery] int offset = 0)
    {
        var users = await _adminService.GetUsersAsync(search, limit, offset);
        return Ok(users);
    }

    [HttpGet("users/{userId}/sessions")]
    public async Task<IActionResult> GetUserSessions(string userId)
    {
        var sessions = await _adminService.GetSessionsAsync(userId);
        return Ok(sessions);
    }

    [HttpPost("users/{userId}/sessions/{sessionId}/revoke")]
    public async Task<IActionResult> RevokeSession(string userId, Guid sessionId)
    {
        try
        {
            await _adminService.RevokeSessionAsync(userId, sessionId);
            return Ok(new { message = "Session revoked." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("users/{userId}/sessions/revoke-all")]
    public async Task<IActionResult> RevokeAllUserSessions(string userId)
    {
        try
        {
            var count = await _adminService.RevokeAllUserSessionsAsync(userId);
            return Ok(new { revokedCount = count, message = $"Revoked {count} active session(s)." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("users/{userId}/ban")]
    public async Task<IActionResult> BanUser(string userId)
    {
        try
        {
            await _adminService.BanUserAsync(userId);
            return Ok(new { message = "User banned and active sessions revoked." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("users/{userId}/unban")]
    public async Task<IActionResult> UnbanUser(string userId)
    {
        try
        {
            await _adminService.UnbanUserAsync(userId);
            return Ok(new { message = "User unbanned." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("outbox")]
    public async Task<IActionResult> GetOutboxMessages([FromQuery] string? status = null, [FromQuery] int limit = 50, [FromQuery] int offset = 0)
    {
        var outbox = await _adminService.GetOutboxMessagesAsync(status, limit, offset);
        return Ok(outbox);
    }

    [HttpPost("outbox/{id}/retry")]
    public async Task<IActionResult> RetryOutboxMessage(Guid id)
    {
        try
        {
            await _adminService.RetryOutboxMessageAsync(id);
            return Ok(new { message = "Outbox message queued for retry." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("security")]
    public IActionResult GetSecuritySummary()
    {
        var summary = _adminService.GetSecuritySummary();
        return Ok(summary);
    }

    [HttpGet("db/tables")]
    public async Task<IActionResult> GetDbTables()
    {
        var tables = await _adminDbService.GetTablesAsync();
        return Ok(tables);
    }

    [HttpGet("db/tables/{table}/rows")]
    public async Task<IActionResult> GetDbRows(string table, [FromQuery] int limit = 50, [FromQuery] int offset = 0)
    {
        try
        {
            var rows = await _adminDbService.GetRowsAsync(table, limit, offset);
            return Ok(rows);
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("db/tables/{table}/rows")]
    public async Task<IActionResult> InsertDbRow(string table, [FromBody] AdminDbInsertRequestDto request)
    {
        try
        {
            var affected = await _adminDbService.InsertRowAsync(table, request.Values);
            return Ok(new { affected });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPut("db/tables/{table}/rows")]
    public async Task<IActionResult> UpdateDbRow(string table, [FromBody] AdminDbUpdateRequestDto request)
    {
        try
        {
            var affected = await _adminDbService.UpdateRowAsync(table, request.Keys, request.Values);
            return Ok(new { affected });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpDelete("db/tables/{table}/rows")]
    public async Task<IActionResult> DeleteDbRow(string table, [FromBody] AdminDbDeleteRequestDto request)
    {
        try
        {
            var affected = await _adminDbService.DeleteRowAsync(table, request.Keys);
            return Ok(new { affected });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }
}
