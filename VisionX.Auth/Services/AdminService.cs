using VisionX.Auth.Data;
using VisionX.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace VisionX.Auth.Services;

public sealed class AdminService
{
    private readonly AuthDbContext _dbContext;
    private readonly AuthService _authService;
    private readonly TokenService _tokenService;
    private readonly ISessionEventPublisher _eventPublisher;
    private readonly IConfiguration _configuration;

    public AdminService(
        AuthDbContext dbContext,
        AuthService authService,
        TokenService tokenService,
        ISessionEventPublisher eventPublisher,
        IConfiguration configuration)
    {
        _dbContext = dbContext;
        _authService = authService;
        _tokenService = tokenService;
        _eventPublisher = eventPublisher;
        _configuration = configuration;
    }

    public async Task<List<string>> GetAllowedDomainsAsync()
    {
        return await _authService.GetAllowedDomainsAsync();
    }

    public async Task<List<string>> SetAllowedDomainsAsync(List<string> domains)
    {
        await _authService.UpdateAllowedDomainsAsync(domains);
        return await _authService.GetAllowedDomainsAsync();
    }

    public async Task<AdminUserListResponseDto> GetUsersAsync(string? search = null, int limit = 50, int offset = 0)
    {
        var boundedLimit = Math.Clamp(limit, 1, 100);
        var boundedOffset = Math.Max(offset, 0);
        var now = DateTime.UtcNow;

        var query = _dbContext.Users.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim().ToLower();
            query = query.Where(u =>
                (u.Email != null && u.Email.ToLower().Contains(term)) ||
                u.Id.ToLower().Contains(term));
        }

        var totalCount = await query.CountAsync();
        var users = await query
            .OrderByDescending(u => u.CreatedAt)
            .Skip(boundedOffset)
            .Take(boundedLimit)
            .Select(u => new AdminUserItemDto
            {
                Id = u.Id,
                Email = u.Email ?? string.Empty,
                EmailVerified = u.EmailVerified,
                Immunity = u.Immunity,
                Banned = u.Banned,
                CreatedAt = u.CreatedAt,
                UserDetails = u.UserDetails,
                ActiveSessionCount = u.Sessions.Count(s => s.RevokedAt == null && s.ExpiresAt > now),
                TotalSessionCount = u.Sessions.Count()
            })
            .ToListAsync();

        return new AdminUserListResponseDto
        {
            TotalCount = totalCount,
            Limit = boundedLimit,
            Offset = boundedOffset,
            Users = users
        };
    }

    public async Task<List<SessionViewDto>> GetSessionsAsync(string userId)
    {
        return await _authService.GetSessionsAsync(userId);
    }

    public async Task RevokeSessionAsync(string userId, Guid sessionId)
    {
        await _authService.RevokeSessionAsync(userId, sessionId);
    }

    public async Task<int> RevokeAllUserSessionsAsync(string userId)
    {
        var activeSessions = await _dbContext.Sessions
            .Where(x => x.UserId == userId && x.RevokedAt == null)
            .ToListAsync();

        foreach (var session in activeSessions)
        {
            session.RevokedAt = DateTime.UtcNow;
            await _eventPublisher.QueueSessionEventAsync("session.revoked", session.Id.ToString(), userId, "Blocked", "AdminRevocationAll");
        }

        if (activeSessions.Count > 0)
        {
            await _dbContext.SaveChangesAsync();
        }

        return activeSessions.Count;
    }

    public async Task BanUserAsync(string userId)
    {
        await _authService.BanUserAsync(userId);
    }

    public async Task UnbanUserAsync(string userId)
    {
        await _authService.UnbanUserAsync(userId);
    }

    public async Task<AdminOutboxResponseDto> GetOutboxMessagesAsync(string? status = null, int limit = 50, int offset = 0)
    {
        var boundedLimit = Math.Clamp(limit, 1, 100);
        var boundedOffset = Math.Max(offset, 0);

        var pendingCount = await _dbContext.OutboxMessages.CountAsync(x => x.DeliveryStatus == "Pending");
        var deliveredCount = await _dbContext.OutboxMessages.CountAsync(x => x.DeliveryStatus == "Delivered");
        var failedCount = await _dbContext.OutboxMessages.CountAsync(x => x.DeliveryStatus == "Failed");

        var query = _dbContext.OutboxMessages.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(status) && !string.Equals(status, "all", StringComparison.OrdinalIgnoreCase))
        {
            var normalized = status.Trim();
            query = query.Where(x => x.DeliveryStatus == normalized);
        }

        var messages = await query
            .OrderByDescending(x => x.CreatedAt)
            .Skip(boundedOffset)
            .Take(boundedLimit)
            .Select(x => new AdminOutboxMessageDto
            {
                Id = x.Id,
                EventId = x.EventId,
                EventType = x.EventType,
                SessionId = x.SessionId,
                UserId = x.UserId,
                Status = x.Status,
                Reason = x.Reason,
                TargetApplication = x.TargetApplication,
                WebhookUrl = x.WebhookUrl,
                DeliveryStatus = x.DeliveryStatus,
                AttemptCount = x.AttemptCount,
                LastError = x.LastError,
                NextAttemptAt = x.NextAttemptAt,
                CreatedAt = x.CreatedAt,
                ProcessedAt = x.ProcessedAt
            })
            .ToListAsync();

        return new AdminOutboxResponseDto
        {
            PendingCount = pendingCount,
            DeliveredCount = deliveredCount,
            FailedCount = failedCount,
            Messages = messages
        };
    }

    public async Task RetryOutboxMessageAsync(Guid outboxId)
    {
        var msg = await _dbContext.OutboxMessages.FirstOrDefaultAsync(x => x.Id == outboxId);
        if (msg == null)
        {
            throw new InvalidOperationException("Outbox message not found.");
        }

        msg.DeliveryStatus = "Pending";
        msg.AttemptCount = 0;
        msg.LastError = null;
        msg.ProcessedAt = null;
        msg.NextAttemptAt = DateTime.UtcNow;

        await _dbContext.SaveChangesAsync();
    }

    public AdminSecuritySummaryDto GetSecuritySummary()
    {
        var recipients = _configuration.GetSection("SessionEvents:Applications")
            .Get<List<SessionEventRecipientConfig>>() ?? new List<SessionEventRecipientConfig>();

        if (recipients.Count == 0)
        {
            var fallbackUrl = _configuration["SessionEvents:VisionXBackend:WebhookUrl"]
                ?? Environment.GetEnvironmentVariable("VISIONX_BACKEND_WEBHOOK_URL")
                ?? "https://api.visionx.io/api/internal/auth/session-events";
            var fallbackSecret = _configuration["SessionEvents:VisionXBackend:Secret"]
                ?? Environment.GetEnvironmentVariable("SESSION_WEBHOOK_SECRET");

            recipients.Add(new SessionEventRecipientConfig
            {
                Name = "VisionXBackend",
                WebhookUrl = fallbackUrl,
                Secret = fallbackSecret ?? string.Empty,
                Enabled = true
            });
        }

        return new AdminSecuritySummaryDto
        {
            SigningAlgorithm = "RS256",
            KeyId = _configuration["Jwt:KeyId"] ?? "visionx-auth-rs256-v1",
            JwksPath = "/.well-known/jwks.json",
            PublicKeyPem = _tokenService.GetPublicKeyPem(),
            WebhookRecipients = recipients.Select(r => new AdminWebhookRecipientDto
            {
                Name = r.Name,
                WebhookUrl = r.WebhookUrl,
                Enabled = r.Enabled,
                HasSecretConfigured = !string.IsNullOrWhiteSpace(r.Secret)
            }).ToList()
        };
    }
}
