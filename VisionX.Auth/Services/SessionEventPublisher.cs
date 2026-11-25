using System.Text.Json;
using VisionX.Auth.Data;
using VisionX.Auth.Models;

namespace VisionX.Auth.Services;

public interface ISessionEventPublisher
{
    Task QueueSessionEventAsync(string eventType, string sessionId, string userId, string status, string reason);
}

public sealed class SessionEventPublisher : ISessionEventPublisher
{
    private readonly AuthDbContext _dbContext;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SessionEventPublisher> _logger;
    private static long _lastSequence = DateTime.UtcNow.Ticks;

    public SessionEventPublisher(
        AuthDbContext dbContext,
        IConfiguration configuration,
        ILogger<SessionEventPublisher> logger)
    {
        _dbContext = dbContext;
        _configuration = configuration;
        _logger = logger;
    }

    private static long NextMonotonicSequence()
    {
        while (true)
        {
            var current = Interlocked.Read(ref _lastSequence);
            var now = DateTime.UtcNow.Ticks;
            var next = now > current ? now : current + 1;
            if (Interlocked.CompareExchange(ref _lastSequence, next, current) == current)
            {
                return next;
            }
        }
    }

    public Task QueueSessionEventAsync(string eventType, string sessionId, string userId, string status, string reason)
    {
        var recipients = _configuration.GetSection("SessionEvents:Applications")
            .Get<List<SessionEventRecipientConfig>>() ?? new List<SessionEventRecipientConfig>();

        // Fallback default if not explicitly configured in json
        if (recipients.Count == 0)
        {
            var defaultUrl = _configuration["SessionEvents:VisionXBackend:WebhookUrl"]
                ?? Environment.GetEnvironmentVariable("VISIONX_BACKEND_WEBHOOK_URL")
                ?? "https://api.visionx.io/api/internal/auth/session-events";
            var defaultSecret = _configuration["SessionEvents:VisionXBackend:Secret"]
                ?? Environment.GetEnvironmentVariable("SESSION_WEBHOOK_SECRET")
                ?? "change-me-webhook-secret";

            recipients.Add(new SessionEventRecipientConfig
            {
                Name = "VisionXBackend",
                WebhookUrl = defaultUrl,
                Secret = defaultSecret,
                Enabled = true
            });
        }

        var eventId = Guid.NewGuid().ToString("D");
        var occurredAt = DateTime.UtcNow.ToString("o");
        var sequence = NextMonotonicSequence();

        var payload = new SessionEventPayload
        {
            EventId = eventId,
            EventType = eventType,
            SessionId = sessionId,
            UserId = userId,
            Status = status,
            Reason = reason,
            OccurredAt = occurredAt,
            Sequence = sequence
        };

        var payloadJson = JsonSerializer.Serialize(payload);

        foreach (var recipient in recipients.Where(r => r.Enabled && !string.IsNullOrWhiteSpace(r.WebhookUrl)))
        {
            var outboxMessage = new SessionOutboxMessage
            {
                EventId = eventId,
                EventType = eventType,
                SessionId = sessionId,
                UserId = userId,
                Status = status,
                Reason = reason,
                PayloadJson = payloadJson,
                TargetApplication = recipient.Name,
                WebhookUrl = recipient.WebhookUrl,
                Secret = recipient.Secret,
                DeliveryStatus = "Pending",
                AttemptCount = 0,
                NextAttemptAt = DateTime.UtcNow,
                CreatedAt = DateTime.UtcNow
            };

            _dbContext.OutboxMessages.Add(outboxMessage);
        }

        _logger.LogInformation(
            "Queued session event {EventType} (seq={Sequence}) for user {UserId}, session {SessionId}, status {Status}, recipients: {Count}",
            eventType, sequence, userId, sessionId, status, recipients.Count);

        return Task.CompletedTask;
    }
}
