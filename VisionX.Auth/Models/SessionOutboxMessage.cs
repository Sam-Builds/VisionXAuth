using System.Text.Json.Serialization;

namespace VisionX.Auth.Models;

public class SessionOutboxMessage
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string EventId { get; set; }
    public required string EventType { get; set; } // "session.revoked", "session.allowed"
    public required string SessionId { get; set; }
    public required string UserId { get; set; }
    public required string Status { get; set; } // "Blocked", "Allowed"
    public required string Reason { get; set; } // "UserLogout", "AdminRevocation", "AccountBanned"
    public required string PayloadJson { get; set; }
    public required string TargetApplication { get; set; }
    public required string WebhookUrl { get; set; }
    public required string Secret { get; set; }
    public string DeliveryStatus { get; set; } = "Pending"; // "Pending", "Delivered", "Failed"
    public int AttemptCount { get; set; } = 0;
    public DateTime? NextAttemptAt { get; set; } = DateTime.UtcNow;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ProcessedAt { get; set; }
    public string? LastError { get; set; }
}

public class SessionEventRecipientConfig
{
    public string Name { get; set; } = string.Empty;
    public string WebhookUrl { get; set; } = string.Empty;
    public string Secret { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
}

public class SessionEventsOptions
{
    public List<SessionEventRecipientConfig> Applications { get; set; } = new();
}

public class SessionEventPayload
{
    [JsonPropertyName("eventId")]
    public string EventId { get; set; } = string.Empty;

    [JsonPropertyName("eventType")]
    public string EventType { get; set; } = string.Empty;

    [JsonPropertyName("sessionId")]
    public string SessionId { get; set; } = string.Empty;

    [JsonPropertyName("userId")]
    public string UserId { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = string.Empty;

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = string.Empty;

    [JsonPropertyName("occurredAt")]
    public string OccurredAt { get; set; } = string.Empty;

    [JsonPropertyName("sequence")]
    public long Sequence { get; set; }
}
