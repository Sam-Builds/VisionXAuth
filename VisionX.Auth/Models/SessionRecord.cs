namespace VisionX.Auth.Models;

public class SessionRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string UserId { get; set; }
    public ApplicationUser? User { get; set; }
    public required string RefreshTokenHash { get; set; }
    public string? DeviceInfo { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
}
