namespace VisionX.Auth.Models;

public class SignupRequestDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? MemberId { get; set; }
    public string? Usn { get => MemberId; set => MemberId = value; }
    public string? DeviceInfo { get; set; }
}

public class SignupConfirmRequestDto
{
    public string Email { get; set; } = string.Empty;
    public string Otp { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? DeviceInfo { get; set; }
}

public class LoginRequestDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? DeviceInfo { get; set; }
}

public class RefreshRequestDto
{
    public string RefreshToken { get; set; } = string.Empty;
    public string? DeviceInfo { get; set; }
}

public class LogoutRequestDto
{
    public string? RefreshToken { get; set; }
}

public class UserDetailsDto
{
    public int? AdmissionYear { get; set; }
    public string? Department { get; set; }
    public string? FirstName { get; set; }
    public string? EmailLocalPart { get; set; }
    public string? FullName { get; set; }
}

public class UserSummaryDto
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailVerified { get; set; }
    public bool Immunity { get; set; }
    public bool Banned { get; set; }
    public string? UserDetails { get; set; }
}

public class TokenResponseDto
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public int ExpiresInSeconds { get; set; } = 3600;
    public UserSummaryDto User { get; set; } = new();
}

public class OtpRequestResponseDto
{
    public string Message { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool DomainVerified { get; set; }
    public bool VisionXDomainVerified { get => DomainVerified; set => DomainVerified = value; }
    public bool Immunity { get; set; }
}

public class SessionViewDto
{
    public Guid Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string? DeviceInfo { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public bool IsActive => RevokedAt is null && ExpiresAt > DateTime.UtcNow;
}

public class AllowedDomainsResponseDto
{
    public List<string> Domains { get; set; } = new();
}

public class AdminUserItemDto
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public bool EmailVerified { get; set; }
    public bool Immunity { get; set; }
    public bool Banned { get; set; }
    public DateTime CreatedAt { get; set; }
    public string? UserDetails { get; set; }
    public int ActiveSessionCount { get; set; }
    public int TotalSessionCount { get; set; }
}

public class AdminUserListResponseDto
{
    public int TotalCount { get; set; }
    public int Limit { get; set; }
    public int Offset { get; set; }
    public List<AdminUserItemDto> Users { get; set; } = new();
}

public class AdminOutboxMessageDto
{
    public Guid Id { get; set; }
    public string EventId { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string SessionId { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public string TargetApplication { get; set; } = string.Empty;
    public string WebhookUrl { get; set; } = string.Empty;
    public string DeliveryStatus { get; set; } = string.Empty;
    public int AttemptCount { get; set; }
    public string? LastError { get; set; }
    public DateTime? NextAttemptAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ProcessedAt { get; set; }
}

public class AdminOutboxResponseDto
{
    public int PendingCount { get; set; }
    public int DeliveredCount { get; set; }
    public int FailedCount { get; set; }
    public List<AdminOutboxMessageDto> Messages { get; set; } = new();
}

public class AdminWebhookRecipientDto
{
    public string Name { get; set; } = string.Empty;
    public string WebhookUrl { get; set; } = string.Empty;
    public bool Enabled { get; set; }
    public bool HasSecretConfigured { get; set; }
}

public class AdminSecuritySummaryDto
{
    public string SigningAlgorithm { get; set; } = "RS256";
    public string KeyId { get; set; } = string.Empty;
    public string JwksPath { get; set; } = "/.well-known/jwks.json";
    public string PublicKeyPem { get; set; } = string.Empty;
    public List<AdminWebhookRecipientDto> WebhookRecipients { get; set; } = new();
}

public class AuthErrorResponseDto
{
    public bool Success { get; set; } = false;
    public string Code { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
}

public class AuthDomainException : Exception
{
    public string Code { get; }
    public int StatusCode { get; }

    public AuthDomainException(string code, string message, int statusCode = 400)
        : base(message)
    {
        Code = code;
        StatusCode = statusCode;
    }
}
