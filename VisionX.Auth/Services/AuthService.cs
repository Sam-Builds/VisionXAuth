using System.Text.Json;
using System.Text.RegularExpressions;
using VisionX.Auth.Data;
using VisionX.Auth.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace VisionX.Auth.Services;

public sealed class AuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthDbContext _dbContext;
    private readonly TokenService _tokenService;
    private readonly OtpService _otpService;
    private readonly ISessionEventPublisher _eventPublisher;
    private readonly ILogger<AuthService> _logger;
    private readonly IConfiguration _configuration;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        AuthDbContext dbContext,
        TokenService tokenService,
        OtpService otpService,
        ISessionEventPublisher eventPublisher,
        ILogger<AuthService> logger,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _dbContext = dbContext;
        _tokenService = tokenService;
        _otpService = otpService;
        _eventPublisher = eventPublisher;
        _logger = logger;
        _configuration = configuration;
    }

    public async Task<OtpRequestResponseDto> RequestSignupAsync(SignupRequestDto request)
    {
        var email = NormalizeEmail(request.Email);
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new AuthDomainException("INVALID_EMAIL", "Email is required.", 400);
        }

        if (await _userManager.FindByEmailAsync(email) is not null)
        {
            throw new AuthDomainException("USER_ALREADY_EXISTS", "A user with this email already exists.", 409);
        }

        var allowedDomains = await GetAllowedDomainsAsync();
        var domain = GetDomain(email);
        var isVisionXDomain = allowedDomains.Contains(domain, StringComparer.OrdinalIgnoreCase);

        await _otpService.IssueOtpAsync(email);

        return new OtpRequestResponseDto
        {
            Message = "OTP has been sent to the supplied email.",
            Email = email,
            DomainVerified = isVisionXDomain,
            Immunity = isVisionXDomain
        };
    }

    public async Task<TokenResponseDto> ConfirmSignupAsync(SignupConfirmRequestDto request)
    {
        var email = NormalizeEmail(request.Email);
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new AuthDomainException("INVALID_EMAIL", "Email is required.", 400);
        }

        var existingUser = await _userManager.FindByEmailAsync(email);
        if (existingUser is not null)
        {
            throw new AuthDomainException("USER_ALREADY_EXISTS", "This account already exists.", 409);
        }

        var otpStatus = await _otpService.VerifyStatusAsync(email, request.Otp);
        if (otpStatus == OtpVerificationStatus.Expired)
        {
            throw new AuthDomainException("OTP_EXPIRED", "The OTP has expired. Please request a new one.", 400);
        }
        if (otpStatus == OtpVerificationStatus.MaxAttemptsExceeded)
        {
            throw new AuthDomainException("OTP_MAX_ATTEMPTS", "Maximum OTP verification attempts exceeded. Please request a new code.", 400);
        }
        if (otpStatus != OtpVerificationStatus.Success)
        {
            throw new AuthDomainException("INVALID_OTP", "The OTP was invalid.", 400);
        }

        var allowedDomains = await GetAllowedDomainsAsync();
        var domain = GetDomain(email);
        var isVisionXDomain = allowedDomains.Contains(domain, StringComparer.OrdinalIgnoreCase);

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailVerified = true,
            Immunity = isVisionXDomain,
            Banned = false,
            CreatedAt = DateTime.UtcNow,
            UserDetails = BuildUserDetailsJson(email, isVisionXDomain)
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            throw new AuthDomainException("USER_CREATION_FAILED", string.Join("; ", result.Errors.Select(x => x.Description)), 400);
        }

        var sessionId = Guid.NewGuid();
        var refreshToken = _tokenService.CreateRefreshToken();

        var session = new SessionRecord
        {
            Id = sessionId,
            UserId = user.Id,
            RefreshTokenHash = _tokenService.HashToken(refreshToken),
            DeviceInfo = NormalizeDeviceInfoJson(request.DeviceInfo),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(30)
        };

        await PersistSessionAsync(session, "confirm-signup", user.Id);
        var accessToken = _tokenService.CreateAccessToken(user, sessionId: sessionId.ToString());

        return new TokenResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresInSeconds = 3600,
            User = MapUserSummary(user)
        };
    }

    public async Task<TokenResponseDto> LoginAsync(LoginRequestDto request)
    {
        var email = NormalizeEmail(request.Email);
        var user = await _userManager.FindByEmailAsync(email);
        if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password))
        {
            throw new AuthDomainException("INVALID_CREDENTIALS", "Invalid credentials.", 401);
        }

        if (user.Banned)
        {
            throw new AuthDomainException("ACCOUNT_BANNED", "This account has been banned.", 403);
        }

        var sessionId = Guid.NewGuid();
        var refreshToken = _tokenService.CreateRefreshToken();

        var session = new SessionRecord
        {
            Id = sessionId,
            UserId = user.Id,
            RefreshTokenHash = _tokenService.HashToken(refreshToken),
            DeviceInfo = NormalizeDeviceInfoJson(request.DeviceInfo),
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(30)
        };

        await PersistSessionAsync(session, "login", user.Id);
        var accessToken = _tokenService.CreateAccessToken(user, await IsAdminAsync(user), sessionId.ToString());

        return new TokenResponseDto
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresInSeconds = 3600,
            User = MapUserSummary(user)
        };
    }

    public async Task<TokenResponseDto> RefreshAsync(RefreshRequestDto request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            throw new AuthDomainException("INVALID_REFRESH_TOKEN", "Refresh token is required.", 400);
        }

        var hash = _tokenService.HashToken(request.RefreshToken);
        var session = await _dbContext.Sessions
            .Include(x => x.User)
            .FirstOrDefaultAsync(x => x.RefreshTokenHash == hash && x.RevokedAt == null && x.ExpiresAt > DateTime.UtcNow);

        if (session is null || session.User is null)
        {
            throw new AuthDomainException("REFRESH_TOKEN_EXPIRED", "Refresh token is invalid or expired.", 401);
        }

        if (session.User.Banned)
        {
            throw new AuthDomainException("ACCOUNT_BANNED", "This account has been banned.", 403);
        }

        var newRefreshToken = _tokenService.CreateRefreshToken();
        session.RefreshTokenHash = _tokenService.HashToken(newRefreshToken);
        session.ExpiresAt = DateTime.UtcNow.AddDays(30);
        if (!string.IsNullOrWhiteSpace(request.DeviceInfo))
        {
            session.DeviceInfo = NormalizeDeviceInfoJson(request.DeviceInfo);
        }

        // Keep session ID (sid) stable across ordinary refresh rotation; never revoke session A on refresh
        await _eventPublisher.QueueSessionEventAsync("session.allowed", session.Id.ToString(), session.UserId, "Allowed", "RefreshTokenRotated");
        try
        {
            await _dbContext.SaveChangesAsync();
        }
        catch (DbUpdateException ex)
        {
            var inner = ex.InnerException?.Message ?? "no inner exception";
            _logger.LogError(ex, "Session persistence failed on refresh for user {UserId}. Inner: {Inner}", session.UserId, inner);
            throw new InvalidOperationException($"Session save failed during refresh. {inner}");
        }

        return new TokenResponseDto
        {
            AccessToken = _tokenService.CreateAccessToken(session.User, await IsAdminAsync(session.User), session.Id.ToString()),
            RefreshToken = newRefreshToken,
            ExpiresInSeconds = 3600,
            User = MapUserSummary(session.User)
        };
    }

    public async Task LogoutAsync(string? refreshToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return;
        }

        var hash = _tokenService.HashToken(refreshToken);
        var session = await _dbContext.Sessions
            .FirstOrDefaultAsync(x => x.RefreshTokenHash == hash && x.RevokedAt == null);

        if (session is not null)
        {
            session.RevokedAt = DateTime.UtcNow;
            await _eventPublisher.QueueSessionEventAsync("session.revoked", session.Id.ToString(), session.UserId, "Blocked", "UserLogout");
            await _dbContext.SaveChangesAsync();
        }
    }

    public async Task<UserSummaryDto> GetCurrentUserAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            throw new AuthDomainException("USER_NOT_FOUND", "User not found.", 404);
        }

        if (user.Banned)
        {
            throw new AuthDomainException("ACCOUNT_BANNED", "This account has been banned.", 403);
        }

        return MapUserSummary(user);
    }

    public async Task<List<string>> GetAllowedDomainsAsync()
    {
        var config = await _dbContext.AppConfigs
            .FirstOrDefaultAsync(x => x.Key == "allowed_domains");

        if (config is null)
        {
            return new List<string>();
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<List<string>>(config.Value);
            return parsed ?? new List<string>();
        }
        catch
        {
            return new List<string>();
        }
    }

    public async Task UpdateAllowedDomainsAsync(List<string> domains)
    {
        var normalized = domains
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var config = await _dbContext.AppConfigs.FirstOrDefaultAsync(x => x.Key == "allowed_domains");
        var payload = JsonSerializer.Serialize(normalized);

        if (config is null)
        {
            _dbContext.AppConfigs.Add(new AppConfig { Key = "allowed_domains", Value = payload });
        }
        else
        {
            config.Value = payload;
            config.UpdatedAt = DateTime.UtcNow;
        }

        await _dbContext.SaveChangesAsync();
    }

    public async Task<List<SessionViewDto>> GetSessionsAsync(string userId)
    {
        var sessions = await _dbContext.Sessions
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.CreatedAt)
            .Select(x => new SessionViewDto
            {
                Id = x.Id,
                UserId = x.UserId,
                DeviceInfo = x.DeviceInfo,
                CreatedAt = x.CreatedAt,
                ExpiresAt = x.ExpiresAt,
                RevokedAt = x.RevokedAt
            })
            .ToListAsync();

        return sessions;
    }

    public async Task RevokeSessionAsync(string userId, Guid sessionId)
    {
        var session = await _dbContext.Sessions
            .FirstOrDefaultAsync(x => x.UserId == userId && x.Id == sessionId);

        if (session is null)
        {
            throw new InvalidOperationException("Session not found.");
        }

        session.RevokedAt = DateTime.UtcNow;
        await _eventPublisher.QueueSessionEventAsync("session.revoked", session.Id.ToString(), session.UserId, "Blocked", "AdminRevocation");
        await _dbContext.SaveChangesAsync();
    }

    public async Task BanUserAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            throw new AuthDomainException("USER_NOT_FOUND", "User not found.", 404);
        }

        user.Banned = true;

        var activeSessions = await _dbContext.Sessions
            .Where(x => x.UserId == userId && x.RevokedAt == null)
            .ToListAsync();

        foreach (var s in activeSessions)
        {
            s.RevokedAt = DateTime.UtcNow;
            await _eventPublisher.QueueSessionEventAsync("session.revoked", s.Id.ToString(), userId, "Blocked", "AccountBanned");
        }

        await _userManager.UpdateAsync(user);
        await _dbContext.SaveChangesAsync();
    }

    public async Task UnbanUserAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            throw new AuthDomainException("USER_NOT_FOUND", "User not found.", 404);
        }

        user.Banned = false;
        await _userManager.UpdateAsync(user);
    }

    private static string NormalizeEmail(string value)
    {
        return value?.Trim() ?? string.Empty;
    }

    private static string GetDomain(string email)
    {
        var index = email.LastIndexOf('@');
        return index >= 0 ? email[(index + 1)..].Trim() : string.Empty;
    }

    private static string? BuildUserDetailsJson(string email, bool isAllowed)
    {
        if (!isAllowed)
        {
            return null;
        }

        var localPart = email.Split('@')[0];
        string firstName = localPart;
        string? lastName = null;

        var nameMatch = Regex.Match(localPart, @"^(?<first>[A-Za-z]+)[\.\-_](?<last>[A-Za-z]+)$");
        if (nameMatch.Success)
        {
            firstName = char.ToUpper(nameMatch.Groups["first"].Value[0]) + nameMatch.Groups["first"].Value[1..].ToLower();
            lastName = char.ToUpper(nameMatch.Groups["last"].Value[0]) + nameMatch.Groups["last"].Value[1..].ToLower();
        }
        else if (localPart.Length > 0 && char.IsLetter(localPart[0]))
        {
            firstName = char.ToUpper(localPart[0]) + (localPart.Length > 1 ? localPart[1..].ToLower() : string.Empty);
        }

        var fullName = string.IsNullOrWhiteSpace(lastName) ? firstName : $"{firstName} {lastName}";

        var details = new UserDetailsDto
        {
            FirstName = firstName,
            EmailLocalPart = localPart,
            FullName = fullName
        };

        return JsonSerializer.Serialize(details);
    }

    private static UserSummaryDto MapUserSummary(ApplicationUser user)
    {
        return new UserSummaryDto
        {
            Id = user.Id,
            Email = user.Email ?? string.Empty,
            EmailVerified = user.EmailVerified,
            Immunity = user.Immunity,
            Banned = user.Banned,
            UserDetails = user.UserDetails
        };
    }

    private async Task<bool> IsAdminAsync(ApplicationUser user)
    {
        var claims = await _userManager.GetClaimsAsync(user);
        if (claims.Any(c => c.Type == "role" && c.Value == "admin"))
        {
            return true;
        }

        var adminEmail = _configuration["Admin:Email"];
        if (!string.IsNullOrWhiteSpace(adminEmail)
            && string.Equals(user.Email, adminEmail, StringComparison.OrdinalIgnoreCase))
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
                && a.Role != null
                && a.Role.IsActive
                && a.Role.Code == "SYSTEM_ADMIN");
    }

    private async Task PersistSessionAsync(SessionRecord session, string flow, string userId)
    {
        _dbContext.Sessions.Add(session);
        await _eventPublisher.QueueSessionEventAsync("session.allowed", session.Id.ToString(), userId, "Allowed", $"SessionCreated:{flow}");
        try
        {
            await _dbContext.SaveChangesAsync();
        }
        catch (DbUpdateException ex)
        {
            var inner = ex.InnerException?.Message ?? "no inner exception";
            _logger.LogError(ex, "Session persistence failed on {Flow} for user {UserId}. Inner: {Inner}", flow, userId, inner);
            throw new InvalidOperationException($"Session save failed during {flow}. {inner}");
        }
    }

    private static string NormalizeDeviceInfoJson(string? rawValue)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
        {
            return "{\"label\":\"unknown\"}";
        }

        var value = rawValue.Trim();
        try
        {
            using var doc = JsonDocument.Parse(value);
            return JsonSerializer.Serialize(doc.RootElement);
        }
        catch
        {
            return JsonSerializer.Serialize(new Dictionary<string, string>
            {
                ["raw"] = value
            });
        }
    }
}
