using System.Security.Cryptography;
using System.Text;
using VisionX.Auth.Data;
using VisionX.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace VisionX.Auth.Services;

public enum OtpVerificationStatus
{
    Success,
    NotFound,
    Expired,
    MaxAttemptsExceeded,
    Invalid
}

public sealed class OtpService
{
    private readonly AuthDbContext _dbContext;
    private readonly IEmailService _emailService;

    public OtpService(AuthDbContext dbContext, IEmailService emailService)
    {
        _dbContext = dbContext;
        _emailService = emailService;
    }

    public async Task<string> IssueOtpAsync(string email, string? userId = null)
    {
        var normalizedEmail = email.Trim();
        var otp = Random.Shared.Next(100000, 999999).ToString("D6");
        var challenge = new OtpChallenge
        {
            Email = normalizedEmail,
            UserId = userId,
            OtpHash = HashOtp(otp),
            ExpiresAt = DateTime.UtcNow.AddMinutes(10),
            Attempts = 0,
            UsedAt = null,
            CreatedAt = DateTime.UtcNow
        };

        var oldChallenges = await _dbContext.OtpChallenges
            .Where(x => x.Email == normalizedEmail && x.UsedAt == null)
            .ToListAsync();

        _dbContext.OtpChallenges.RemoveRange(oldChallenges);
        _dbContext.OtpChallenges.Add(challenge);
        await _dbContext.SaveChangesAsync();

        Console.WriteLine($"OTP for {normalizedEmail}: {otp}");

        // Dispatch OTP email via Brevo
        await _emailService.SendOtpEmailAsync(normalizedEmail, otp);

        return otp;
    }

    public async Task<OtpVerificationStatus> VerifyStatusAsync(string email, string otp)
    {
        var challenge = await _dbContext.OtpChallenges
            .Where(x => x.Email == email.Trim() && x.UsedAt == null)
            .OrderByDescending(x => x.CreatedAt)
            .FirstOrDefaultAsync();

        if (challenge is null)
        {
            return OtpVerificationStatus.NotFound;
        }

        if (DateTime.UtcNow > challenge.ExpiresAt)
        {
            _dbContext.OtpChallenges.Remove(challenge);
            await _dbContext.SaveChangesAsync();
            return OtpVerificationStatus.Expired;
        }

        if (challenge.Attempts >= 5)
        {
            return OtpVerificationStatus.MaxAttemptsExceeded;
        }

        if (!string.Equals(challenge.OtpHash, HashOtp(otp), StringComparison.Ordinal))
        {
            challenge.Attempts += 1;
            await _dbContext.SaveChangesAsync();
            return OtpVerificationStatus.Invalid;
        }

        challenge.UsedAt = DateTime.UtcNow;
        await _dbContext.SaveChangesAsync();
        return OtpVerificationStatus.Success;
    }

    public async Task<bool> VerifyAsync(string email, string otp)
    {
        return (await VerifyStatusAsync(email, otp)) == OtpVerificationStatus.Success;
    }

    private static string HashOtp(string otp)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(otp.Trim()));
        return Convert.ToHexString(bytes);
    }
}
