using System.Text;
using System.Text.Json;

namespace VisionX.Auth.Services;

public interface IEmailService
{
    Task SendOtpEmailAsync(string toEmail, string otp);
}

public sealed class BrevoEmailService : IEmailService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<BrevoEmailService> _logger;

    public BrevoEmailService(HttpClient httpClient, IConfiguration configuration, ILogger<BrevoEmailService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
    }

    private string? ResolveConfig(params string[] keys)
    {
        foreach (var key in keys)
        {
            var value = _configuration[key];
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value.Trim();
            }

            var envValue = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrWhiteSpace(envValue))
            {
                return envValue.Trim();
            }
        }
        return null;
    }

    public async Task SendOtpEmailAsync(string toEmail, string otp)
    {
        var apiKey = ResolveConfig(
            "BREVO_API_KEY",
            "Brevo:ApiKey",
            "Brevo__ApiKey",
            "BREVO_KEY",
            "BrevoApiKey");

        var senderEmail = ResolveConfig(
            "BREVO_SENDER_EMAIL",
            "Brevo:SenderEmail",
            "Brevo__SenderEmail") ?? "notifications@visionx.io";

        var senderName = ResolveConfig(
            "BREVO_SENDER_NAME",
            "Brevo:SenderName",
            "Brevo__SenderName") ?? "VisionX";

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            _logger.LogWarning("Brevo API key is not configured. OTP email for {Email} was skipped. (Console OTP: {Otp})", toEmail, otp);
            return;
        }

        var payload = new
        {
            sender = new { name = senderName, email = senderEmail },
            to = new[] { new { email = toEmail } },
            subject = "Your VisionX Verification Code",
            htmlContent = $@"
                <div style='font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 24px; border: 1px solid #eaeaea; border-radius: 12px; background-color: #ffffff;'>
                    <h2 style='color: #1a1a1a; margin-top: 0;'>Email Verification</h2>
                    <p style='color: #4a4a4a; font-size: 15px; line-height: 1.5;'>Use the following verification code to complete your signup for the VisionX:</p>
                    <div style='background-color: #f7f7f8; padding: 18px; border-radius: 8px; text-align: center; margin: 24px 0;'>
                        <span style='font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #CC6A29;'>{otp}</span>
                    </div>
                    <p style='color: #666666; font-size: 13px; line-height: 1.4;'>This code will expire in <strong>10 minutes</strong>. If you did not request this verification, you can safely ignore this email.</p>
                    <hr style='border: none; border-top: 1px solid #eaeaea; margin: 24px 0;' />
                    <p style='color: #999999; font-size: 12px; text-align: center; margin-bottom: 0;'>&copy; {DateTime.UtcNow.Year} {senderName}. All rights reserved.</p>
                </div>",
            textContent = $"Your VisionX verification code is {otp}. This code expires in 10 minutes."
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.brevo.com/v3/smtp/email");
        request.Headers.Add("api-key", apiKey);
        request.Headers.Add("accept", "application/json");
        request.Content = new StringContent(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8,
            "application/json");

        try
        {
            var response = await _httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync();
                _logger.LogError("Brevo API returned error HTTP {StatusCode} when sending to {Email}: {Error}", response.StatusCode, toEmail, errorBody);
            }
            else
            {
                _logger.LogInformation("Successfully dispatched OTP email via Brevo to {Email}", toEmail);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Network exception communicating with Brevo API for {Email}", toEmail);
        }
    }
}
