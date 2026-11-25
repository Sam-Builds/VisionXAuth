using System.Security.Cryptography;
using System.Text;
using VisionX.Auth.Data;
using VisionX.Auth.Models;
using Microsoft.EntityFrameworkCore;

namespace VisionX.Auth.Services;

public sealed class SessionOutboxDispatcherService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SessionOutboxDispatcherService> _logger;

    public SessionOutboxDispatcherService(
        IServiceProvider serviceProvider,
        IHttpClientFactory httpClientFactory,
        ILogger<SessionOutboxDispatcherService> logger)
    {
        _serviceProvider = serviceProvider;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SessionOutboxDispatcherService started.");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ProcessPendingMessagesAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error processing session outbox messages.");
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInformation("SessionOutboxDispatcherService stopped.");
    }

    private async Task ProcessPendingMessagesAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

        var pendingMessages = await db.OutboxMessages
            .Where(x => x.DeliveryStatus == "Pending" && (x.NextAttemptAt == null || x.NextAttemptAt <= DateTime.UtcNow))
            .OrderBy(x => x.CreatedAt)
            .Take(25)
            .ToListAsync(cancellationToken);

        if (pendingMessages.Count == 0)
        {
            return;
        }

        var client = _httpClientFactory.CreateClient("SessionOutboxClient");
        client.Timeout = TimeSpan.FromSeconds(10);

        foreach (var message in pendingMessages)
        {
            if (cancellationToken.IsCancellationRequested) break;

            try
            {
                var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                var signaturePayload = $"{timestamp}.{message.PayloadJson}";
                var signature = ComputeHmacSha256(signaturePayload, message.Secret);

                using var request = new HttpRequestMessage(HttpMethod.Post, message.WebhookUrl)
                {
                    Content = new StringContent(message.PayloadJson, Encoding.UTF8, "application/json")
                };

                request.Headers.Add("X-Event-Id", message.EventId);
                request.Headers.Add("X-Timestamp", timestamp);
                request.Headers.Add("X-Signature", signature);

                var response = await client.SendAsync(request, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    message.DeliveryStatus = "Delivered";
                    message.ProcessedAt = DateTime.UtcNow;
                    message.LastError = null;
                    _logger.LogInformation(
                        "Session event {EventId} successfully delivered to {Target} ({Url})",
                        message.EventId, message.TargetApplication, message.WebhookUrl);
                }
                else
                {
                    var responseBody = await response.Content.ReadAsStringAsync(cancellationToken);
                    HandleFailure(message, $"HTTP {(int)response.StatusCode}: {responseBody}");
                }
            }
            catch (Exception ex)
            {
                HandleFailure(message, ex.Message);
            }
        }

        await db.SaveChangesAsync(cancellationToken);
    }

    private void HandleFailure(SessionOutboxMessage message, string error)
    {
        message.AttemptCount++;
        message.LastError = error;

        if (message.AttemptCount >= 5)
        {
            message.DeliveryStatus = "Failed";
            message.ProcessedAt = DateTime.UtcNow;
            _logger.LogWarning(
                "Session event {EventId} to {Target} failed permanently after {Attempts} attempts. Error: {Error}",
                message.EventId, message.TargetApplication, message.AttemptCount, error);
        }
        else
        {
            var delaySeconds = Math.Pow(2, message.AttemptCount) * 2; // 4s, 8s, 16s, 32s
            message.NextAttemptAt = DateTime.UtcNow.AddSeconds(delaySeconds);
            _logger.LogInformation(
                "Session event {EventId} delivery to {Target} failed (attempt {Attempts}). Retrying in {Delay}s. Error: {Error}",
                message.EventId, message.TargetApplication, message.AttemptCount, delaySeconds, error);
        }
    }

    public static string ComputeHmacSha256(string data, string secretKey)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secretKey);
        using var hmac = new HMACSHA256(keyBytes);
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}
