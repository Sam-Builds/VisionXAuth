using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using VisionX.Auth.Models;
using Microsoft.IdentityModel.Tokens;

namespace VisionX.Auth.Services;

public sealed class TokenService : IDisposable
{
    private readonly IConfiguration _configuration;
    private readonly RSA _rsa;
    private readonly RsaSecurityKey _signingKey;
    private readonly string _keyId;

    public TokenService(IConfiguration configuration, ILogger<TokenService>? logger = null)
    {
        _configuration = configuration;
        _keyId = _configuration["Jwt:KeyId"] ?? "visionx-auth-rs256-v1";
        _rsa = LoadOrCreateRsaKey(_configuration, logger);
        _signingKey = new RsaSecurityKey(_rsa) { KeyId = _keyId };
    }

    private static RSA LoadOrCreateRsaKey(IConfiguration configuration, ILogger<TokenService>? logger)
    {
        var pem = configuration["Jwt:PrivateKeyPem"] ?? Environment.GetEnvironmentVariable("JWT_PRIVATE_KEY_PEM");
        if (!string.IsNullOrWhiteSpace(pem))
        {
            var normalizedPem = pem.Replace("\\n", "\n").Trim();
            var rsa = RSA.Create();
            rsa.ImportFromPem(normalizedPem);
            return rsa;
        }

        var path = configuration["Jwt:PrivateKeyPath"] ?? Environment.GetEnvironmentVariable("JWT_PRIVATE_KEY_PATH");
        if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
        {
            var filePem = File.ReadAllText(path);
            var rsa = RSA.Create();
            rsa.ImportFromPem(filePem);
            return rsa;
        }

        // Ephemeral fallback for local development or unit testing when no PEM is configured
        logger?.LogWarning(
            "No Jwt:PrivateKeyPem or Jwt:PrivateKeyPath configured; generated ephemeral 2048-bit RS256 keypair. Do not use ephemeral keys in multi-instance production.");
        return RSA.Create(2048);
    }

    public string CreateAccessToken(ApplicationUser user, bool isAdmin = false, string? sessionId = null)
    {
        var issuer = _configuration["Jwt:Issuer"] ?? "visionx-auth-service";
        var audience = _configuration["Jwt:Audience"] ?? "visionx-app";

        var credentials = new SigningCredentials(_signingKey, SecurityAlgorithms.RsaSha256);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new("role", isAdmin ? "admin" : "user"),
            new("immunity", user.Immunity ? "true" : "false"),
            new("email_verified", user.EmailVerified ? "true" : "false")
        };

        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            claims.Add(new("sid", sessionId));
        }

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(60),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public RsaSecurityKey GetValidationKey()
    {
        var publicParameters = _rsa.ExportParameters(includePrivateParameters: false);
        return new RsaSecurityKey(publicParameters) { KeyId = _keyId };
    }

    public string GetPublicKeyPem()
    {
        return _rsa.ExportSubjectPublicKeyInfoPem();
    }

    public string CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    public string HashToken(string token)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes);
    }

    public object GetJwks()
    {
        var parameters = _rsa.ExportParameters(includePrivateParameters: false);
        return new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    alg = "RS256",
                    kid = _keyId,
                    n = Base64UrlEncoder.Encode(parameters.Modulus),
                    e = Base64UrlEncoder.Encode(parameters.Exponent)
                }
            }
        };
    }

    public void Dispose()
    {
        _rsa.Dispose();
    }
}
