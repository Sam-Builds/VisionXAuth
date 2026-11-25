using System.Security.Claims;
using VisionX.Auth.Models;
using VisionX.Auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace VisionX.Auth.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(AuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    [HttpPost("signup/request")]
    public async Task<IActionResult> RequestSignup([FromBody] SignupRequestDto request)
    {
        try
        {
            var result = await _authService.RequestSignupAsync(request);
            return Ok(result);
        }
        catch (AuthDomainException ex)
        {
            _logger.LogWarning("Signup request rejected for {Email}: {Code} - {Message}", request.Email, ex.Code, ex.Message);
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Signup request failed for {Email}", request.Email);
            return StatusCode(500, new AuthErrorResponseDto { Success = false, Code = "INTERNAL_SERVER_ERROR", Message = "An unexpected error occurred." });
        }
    }

    [HttpPost("signup/confirm")]
    public async Task<IActionResult> ConfirmSignup([FromBody] SignupConfirmRequestDto request)
    {
        try
        {
            var result = await _authService.ConfirmSignupAsync(request);
            return Ok(result);
        }
        catch (AuthDomainException ex)
        {
            _logger.LogWarning("Signup confirm rejected for {Email}: {Code} - {Message}", request.Email, ex.Code, ex.Message);
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Signup confirm failed for {Email}", request.Email);
            return StatusCode(500, new AuthErrorResponseDto { Success = false, Code = "INTERNAL_SERVER_ERROR", Message = "An unexpected error occurred." });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        try
        {
            var result = await _authService.LoginAsync(request);
            return Ok(result);
        }
        catch (AuthDomainException ex)
        {
            _logger.LogWarning("Login rejected for {Email}: {Code} - {Message}", request.Email, ex.Code, ex.Message);
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login failed for {Email}", request.Email);
            return StatusCode(500, new AuthErrorResponseDto { Success = false, Code = "INTERNAL_SERVER_ERROR", Message = "An unexpected error occurred." });
        }
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequestDto request)
    {
        try
        {
            var result = await _authService.RefreshAsync(request);
            return Ok(result);
        }
        catch (AuthDomainException ex)
        {
            _logger.LogWarning("Refresh rejected: {Code} - {Message}", ex.Code, ex.Message);
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Refresh failed");
            return StatusCode(500, new AuthErrorResponseDto { Success = false, Code = "INTERNAL_SERVER_ERROR", Message = "An unexpected error occurred." });
        }
    }

    [HttpPost("logout")]
    [Authorize]
    public async Task<IActionResult> Logout([FromBody] LogoutRequestDto request)
    {
        try
        {
            await _authService.LogoutAsync(request.RefreshToken);
            return Ok(new { message = "Session revoked." });
        }
        catch (AuthDomainException ex)
        {
            _logger.LogWarning("Logout rejected: {Code} - {Message}", ex.Code, ex.Message);
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout failed");
            return StatusCode(500, new AuthErrorResponseDto { Success = false, Code = "INTERNAL_SERVER_ERROR", Message = "An unexpected error occurred." });
        }
    }

    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> GetCurrentUser()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        if (string.IsNullOrWhiteSpace(userId))
        {
            return StatusCode(401, new AuthErrorResponseDto { Success = false, Code = "UNAUTHORIZED", Message = "User token is missing identity claim." });
        }

        try
        {
            var user = await _authService.GetCurrentUserAsync(userId);
            return Ok(user);
        }
        catch (AuthDomainException ex)
        {
            return StatusCode(ex.StatusCode, new AuthErrorResponseDto { Success = false, Code = ex.Code, Message = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "GetCurrentUser failed for {UserId}", userId);
            return StatusCode(500, new AuthErrorResponseDto { Success = false, Code = "INTERNAL_SERVER_ERROR", Message = "An unexpected error occurred." });
        }
    }
}
