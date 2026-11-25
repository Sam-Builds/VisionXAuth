using Microsoft.AspNetCore.Identity;

namespace VisionX.Auth.Models;

public class ApplicationUser : IdentityUser
{
    public bool EmailVerified { get; set; }
    public bool Immunity { get; set; }
    public bool Banned { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? UserDetails { get; set; }

    public ICollection<SessionRecord> Sessions { get; set; } = new List<SessionRecord>();
}
