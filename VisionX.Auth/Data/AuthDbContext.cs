using VisionX.Auth.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace VisionX.Auth.Data;

public class AuthDbContext : IdentityDbContext<ApplicationUser>
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }

    public DbSet<SessionRecord> Sessions => Set<SessionRecord>();
    public DbSet<OtpChallenge> OtpChallenges => Set<OtpChallenge>();
    public DbSet<AppConfig> AppConfigs => Set<AppConfig>();
    public DbSet<SessionOutboxMessage> OutboxMessages => Set<SessionOutboxMessage>();
    public new DbSet<RoleEntity> Roles => Set<RoleEntity>();
    public DbSet<PermissionEntity> Permissions => Set<PermissionEntity>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<UserRoleAssignment> UserRoleAssignments => Set<UserRoleAssignment>();
    public DbSet<RoleAssignmentHistory> RoleAssignmentHistories => Set<RoleAssignmentHistory>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<SessionOutboxMessage>(entity =>
        {
            entity.HasIndex(x => x.EventId);
            entity.HasIndex(x => new { x.EventId, x.TargetApplication }).IsUnique();
            entity.HasIndex(x => new { x.DeliveryStatus, x.NextAttemptAt });
            entity.Property(x => x.EventId).HasMaxLength(128);
            entity.Property(x => x.EventType).HasMaxLength(64);
            entity.Property(x => x.SessionId).HasMaxLength(128);
            entity.Property(x => x.UserId).HasMaxLength(128);
            entity.Property(x => x.Status).HasMaxLength(32);
            entity.Property(x => x.Reason).HasMaxLength(64);
            entity.Property(x => x.DeliveryStatus).HasMaxLength(32);
            entity.Property(x => x.PayloadJson).HasColumnType("text");
        });

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(u => u.EmailVerified).HasDefaultValue(false);
            entity.Property(u => u.Immunity).HasDefaultValue(false);
            entity.Property(u => u.Banned).HasDefaultValue(false);
            entity.Property(u => u.UserDetails).HasColumnType("jsonb");
        });

        builder.Entity<SessionRecord>(entity =>
        {
            entity.HasIndex(x => x.UserId);
            entity.HasOne(x => x.User)
                .WithMany(x => x.Sessions)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.Property(x => x.RefreshTokenHash).HasMaxLength(512);
            entity.Property(x => x.DeviceInfo).HasColumnType("jsonb");
        });

        builder.Entity<OtpChallenge>(entity =>
        {
            entity.HasIndex(x => x.Email);
            entity.Property(x => x.Email).HasMaxLength(256);
            entity.Property(x => x.OtpHash).HasMaxLength(512);
        });

        builder.Entity<AppConfig>(entity =>
        {
            entity.HasIndex(x => x.Key).IsUnique();
            entity.Property(x => x.Key).HasMaxLength(128);
            entity.Property(x => x.Value).HasColumnType("text");
        });

        builder.Entity<RoleEntity>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.HasIndex(x => x.Code).IsUnique();
            entity.Property(x => x.Code).HasMaxLength(64).IsRequired();
            entity.Property(x => x.Name).HasMaxLength(120).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(500);
        });

        builder.Entity<PermissionEntity>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.HasIndex(x => x.Code).IsUnique();
            entity.Property(x => x.Code).HasMaxLength(96).IsRequired();
            entity.Property(x => x.Name).HasMaxLength(128).IsRequired();
            entity.Property(x => x.Description).HasMaxLength(500);
            entity.Property(x => x.Module).HasMaxLength(64).IsRequired();
        });

        builder.Entity<RolePermission>(entity =>
        {
            entity.HasKey(x => new { x.RoleId, x.PermissionId });
            entity.HasOne(x => x.Role)
                .WithMany(r => r.RolePermissions)
                .HasForeignKey(x => x.RoleId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(x => x.Permission)
                .WithMany(p => p.RolePermissions)
                .HasForeignKey(x => x.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        builder.Entity<UserRoleAssignment>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.HasIndex(x => new { x.UserId, x.IsActive });
            entity.HasIndex(x => new { x.DepartmentId, x.IsActive });
            entity.HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            entity.HasOne(x => x.Role)
                .WithMany(r => r.UserAssignments)
                .HasForeignKey(x => x.RoleId)
                .OnDelete(DeleteBehavior.Restrict);
            entity.Property(x => x.DepartmentCode).HasMaxLength(32);
            entity.Property(x => x.AssignedBy).HasMaxLength(256).IsRequired();
            entity.Property(x => x.RevokedBy).HasMaxLength(256);
            entity.Property(x => x.AssignmentReason).HasMaxLength(300);
        });

        builder.Entity<RoleAssignmentHistory>(entity =>
        {
            entity.HasKey(x => x.Id);
            entity.HasIndex(x => x.UserId);
            entity.HasIndex(x => x.Timestamp);
            entity.Property(x => x.UserId).HasMaxLength(128).IsRequired();
            entity.Property(x => x.RoleCode).HasMaxLength(64).IsRequired();
            entity.Property(x => x.Action).HasMaxLength(64).IsRequired();
            entity.Property(x => x.PerformedBy).HasMaxLength(256).IsRequired();
            entity.Property(x => x.Reason).HasMaxLength(300);
            entity.Property(x => x.PreviousValuesJson).HasColumnType("text");
            entity.Property(x => x.NewValuesJson).HasColumnType("text");
        });
    }
}
