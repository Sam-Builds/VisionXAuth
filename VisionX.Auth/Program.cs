
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using VisionX.Auth.Data;
using VisionX.Auth.Models;
using VisionX.Auth.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;

var builder = WebApplication.CreateBuilder(args);
var authVersion = builder.Configuration["App:Version"]
    ?? typeof(Program).Assembly.GetName().Version?.ToString()
    ?? "dev";

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Host=localhost;Port=5433;Database=visionx_auth;Username=visionx_user;Password=visionx_password";

if (!builder.Environment.IsEnvironment("Testing"))
{
    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseNpgsql(connectionString));
}

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequiredLength = 8;
        options.Password.RequireNonAlphanumeric = false;
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "visionx-auth-service";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "visionx-app";

var defaultCorsOrigins = new[]
{
    "https://visionx.samstack.site",
    "https://samstack.site",
    "https://admin.visionx.io",
    "https://manage.visionx.io",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:3000",
    "http://127.0.0.1:3000"
};

var corsOriginsConfig = builder.Configuration["Cors:AllowedOrigins"];
var configuredOrigins = string.IsNullOrWhiteSpace(corsOriginsConfig)
    ? Array.Empty<string>()
    : corsOriginsConfig.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

var allowedCorsOrigins = defaultCorsOrigins
    .Union(configuredOrigins, StringComparer.OrdinalIgnoreCase)
    .ToArray();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AdminCors", policy =>
    {
        policy.SetIsOriginAllowed(origin =>
        {
            if (string.IsNullOrWhiteSpace(origin)) return false;
            if (allowedCorsOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase)) return true;
            try
            {
                var uri = new Uri(origin);
                if (uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) &&
                    (uri.Host.Equals("visionx.samstack.site", StringComparison.OrdinalIgnoreCase) ||
                     uri.Host.Equals("samstack.site", StringComparison.OrdinalIgnoreCase) ||
                     uri.Host.EndsWith(".samstack.site", StringComparison.OrdinalIgnoreCase) ||
                     uri.Host.Equals("visionx.io", StringComparison.OrdinalIgnoreCase) ||
                     uri.Host.EndsWith(".visionx.io", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
                if (uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                    uri.Host.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
            return false;
        })
        .AllowAnyHeader()
        .AllowAnyMethod();
    });
});

builder.Services.AddSingleton<TokenService>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer();

builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<TokenService>((options, tokenService) =>
    {
        var validIssuers = new[]
        {
            "https://visionx.samstack.site/auth",
            "https://visionx.samstack.site",
            "visionx-auth-service",
            jwtIssuer
        }
        .Where(s => !string.IsNullOrWhiteSpace(s))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuers = validIssuers,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            IssuerSigningKey = tokenService.GetValidationKey(),
            RoleClaimType = "role"
        };
    });

builder.Services.AddAuthorization(options =>
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin")));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpClient();
builder.Services.AddHttpClient("SessionOutboxClient");
builder.Services.AddHttpClient<IEmailService, BrevoEmailService>();
builder.Services.AddScoped<OtpService>();
builder.Services.AddScoped<ISessionEventPublisher, SessionEventPublisher>();
builder.Services.AddHostedService<SessionOutboxDispatcherService>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<AdminService>();
builder.Services.AddScoped<AdminDbService>();
builder.Services.AddScoped<RbacService>();

var app = builder.Build();

app.Logger.LogInformation(
    "VisionX.Auth startup. Version={Version} Environment={Environment} CorsOrigins={Origins}",
    authVersion,
    app.Environment.EnvironmentName,
    string.Join(",", allowedCorsOrigins));

app.Logger.LogInformation("Configured admin email: {AdminEmail}", builder.Configuration["Admin:Email"] ?? "<missing>");

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    if (db.Database.IsRelational())
    {
        await BootstrapLegacyEnsureCreatedHistoryIfNeededAsync(db);
        db.Database.Migrate();
    }
    else
    {
        db.Database.EnsureCreated();
    }
    await SeedDefaultConfigAsync(db);
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    await EnsureAdminUserAsync(userManager, builder.Configuration);
    var rbacService = scope.ServiceProvider.GetRequiredService<RbacService>();
    await rbacService.SeedDefaultRolesAndPermissionsAsync();
    var configuredAdminEmail = builder.Configuration["Admin:Email"];
    if (!string.IsNullOrWhiteSpace(configuredAdminEmail))
    {
        var admin = await userManager.FindByEmailAsync(configuredAdminEmail);
        app.Logger.LogInformation("Configured admin user exists: {Exists}", admin is not null);
    }
}

var forwardedHeadersOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost
};
forwardedHeadersOptions.KnownIPNetworks.Clear();
forwardedHeadersOptions.KnownProxies.Clear();
app.UseForwardedHeaders(forwardedHeadersOptions);

// Handle Cloudflare Tunnel path routing (e.g. visionx.samstack.site/auth)
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/auth", out var remainingPath))
    {
        context.Request.PathBase = "/auth";
        context.Request.Path = remainingPath.HasValue && !string.IsNullOrEmpty(remainingPath.Value) ? remainingPath : "/";
    }
    await next();
});

app.UseSwagger(c =>
{
    c.PreSerializeFilters.Add((swaggerDoc, httpReq) =>
    {
        var host = httpReq.Headers["X-Forwarded-Host"].FirstOrDefault() ?? httpReq.Host.Value;
        var scheme = httpReq.Headers["X-Forwarded-Proto"].FirstOrDefault() ?? httpReq.Scheme;
        var pathBase = httpReq.PathBase.Value ?? "";
        swaggerDoc.Servers = new List<OpenApiServer>
        {
            new() { Url = $"{scheme}://{host}{pathBase}" }
        };
    });
});
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("v1/swagger.json", "VisionX Auth Service");
    options.RoutePrefix = "swagger";
});

app.UseRouting();
app.UseCors("AdminCors");
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext context) =>
{
    var target = context.Request.PathBase.HasValue ? $"{context.Request.PathBase}/swagger" : "/swagger";
    return Results.Redirect(target);
});

app.MapGet("/api/meta/version", () => Results.Ok(new
{
    service = "visionx-auth-service",
    version = authVersion,
    environment = app.Environment.EnvironmentName,
    utc = DateTime.UtcNow
}));

app.MapGet("/.well-known/jwks.json", (TokenService tokenService) =>
{
    return Results.Ok(tokenService.GetJwks());
});

app.MapControllers();

app.Run();

static async Task SeedDefaultConfigAsync(AuthDbContext db)
{
    var existing = await db.AppConfigs.FirstOrDefaultAsync(x => x.Key == "allowed_domains");
    var defaultDomains = new List<string> { "samstack.site", "visionx.io" };
    var payload = JsonSerializer.Serialize(defaultDomains);

    if (existing is null)
    {
        db.AppConfigs.Add(new AppConfig
        {
            Key = "allowed_domains",
            Value = payload
        });
    }
    else
    {
        existing.Value = payload;
        existing.UpdatedAt = DateTime.UtcNow;
    }

    await db.SaveChangesAsync();
}

static async Task EnsureAdminUserAsync(UserManager<ApplicationUser> userManager, IConfiguration configuration)
{
    var adminEmail = configuration["Admin:Email"];
    var adminPassword = configuration["Admin:Password"];

    if (string.IsNullOrWhiteSpace(adminEmail) || string.IsNullOrWhiteSpace(adminPassword))
    {
        return;
    }

    var adminUser = await userManager.FindByEmailAsync(adminEmail);
    if (adminUser is null)
    {
        adminUser = new ApplicationUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            EmailVerified = true,
            Immunity = true,
            CreatedAt = DateTime.UtcNow
        };

        var result = await userManager.CreateAsync(adminUser, adminPassword);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"Could not create admin user: {string.Join(", ", result.Errors.Select(x => x.Description))}");
        }
    }

    var claims = await userManager.GetClaimsAsync(adminUser);
    if (!claims.Any(x => x.Type == "role" && x.Value == "admin"))
    {
        await userManager.AddClaimAsync(adminUser, new Claim("role", "admin"));
    }
}

static async Task BootstrapLegacyEnsureCreatedHistoryIfNeededAsync(AuthDbContext db)
{
    var conn = db.Database.GetDbConnection();
    if (conn.State != System.Data.ConnectionState.Open)
        await conn.OpenAsync();

    using var checkCmd = conn.CreateCommand();
    checkCmd.CommandText = @"
        SELECT
            EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '__EFMigrationsHistory') AS has_history,
            EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'AspNetUsers') AS has_users;
    ";
    using var reader = await checkCmd.ExecuteReaderAsync();
    if (!await reader.ReadAsync()) return;
    var hasHistory = reader.GetBoolean(0);
    var hasUsers = reader.GetBoolean(1);
    await reader.DisposeAsync();

    if (!hasHistory && hasUsers)
    {
        await db.Database.ExecuteSqlRawAsync(@"
            CREATE TABLE IF NOT EXISTS ""__EFMigrationsHistory"" (
                ""MigrationId"" character varying(150) NOT NULL,
                ""ProductVersion"" character varying(32) NOT NULL,
                CONSTRAINT ""PK___EFMigrationsHistory"" PRIMARY KEY (""MigrationId"")
            );
            INSERT INTO ""__EFMigrationsHistory"" (""MigrationId"", ""ProductVersion"")
            VALUES ('20261110064321_InitialAndOutbox', '10.0.4')
            ON CONFLICT DO NOTHING;
        ");
    }
}

public partial class Program { }

