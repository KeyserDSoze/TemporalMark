using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Business.Tenancy;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHealthChecks();
builder.Services.AddProblemDetails();
builder.Services.AddSingleton(_ =>
{
    var connectionString = builder.Configuration.GetConnectionString("Registry")
        ?? throw new InvalidOperationException("ConnectionStrings:Registry is required.");
    return NpgsqlDataSource.Create(connectionString);
});
builder.Services.AddScoped<ITimestampRegistry, PostgresTimestampRegistry>();
builder.Services.AddScoped<ITenantAuthorization, PostgresTenantAuthorization>();
builder.Services.AddScoped<TimestampRegistryService>();

var origins = builder.Configuration.GetSection("Cors:Origins").Get<string[]>() ?? [];
builder.Services.AddCors(options => options.AddPolicy("web", policy =>
    policy.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod()));

var oidcAuthority = builder.Configuration["Authentication:Authority"]
    ?? throw new InvalidOperationException("Authentication:Authority is required.");
var validAudience = builder.Configuration["Authentication:Audience"]
    ?? throw new InvalidOperationException("Authentication:Audience is required.");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = oidcAuthority;
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = validAudience,
            NameClaimType = "preferred_username",
            RoleClaimType = "role"
        };
        if (builder.Environment.IsDevelopment() &&
            builder.Configuration["Authentication:InternalAuthority"] is { Length: > 0 } internalAuthority)
        {
            options.BackchannelHttpHandler = new DevelopmentAuthorityHandler(oidcAuthority, internalAuthority);
        }
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseCors("web");
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/healthz");
// Claim-based admission AND authoritative membership lookup: never accept tenant IDs from caller.
var api = app.MapGroup("/api/v1").RequireAuthorization();

api.MapGet("/me", async Task<IResult> (ClaimsPrincipal user, ITenantAuthorization access, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    return tenant.HasValue
        ? Results.Ok(new { organizationId = tenant.Value, role = "tenant_admin", qualificationState = "NOT_QUALIFIED" })
        : Results.Forbid();
});

api.MapGet("/stamps/summary", async Task<IResult> (
    ClaimsPrincipal user, ITenantAuthorization access, TimestampRegistryService registry,
    DateTimeOffset fromUtc, DateTimeOffset toUtcExclusive, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    try
    {
        return Results.Ok(await registry.SummaryAsync(tenant.Value, new UtcPeriod(fromUtc, toUtcExclusive), ct));
    }
    catch (ArgumentException error)
    {
        return Results.BadRequest(new { error = error.Message });
    }
});

api.MapGet("/stamps", async Task<IResult> (
    ClaimsPrincipal user, ITenantAuthorization access, TimestampRegistryService registry,
    DateTimeOffset fromUtc, DateTimeOffset toUtcExclusive, int? offset, int? limit, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    try
    {
        var records = await registry.PageAsync(tenant.Value, new UtcPeriod(fromUtc, toUtcExclusive),
            offset ?? 0, limit ?? 50, ct);
        return Results.Ok(records.Select(record => new
        {
            record.Id, record.IssuedUtc, record.HashAlgorithmOid, record.DigestBase64,
            record.PolicyOid, record.ProviderId, record.TokenSha256Hex,
            validationState = record.ValidationState.ToString(), record.EvidenceReference
        }));
    }
    catch (ArgumentException error)
    {
        return Results.BadRequest(new { error = error.Message });
    }
});

api.MapGet("/stamps/export", async Task<IResult> (
    HttpContext http, ClaimsPrincipal user, ITenantAuthorization access,
    TimestampRegistryService registry, ILogger<Program> log,
    DateTimeOffset fromUtc, DateTimeOffset toUtcExclusive, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    try
    {
        var bytes = await registry.ExportZipAsync(tenant.Value, new UtcPeriod(fromUtc, toUtcExclusive), ct);
        http.Response.Headers.CacheControl = "no-store";
        log.LogInformation("Export issued for organization {OrganizationId} by {Subject}, range {From}..{To}",
            tenant.Value, user.FindFirstValue("sub"), fromUtc, toUtcExclusive);
        return Results.File(bytes, "application/zip",
            $"temporalmark-{fromUtc:yyyyMMdd}-{toUtcExclusive:yyyyMMdd}.zip");
    }
    catch (ExportTooLargeException error)
    {
        return Results.Problem(title: error.Message, statusCode: StatusCodes.Status413PayloadTooLarge);
    }
    catch (ArgumentException error)
    {
        return Results.BadRequest(new { error = error.Message });
    }
});

// MUST NOT return fictional qualified tokens: production issuance remains gated until controls exist.
api.MapPost("/stamps/issue", () => Results.Problem(
    title: "Timestamp issuance is not configured",
    detail: "RFC 3161, HSM/time-health and qualified status checks must be implemented and audited first.",
    statusCode: StatusCodes.Status503ServiceUnavailable));

app.Run();

static async Task<Guid?> TenantAdminAsync(
    ClaimsPrincipal user, ITenantAuthorization access, CancellationToken ct)
{
    var tenantClaim = user.FindFirstValue("organization_id");
    var subject = user.FindFirstValue("sub");
    if (!Guid.TryParse(tenantClaim, out var tenant) || tenant == Guid.Empty
        || string.IsNullOrWhiteSpace(subject) || !user.IsInRole("tenant_admin"))
        return null;
    return await access.IsActiveAdminAsync(tenant, subject, ct) ? tenant : null;
}
