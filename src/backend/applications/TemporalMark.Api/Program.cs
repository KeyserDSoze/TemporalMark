using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Business.Tenancy;
using TemporalMark.Business.Stamping;
using TemporalMark.Business.Audit;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using TemporalMark.Infrastructure.Timestamping;

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
builder.Services.AddScoped<ITimestampWriter, PostgresTimestampWriter>();
builder.Services.AddScoped<TimestampIssueService>();
builder.Services.AddScoped<ITenantAuditRepository, PostgresTenantAuditRepository>();
builder.Services.AddScoped<TenantAuditService>();
builder.Services.AddScoped<IImprintSearchRateRepository, PostgresImprintSearchRateRepository>();
builder.Services.AddScoped<ImprintSearchRateGateService>();
builder.Services.AddHttpClient("external-tsa", http =>
{
    http.Timeout = TimeSpan.FromSeconds(20);
})
// The named TSA client must not follow 307/308 (or any HTTP redirects):
// forwarded RFC3161 imprints could otherwise leave the pinned TSA origin.
// Only the trusted deployment Development mode permits direct loopback TCP.
// The outbound handler validates every DNS answer and pins the exact socket IP.
.ConfigurePrimaryHttpMessageHandler(() =>
    ExternalRfc3161TransportPolicy.CreateHandler(builder.Environment.IsDevelopment()));
builder.Services.AddScoped<ITimestampProvider>(sp =>
{
    var url = builder.Configuration["TimestampProvider:Url"];
    var providerId = builder.Configuration["TimestampProvider:Id"] ?? "unknown";
    // Operator-controlled identity of the RFC3161 *CMS signer* (not TLS peer).
    // A configured TSA URL without this reviewed whole-DER SHA-256 pin
    // cannot issue, even in Development: the provider fails before HTTP.
    var approvedSignerCertificateSha256 =
        builder.Configuration["TimestampProvider:SignerCertificateSha256"];
    // RFC3161 reqPolicy is operator-owned: never derive a policy from a
    // caller, tenant, HTTPS server or unverified TSA response.
    var approvedPolicyOid = builder.Configuration["TimestampProvider:PolicyOid"];
    // Offline X.509 path root for verified CMS signer, independently
    // reviewed and installed by the deployment operator (not system CAs).
    var trustAnchorCertificateBase64Der =
        builder.Configuration["TimestampProvider:TrustAnchorCertificateBase64Der"];
    // Deployment-owned, authenticated complete issuer CRL snapshot. Never
    // follow untrusted CRL distribution URLs or read a tenant-supplied CRL.
    var issuerCrlBase64Der =
        builder.Configuration["TimestampProvider:IssuerCrlBase64Der"];
    // Second independently reviewed issuer-signed CRL is only needed for
    // a selected root -> intermediate CA -> TSA signer chain.
    var intermediateIssuerCrlBase64Der =
        builder.Configuration["TimestampProvider:IntermediateIssuerCrlBase64Der"];
    // Separate deployment-approved minimum signed CRL sequence numbers.
    // These are NOT an independent or rollback-resistant witnessed store.
    var rootCrlNumberFloor = builder.Configuration["TimestampProvider:IssuerCrlNumberFloor"];
    var intermediateCrlNumberFloor =
        builder.Configuration["TimestampProvider:IntermediateIssuerCrlNumberFloor"];
    if (!string.IsNullOrWhiteSpace(url) && !Uri.TryCreate(url, UriKind.Absolute, out _))
        throw new InvalidOperationException("TimestampProvider:Url must be a valid absolute URL.");
    var uri = string.IsNullOrWhiteSpace(url) ? null : new Uri(url);
    // Fixed operator-owned URI, never caller-selected. Apply the same runtime
    // policy here and inside the provider, including if the provider is reused.
    var allowDevelopmentLoopback = builder.Environment.IsDevelopment();
    if (uri is not null)
        ExternalRfc3161EndpointPolicy.Validate(uri, allowDevelopmentLoopback);
    return new ExternalRfc3161TimestampProvider(
        sp.GetRequiredService<IHttpClientFactory>().CreateClient("external-tsa"),
        uri, providerId, allowDevelopmentLoopback: allowDevelopmentLoopback,
        approvedSignerCertificateSha256: approvedSignerCertificateSha256,
        approvedPolicyOid: approvedPolicyOid,
        approvedTrustAnchorCertificateBase64Der: trustAnchorCertificateBase64Der,
        approvedIssuerCrlBase64Der: issuerCrlBase64Der,
        approvedIntermediateIssuerCrlBase64Der: intermediateIssuerCrlBase64Der,
        approvedRootCrlNumberFloor: rootCrlNumberFloor,
        approvedIntermediateCrlNumberFloor: intermediateCrlNumberFloor);
});

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
            ValidateLifetime = true,
            RequireExpirationTime = true,
            // High-assurance API: do not accept an expired bearer for the default
            // 300-second IdentityModel clock-skew grace period. Host clocks must
            // be synchronized; fail closed when they are not.
            ClockSkew = TimeSpan.Zero,
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

// Same OIDC + active tenant-admin DB gate as the existing exact total.
// Daily aggregate never accepts a tenant selector supplied by a browser.
api.MapGet("/stamps/daily", async Task<IResult> (
    ClaimsPrincipal user, ITenantAuthorization access, TimestampRegistryService registry,
    DateTimeOffset fromUtc, DateTimeOffset toUtcExclusive, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    try
    {
        return Results.Ok(await registry.DailyAsync(
            tenant.Value, new UtcPeriod(fromUtc, toUtcExclusive), ct));
    }
    catch (ArgumentException error)
    {
        return Results.BadRequest(new { error = error.Message });
    }
});

// Lookup by SHA-256 of the ORIGINAL DOCUMENT, not the .tsr token.
// Read-only POST avoids leaking document imprints in URL access logs.
api.MapPost("/stamps/search", async Task<IResult> (
    StampSearchRequest input, HttpContext http, ClaimsPrincipal user,
    ITenantAuthorization access, TimestampRegistryService registry, TenantAuditService audit,
    ImprintSearchRateGateService searchRateGate, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    try
    {
        var period = new UtcPeriod(input.FromUtc, input.ToUtcExclusive);
        TimestampRegistryService.ValidateDocumentImprintSearchRequest(
            tenant.Value, period, input.DigestSha256Hex, input.Offset, input.Limit);
        // Shared PostgreSQL transaction enforces tenant + principal limits across
        // API replicas before any document registry query. Never key by imprint.
        var admission = await searchRateGate.TryAcquireAsync(
            tenant.Value, user.FindFirstValue("sub")!, ct);
        if (!admission.Allowed)
        {
            http.Response.Headers.CacheControl = "no-store";
            http.Response.Headers["Retry-After"] =
                admission.RetryAfterSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
            // No match/hasMore, digest or tenant result in the 429 response.
            return Results.StatusCode(StatusCodes.Status429TooManyRequests);
        }
        var result = await registry.SearchByDocumentSha256Async(
            tenant.Value, period,
            input.DigestSha256Hex, input.Offset, input.Limit, ct);
        // Persist lookup audit before returning any sensitive result. DB failure => no matches.
        // Never copy the searched imprint, matched IDs or match counts into audit.
        await audit.PrepareImprintSearchAsync(tenant.Value, user.FindFirstValue("sub")!, ct);
        http.Response.Headers.CacheControl = "no-store";
        return Results.Ok(new
        {
            items = result.Items.Select(record => new
            {
                record.Id, record.IssuedUtc, record.HashAlgorithmOid,
                record.DigestBase64, record.ProviderId,
                validationState = record.ValidationState.ToString(),
                record.EvidenceReference
            }).ToArray(),
            result.HasMore
        });
    }
    catch (ArgumentException error)
    {
        // Do not echo the caller's fingerprint or return raw evidence.
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

// Server-selected tenant, DB-verified membership. Audit events never expose evidence bytes.
api.MapGet("/audit", async Task<IResult> (
    ClaimsPrincipal user, ITenantAuthorization access, TenantAuditService audit,
    DateTimeOffset fromUtc, DateTimeOffset toUtcExclusive, int? offset, int? limit, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    try
    {
        var entries = await audit.PageAsync(tenant.Value, new UtcPeriod(fromUtc, toUtcExclusive),
            offset ?? 0, limit ?? 25, ct);
        return Results.Ok(entries.Select(entry => new
        {
            entry.Id, entry.OrganizationId, entry.ActorSubjectId,
            action = entry.Action.ToString(),
            entry.OccurredUtc, entry.ReceiptId, entry.PeriodFromUtc,
            entry.PeriodToUtcExclusive
        }));
    }
    catch (ArgumentException error)
    {
        return Results.BadRequest(new { error = error.Message });
    }
});

api.MapGet("/stamps/{id:guid}/receipt", async Task<IResult> (
    Guid id, ClaimsPrincipal user, ITenantAuthorization access,
    TimestampRegistryService registry, TenantAuditService audit, HttpContext http,
    CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    var der = await registry.DownloadReceiptAsync(tenant.Value, id, ct);
    if (der is null) return Results.NotFound();
    // Fail closed on audit persistence failure before responding with receipt bytes.
    await audit.PrepareReceiptDownloadAsync(tenant.Value, user.FindFirstValue("sub")!, id, ct);
    http.Response.Headers.CacheControl = "no-store";
    return Results.File(der, "application/timestamp-reply", $"timestamp-{id:N}.tsr");
});

api.MapGet("/stamps/export", async Task<IResult> (
    HttpContext http, ClaimsPrincipal user, ITenantAuthorization access,
    TimestampRegistryService registry, TenantAuditService audit, ILogger<Program> log,
    DateTimeOffset fromUtc, DateTimeOffset toUtcExclusive, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    try
    {
        var period = new UtcPeriod(fromUtc, toUtcExclusive);
        var bytes = await registry.ExportZipAsync(tenant.Value, period, ct);
        // Ready for delivery, not proof of HTTP delivery. Fail closed if audit insert fails.
        await audit.PreparePeriodExportAsync(tenant.Value, user.FindFirstValue("sub")!, period, ct);
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

// The external TSA path is *not* own QTSP issuance. Every result stays UNVERIFIED
// until full historic Trusted List, revocation, provenance and evidence checks are added.
api.MapPost("/stamps/issue", async Task<IResult> (
    StampIssueRequest input, ClaimsPrincipal user, ITenantAuthorization access,
    TimestampIssueService issue, ILogger<Program> log, CancellationToken ct) =>
{
    var tenant = await TenantAdminAsync(user, access, ct);
    if (!tenant.HasValue) return Results.Forbid();
    try
    {
        var record = await issue.IssueAsync(tenant.Value, input.DigestBase64, ct);
        log.LogInformation("External timestamp stored as UNVERIFIED for organization {OrganizationId}, record {RecordId}",
            tenant.Value, record.Id);
        return Results.Created($"/api/v1/stamps/{record.Id:N}/receipt", new
        {
            record.Id,
            record.IssuedUtc,
            record.ProviderId,
            validationState = record.ValidationState.ToString(),
            qualified = false
        });
    }
    catch (ArgumentException error)
    {
        return Results.BadRequest(new { error = error.Message });
    }
    catch (TimestampProviderUnavailableException error)
    {
        return Results.Problem(title: error.Message, statusCode: StatusCodes.Status503ServiceUnavailable);
    }
    catch (TimestampProviderResponseException error)
    {
        log.LogWarning("External TSA rejected: {Reason}", error.Message);
        return Results.Problem(title: error.Message, statusCode: StatusCodes.Status502BadGateway);
    }
});

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

internal sealed record StampSearchRequest(
    DateTimeOffset FromUtc, DateTimeOffset ToUtcExclusive,
    string DigestSha256Hex, int Offset, int Limit);
