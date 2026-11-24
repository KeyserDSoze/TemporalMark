using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.Http.Features;
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

// CODE-OWNED, environment-independent privacy boundary for ordinary request
// telemetry. Nginx access logs are separately minimized (#117), but a
// malformed request can still contain an imprint/credential in URL or headers.
// Suppress informational request start/completion and route diagnostics;
// preserve Warning/Error for incident investigation (still privacy-reviewed).
builder.Logging.AddFilter("Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
builder.Logging.AddFilter("Microsoft.AspNetCore.Routing.EndpointMiddleware", LogLevel.Warning);
builder.Logging.AddFilter("Microsoft.AspNetCore.Routing.Matching.DfaMatcher", LogLevel.Warning);
// Explicit defense-in-depth should anyone add a logging middleware later.
// DO NOT add UseHttpLogging or UseW3CLogging without an approved review.
builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware", LogLevel.None);
builder.Logging.AddFilter("Microsoft.AspNetCore.HttpLogging.W3CLogger", LogLevel.None);
builder.Services.AddHttpLogging(options =>
{
    options.LoggingFields = HttpLoggingFields.None;
});

builder.Services.AddHealthChecks();
builder.Services.AddProblemDetails();
// The existing OSS on-prem and current Azure reference remain Password mode
// unless an operator explicitly chooses the independent Container Apps Entra
// candidate. Never auto-detect cloud credentials or downgrade failed Entra.
var registryPostgresMode =
    builder.Configuration["RegistryPostgres:AuthenticationMode"] ?? "Password";
ContainerAppsEntraApiRegistryCandidate? entraRegistryCandidate = null;
switch (registryPostgresMode)
{
    case "Password":
        builder.Services.AddSingleton(_ =>
        {
            var connectionString = builder.Configuration.GetConnectionString("Registry")
                ?? throw new InvalidOperationException("ConnectionStrings:Registry is required.");
            return NpgsqlDataSource.Create(connectionString);
        });
        break;

    case "ContainerAppsEntraCandidate":
        // This opt-in is NOT a production rollout authorization. Even in a
        // Production environment, actual Entra SQL role/grants and Azure
        // staging/CAB remain mandatory (#128/#18). No local/dev escape hatch.
        if (!builder.Environment.IsProduction())
            throw new InvalidOperationException("Registry PostgreSQL Entra startup denied");
        try
        {
            entraRegistryCandidate = ContainerAppsEntraApiRegistryCandidate.Create(
                builder.Configuration.GetConnectionString("Registry"),
                Environment.GetEnvironmentVariable("IDENTITY_ENDPOINT"),
                Environment.GetEnvironmentVariable("IDENTITY_HEADER"),
                builder.Configuration["RegistryPostgres:UserAssignedClientId"],
                builder.Configuration["RegistryPostgres:ExpectedRuntimeLogin"]);
        }
        catch (Exception)
        {
            // Never echo raw SQL string, MI secret, local URL or token.
            throw new InvalidOperationException("Registry PostgreSQL Entra startup denied");
        }
        // This explicit single instance is owned by the candidate and disposed
        // on application stop; regular repositories still share NpgsqlDataSource.
        builder.Services.AddSingleton<NpgsqlDataSource>(entraRegistryCandidate.DataSource);
        break;

    default:
        throw new InvalidOperationException("Unsupported PostgreSQL authentication mode");
}
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

// In the explicit Entra candidate mode only, acquire an actual token and
// open a real TLS-verified SQL session, then confirm non-admin runtime grants
// BEFORE ANY HTTP LISTENER IS STARTED. Failure aborts startup without a
// password fallback or leaking provider/credential details. Bounded timeout.
if (entraRegistryCandidate is not null)
{
    app.Lifetime.ApplicationStopped.Register(entraRegistryCandidate.Dispose);
    using var prelistenTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    try
    {
        await entraRegistryCandidate.VerifyAtStartupAsync(prelistenTimeout.Token);
    }
    catch (Exception)
    {
        entraRegistryCandidate.Dispose();
        throw new InvalidOperationException("Registry PostgreSQL Entra startup denied");
    }
}
// #186 / ADR 0144: browser HTTP caching is distinct from the PWA's
// Workbox CacheStorage. Private tenant metadata, actor identity, search,
// audit and every error/status under /api/v1 must NEVER be stored by
// compliant HTTP caches, even if an endpoint forgets its own header.
// Run before Kestrel's pre-auth search 413, CORS and JWT/tenant auth.
// OnStarting runs on success, authentication denials and other responses
// and overwrites any accidentally weaker downstream caching directive.
// The segment boundary excludes /api/v10, /healthz and PWA static shell.
app.Use(async (HttpContext context, RequestDelegate next) =>
{
    if (context.Request.Path.StartsWithSegments(
        new PathString("/api/v1"), StringComparison.OrdinalIgnoreCase))
    {
        context.Response.OnStarting(() =>
        {
            context.Response.Headers.CacheControl = "no-store";
            return Task.CompletedTask;
        });
    }

    await next(context);
});

// #136 / ADR 0102: exact sensitive search route ONLY, including direct ACA
// access that bypasses on-prem Nginx. This early pre-auth request budget
// prevents oversized declared JSON from reaching JWT/model binding and makes
// Kestrel enforce the byte count on reads for chunked/unknown-length bodies.
// No request body, tenant, JWT, searched digest or URI is logged or reflected.
const long ImprintSearchBodyLimitBytes = 4096;
// #187 / ADR 0145: a canonical SHA256 issuance request is tiny too.
// Keep an independent, exact versioned POST body cap, not a global limit.
const long IssueBodyLimitBytes = 4096;
app.Use(async (HttpContext context, RequestDelegate next) =>
{
    if (HttpMethods.IsPost(context.Request.Method) &&
        string.Equals(context.Request.Path.Value, "/api/v1/stamps/search",
            StringComparison.OrdinalIgnoreCase))
    {
        var maxBody = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (maxBody is null || maxBody.IsReadOnly)
        {
            // Cannot safely override Kestrel's normal much larger default:
            // deny without attempting authentication, JSON or PostgreSQL.
            context.Response.Headers.CacheControl = "no-store";
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }

        maxBody.MaxRequestBodySize = ImprintSearchBodyLimitBytes;
        if (context.Request.ContentLength > ImprintSearchBodyLimitBytes)
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
    }

    // #187 / ADR 0145: independent delegated-issuance input gate BEFORE
    // JWT, JSON model binding or external TSA access, including direct
    // Azure Container Apps API requests bypassing the on-prem web proxy.
    // Exactly 4096 original JSON bytes remain admissible; 4097 is not.
    // Kestrel enforces unknown-length/chunked bodies on actual reads.
    if (HttpMethods.IsPost(context.Request.Method) &&
        string.Equals(context.Request.Path.Value, "/api/v1/stamps/issue",
            StringComparison.OrdinalIgnoreCase))
    {
        var maxBody = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (maxBody is null || maxBody.IsReadOnly)
        {
            // No insecure fallback to the default larger Kestrel limit.
            context.Response.Headers.CacheControl = "no-store";
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return;
        }

        maxBody.MaxRequestBodySize = IssueBodyLimitBytes;
        if (context.Request.ContentLength > IssueBodyLimitBytes)
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }
    }

    await next(context);
});

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
})
// Defense in depth: endpoint-scoped metadata also pins the body-read limit
// before minimal API JSON binding, regardless of Content-Length presence.
.WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(
    ImprintSearchBodyLimitBytes));

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
    byte[]? der;
    try
    {
        der = await registry.DownloadReceiptAsync(tenant.Value, id, ct);
    }
    catch (ReceiptTooLargeException)
    {
        // A legacy row can have a valid stored hash yet exceed this pilot's
        // single-receipt delivery budget. Do not disclose its DER or create
        // a misleading ReceiptDownloadPrepared event for the failed read.
        // HTTP 409 is intentional: 413 applies to *request* content size.
        http.Response.Headers.CacheControl = "no-store";
        return Results.Problem(
            title: "Stored receipt is unavailable under pilot download limits.",
            statusCode: StatusCodes.Status409Conflict);
    }
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
})
// Defense in depth for actual streamed/chunked JSON reads during binding.
.WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(
    IssueBodyLimitBytes));

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
