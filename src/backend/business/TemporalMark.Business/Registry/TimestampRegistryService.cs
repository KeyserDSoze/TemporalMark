using System.IO.Compression;
using System.Text.Json;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Registry;

public sealed class ExportTooLargeException() : Exception("The period exceeds synchronous export limits. Split the time interval.");

public sealed record RegistrySummary(Guid OrganizationId, long Count, DateTimeOffset FromUtc, DateTimeOffset ToUtcExclusive);

public sealed record RegistryDailySummary(
    Guid OrganizationId, DateTimeOffset FromUtc, DateTimeOffset ToUtcExclusive,
    IReadOnlyList<RegistryDayCount> Days);

public sealed record RegistryImprintSearchResult(
    IReadOnlyList<TimestampRecord> Items, bool HasMore);

/// <summary>Tenant-bound queries and an integrity-checked export of DER receipts.</summary>
public sealed class TimestampRegistryService(ITimestampRegistry registry)
{
    public const int ExportLimit = 10000;
    public const int ExportReceiptDerLimitBytes = 1024 * 1024;
    public const long ExportTotalDerLimitBytes = 64L * 1024 * 1024;
    public const int ExportManifestLimitBytes = 8 * 1024 * 1024;
    public const int ExportArchiveLimitBytes = 80 * 1024 * 1024;

    public async Task<byte[]?> DownloadReceiptAsync(
        Guid organizationId, Guid recordId, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        if (recordId == Guid.Empty) throw new ArgumentException("Record ID is required.", nameof(recordId));
        var record = await registry.FindByIdAsync(organizationId, recordId, cancellationToken);
        if (record is null) return null;
        if (record.OrganizationId != organizationId)
            throw new InvalidOperationException("Repository returned a record outside authorized tenant.");
        record.Validate();
        // Only Unverified has an implemented issuance/verification workflow.
        // Never deliver a claimed qualification or incident state from an
        // otherwise self-consistent but unsupported repository row.
        RequirePilotUnverifiedState(record);
        return record.ResponseDer;
    }

    public async Task<RegistrySummary> SummaryAsync(
        Guid organizationId, UtcPeriod period, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        var count = await registry.CountAsync(organizationId, period, cancellationToken);
        return new RegistrySummary(organizationId, count, period.FromUtc, period.ToUtcExclusive);
    }

    /// <summary>One query, zero-filled per UTC day, max 31 days. Never infer
    /// full counts from a truncated registry page or client-selected tenant.</summary>
    public async Task<RegistryDailySummary> DailyAsync(
        Guid organizationId, UtcPeriod period, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        var duration = period.ToUtcExclusive - period.FromUtc;
        if (period.FromUtc.TimeOfDay != TimeSpan.Zero ||
            period.ToUtcExclusive.TimeOfDay != TimeSpan.Zero ||
            duration < TimeSpan.FromDays(1) || duration > TimeSpan.FromDays(31))
            throw new ArgumentException("Daily statistics require 1 to 31 complete UTC days.", nameof(period));

        var first = DateOnly.FromDateTime(period.FromUtc.UtcDateTime);
        var last = DateOnly.FromDateTime(period.ToUtcExclusive.UtcDateTime);
        var groups = await registry.CountByUtcDayAsync(organizationId, period, cancellationToken);
        // A repository or SQL scoping bug must never silently create
        // misleading dashboard statistics outside the authorized range.
        var counts = new Dictionary<DateOnly, long>();
        foreach (var item in groups)
        {
            if (item.DateUtc < first || item.DateUtc >= last ||
                item.Count <= 0 || !counts.TryAdd(item.DateUtc, item.Count))
                throw new InvalidOperationException("Repository returned invalid UTC daily statistics.");
        }

        var series = new List<RegistryDayCount>((int)duration.TotalDays);
        for (var date = first; date < last; date = date.AddDays(1))
            series.Add(new RegistryDayCount(date, counts.GetValueOrDefault(date)));

        return new RegistryDailySummary(
            organizationId, period.FromUtc, period.ToUtcExclusive, series);
    }

    /// <summary>Pure request preflight: run after authenticated tenant gate and
    /// before any quota consumption or registry SQL. Never use imprint as a quota key.</summary>
    public static void ValidateDocumentImprintSearchRequest(
        Guid organizationId, UtcPeriod period, string? digestSha256Hex, int offset, int limit)
    {
        RequireTenant(organizationId);
        ArgumentNullException.ThrowIfNull(period);
        if (offset < 0 || limit < 1 || limit > 50)
            throw new ArgumentOutOfRangeException(nameof(limit),
                "Use 1..50 search results per page and offset >= 0.");
        if (digestSha256Hex is null || digestSha256Hex.Length != 64 ||
            !digestSha256Hex.All(Uri.IsHexDigit))
            throw new ArgumentException("A 64-character SHA-256 hexadecimal imprint is required.",
                nameof(digestSha256Hex));
    }

    /// <summary>
    /// Exact SHA-256 *document imprint* search (not token DER hash).
    /// The caller supplies hex only; the database stores canonical Base64.
    /// No document bytes, issuer trust claim or qualified evidence is inferred.
    /// </summary>
    public async Task<RegistryImprintSearchResult> SearchByDocumentSha256Async(
        Guid organizationId, UtcPeriod period, string digestSha256Hex,
        int offset, int limit, CancellationToken cancellationToken)
    {
        ValidateDocumentImprintSearchRequest(organizationId, period, digestSha256Hex, offset, limit);

        var canonicalBase64 = Convert.ToBase64String(Convert.FromHexString(digestSha256Hex));
        const string sha256Oid = "2.16.840.1.101.3.4.2.1";
        var results = await registry.SearchByDigestAsync(
            organizationId, period, canonicalBase64, offset, limit + 1, cancellationToken);
        if (results.Count > limit + 1)
            throw new InvalidOperationException("Repository exceeded authorized search result bounds.");

        // All *including* the lookahead entry must be integrity checked
        // before any metadata or hasMore indicator is returned.
        ValidateReturnedRecords(results, organizationId, period);
        if (results.Any(row => row.HashAlgorithmOid != sha256Oid ||
                               !string.Equals(row.DigestBase64, canonicalBase64,
                                   StringComparison.Ordinal)))
            throw new InvalidOperationException("Repository returned a mismatched document imprint.");

        return new RegistryImprintSearchResult(
            results.Take(limit).ToArray(), results.Count > limit);
    }

    public async Task<IReadOnlyList<TimestampRecord>> PageAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        if (offset < 0 || limit < 1 || limit > 200)
            throw new ArgumentOutOfRangeException(nameof(limit), "Use 1..200 records per page and offset >= 0.");
        var records = await registry.PageAsync(organizationId, period, offset, limit, cancellationToken);
        // Do not surface record metadata unless the underlying retained DER
        // and hash are self-consistent and each listed ID is unique.
        ValidateReturnedRecords(records, organizationId, period);
        return records;
    }

    public async Task<byte[]> ExportZipAsync(
        Guid organizationId, UtcPeriod period, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        var records = await registry.ForExportAsync(organizationId, period, ExportLimit + 1, cancellationToken);
        if (records.Count > ExportLimit)
            throw new ExportTooLargeException();
        // Bound raw DER BEFORE hashing every receipt or allocating the
        // in-memory ZIP. Legacy persisted rows need this independent guard:
        // the live TSA's 1 MiB response cap does not constrain database data.
        ValidateSynchronousExportByteBudget(records);
        // Fail before creating any ZIP or manifest: a duplicate ID could
        // otherwise create ambiguous tokens/{id}.tsr archive paths.
        ValidateReturnedRecords(records, organizationId, period);

        var manifest = new
            {
                format = "temporalmark-period-export-v1",
                organizationId,
                fromUtc = period.FromUtc,
                toUtcExclusive = period.ToUtcExclusive,
                exportedAtUtc = DateTimeOffset.UtcNow,
                count = records.Count,
                entries = records.Select(record => new
                {
                    record.Id,
                    record.IssuedUtc,
                    record.HashAlgorithmOid,
                    record.DigestBase64,
                    record.PolicyOid,
                    record.ProviderId,
                    record.TokenSha256Hex,
                    validationState = record.ValidationState.ToString(),
                    record.EvidenceReference,
                    responseFile = $"tokens/{record.Id:N}.tsr"
                }).ToArray()
            };

        // The offline v1 verifier refuses manifests over 8 MiB of actual
        // UTF-8 JSON. Bound serializer output BEFORE allocating any ZIP:
        // Unicode escaping and metadata length make char estimates unsafe.
        await using var manifestBuffer = new BoundedManifestStream();
        await JsonSerializer.SerializeAsync(
            manifestBuffer, manifest, cancellationToken: cancellationToken);
        manifestBuffer.Position = 0;

        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            var index = zip.CreateEntry("manifest.json", CompressionLevel.Optimal);
            await using (var output = index.Open())
                await manifestBuffer.CopyToAsync(output, cancellationToken);

            foreach (var record in records)
            {
                var entry = zip.CreateEntry($"tokens/{record.Id:N}.tsr", CompressionLevel.Optimal);
                await using var output = entry.Open();
                await output.WriteAsync(record.ResponseDer, cancellationToken);
            }
        }
        // Align the physical v1 producer with the standalone offline
        // verifer's outer-file cap. Never return a partial/unsupported ZIP.
        if (buffer.Length > ExportArchiveLimitBytes)
            throw new ExportTooLargeException();
        return buffer.ToArray();
    }

    /// <summary>
    /// Holds one v1 manifest and never accepts writes beyond its real
    /// serialized UTF-8 JSON budget, including async serializer writes.
    /// No unbounded SerializeToUtf8Bytes allocation and no private values
    /// in the overflow exception.
    /// </summary>
    private sealed class BoundedManifestStream : MemoryStream
    {
        private void RequireCapacityFor(int count)
        {
            if (count < 0 || count > ExportManifestLimitBytes - Length)
                throw new ExportTooLargeException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            RequireCapacityFor(count);
            base.Write(buffer, offset, count);
        }

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            RequireCapacityFor(buffer.Length);
            base.Write(buffer);
        }

        public override Task WriteAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireCapacityFor(count);
            return base.WriteAsync(buffer, offset, count, cancellationToken);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequireCapacityFor(buffer.Length);
            return base.WriteAsync(buffer, cancellationToken);
        }
    }

    private static void ValidateSynchronousExportByteBudget(IReadOnlyList<TimestampRecord> records)
    {
        long totalBytes = 0;
        foreach (var record in records)
        {
            var length = record.ResponseDer.Length;
            // Subtraction avoids arithmetic overflow even if the repository
            // returns unexpected/oversized legacy evidence.
            if (length > ExportReceiptDerLimitBytes ||
                length > ExportTotalDerLimitBytes - totalBytes)
                throw new ExportTooLargeException();
            totalBytes += length;
        }
    }

    private static void ValidateReturnedRecords(
        IReadOnlyList<TimestampRecord> records, Guid organizationId, UtcPeriod period)
    {
        var seenIds = new HashSet<Guid>();
        foreach (var record in records)
        {
            if (record.OrganizationId != organizationId || !period.Contains(record.IssuedUtc))
                throw new InvalidOperationException(
                    "Repository returned a record outside authorized tenant/period.");

            // Existing domain rule checks actual retained token bytes against
            // its stored SHA-256; this does not assert RFC3161 qualification.
            record.Validate();
            // Applies before Page/Search (including lookahead)/ExportZip
            // can expose a claimed legal or incident status or DER.
            RequirePilotUnverifiedState(record);

            if (!seenIds.Add(record.Id))
                throw new InvalidOperationException(
                    "Repository returned duplicate timestamp record identifiers.");
        }
    }

    // Scoped unqualified pilot policy: V001 has future-state enum values,
    // but no external QTSP-qualified validation or incident adjudication
    // workflow is active. The database value is never silently downgraded.
    private static void RequirePilotUnverifiedState(TimestampRecord record)
    {
        if (record.ValidationState != TimestampValidationState.Unverified)
            throw new InvalidOperationException(
                "Repository returned an unsupported timestamp verification state.");
    }

    private static void RequireTenant(Guid organizationId)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization identity must be resolved from the validated token.");
    }
}
