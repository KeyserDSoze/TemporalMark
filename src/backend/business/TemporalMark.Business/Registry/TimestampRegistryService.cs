using System.IO.Compression;
using System.Text;
using System.Text.Json;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Registry;

public sealed class ExportTooLargeException() : Exception("The period exceeds synchronous export limits. Split the time interval.");

/// <summary>Existing pilot receipt cannot be delivered within its single-file cap.</summary>
public sealed class ReceiptTooLargeException() : InvalidOperationException("Stored receipt exceeds pilot download limits.");

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
    // Raw UTF-8 evidence_reference admission; serialized JSON has its OWN cap.
    public const int EvidenceReferenceLimitBytes = 8 * 1024 * 1024;
    public const long EvidenceReferenceBatchLimitBytes = 8L * 1024 * 1024;
    // #176 / ADR 0134: original UTF-8 V001 nonnull text metadata. These
    // are independent of DER, evidence_reference and serialized JSON caps.
    public const int MetadataTextFieldLimitBytes = 16 * 1024;
    public const long MetadataTextBatchLimitBytes = 2L * 1024 * 1024;
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
        // Bind the result to the exact requested receipt, not merely the
        // authorized tenant. An alternate/broken repository could otherwise
        // deliver another valid receipt and audit the requested ID instead.
        // This precedes size/hash/status checks to avoid wrong-ID metadata
        // disclosure. The real PostgreSQL adapter also filters by both keys.
        if (record.Id != recordId)
            throw new InvalidOperationException("Repository returned a receipt outside requested identity.");
        // #176: Business defense in depth against alternate adapters. The
        // real PostgreSQL SELECT separately prevents oversized text from
        // ever appearing in its result fields before Npgsql GetString.
        if (MeasureMetadataTextBytes(record) < 0)
            throw new ReceiptTooLargeException();
        // Alternate repositories must not bypass the SQL read projection
        // limit on legacy evidence references. The raw DER remains original.
        if (record.EvidenceReference is not null &&
            Encoding.UTF8.GetByteCount(record.EvidenceReference) > EvidenceReferenceLimitBytes)
            throw new ReceiptTooLargeException();
        // Use the same conservative per-receipt pilot budget as synchronous
        // ZIP export and the strict offline v1 checker. Legacy rows with
        // matching hashes can still be oversized; refuse before SHA hashing.
        // Tenant scoping MUST precede this check to avoid size disclosure.
        if (record.ResponseDer.Length > ExportReceiptDerLimitBytes)
            throw new ReceiptTooLargeException();
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
        RequireAscendingRegistryOrder(results);
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
        // A buggy repository must never expand a tenant's requested page.
        if (records.Count > limit)
            throw new InvalidOperationException("Repository exceeded authorized page result bounds.");
        // Do not surface metadata until DER integrity, tenant, UTC, pilot
        // status, unique IDs and deterministic database order all pass.
        ValidateReturnedRecords(records, organizationId, period);
        RequireAscendingRegistryOrder(records);
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
        ValidateReturnedRecords(records, organizationId, period, forExport: true);

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

        public override void WriteByte(byte value)
        {
            RequireCapacityFor(1);
            base.WriteByte(value);
        }

        public override void SetLength(long value)
        {
            if (value > ExportManifestLimitBytes)
                throw new ExportTooLargeException();
            base.SetLength(value);
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

    /// <summary>
    /// Bind the repository's documented (issued_utc, id) SQL ordering at
    /// the read boundary, including search's limit+1 lookahead. A broken
    /// adapter must not yield misleading page navigation or hasMore.
    /// </summary>
    private static void RequireAscendingRegistryOrder(IReadOnlyList<TimestampRecord> records)
    {
        for (var index = 1; index < records.Count; index++)
        {
            var previous = records[index - 1];
            var current = records[index];
            // Validation of UTC offset, nonempty IDs and unique IDs occurs
            // in ValidateReturnedRecords before this helper is invoked.
            if (previous.IssuedUtc > current.IssuedUtc ||
                (previous.IssuedUtc == current.IssuedUtc &&
                 string.CompareOrdinal(previous.Id.ToString("N"), current.Id.ToString("N")) >= 0))
                throw new InvalidOperationException("Repository returned an unordered registry batch.");
        }
    }

    private static void ValidateReturnedRecords(
        IReadOnlyList<TimestampRecord> records, Guid organizationId, UtcPeriod period,
        bool forExport = false)
    {
        // #171 / ADR 0129: check ALL tenant/period identities first. An
        // oversized foreign record must not turn a scope failure into a
        // byte-budget detail. No repository rows have been exposed yet.
        foreach (var record in records)
        {
            if (record.OrganizationId != organizationId || !period.Contains(record.IssuedUtc))
                throw new InvalidOperationException(
                    "Repository returned a record outside authorized tenant/period.");
        }

        // Page/search both materialize the original DER for local SHA-256
        // checking even though only metadata is returned in JSON. Apply
        // the same conservative pilot source-byte limits as ZIP BEFORE
        // hashing any records, including the search lookahead row.
        // PostgreSQL has already materialized bytea: this is NOT a
        // pre-query allocation/concurrency cap.
        long totalBytes = 0;
        foreach (var record in records)
        {
            var length = record.ResponseDer.Length;
            if (length > ExportReceiptDerLimitBytes ||
                length > ExportTotalDerLimitBytes - totalBytes)
                throw new InvalidOperationException(
                    "Repository returned a registry batch outside pilot evidence read limits.");
            totalBytes += length;
        }

        // #175 / ADR 0133: a SHA-consistent 4-byte DER cannot make a
        // multi-megabyte unbounded evidence reference safe to list or export.
        // Check original UTF-8 BYTES (not C# chars), including search lookahead,
        // without silently truncating any retained metadata. This Business
        // defense-in-depth runs after an alternate adapter materializes text;
        // the PostgreSQL provider independently gates its wire projection.
        long totalReferenceBytes = 0;
        foreach (var record in records)
        {
            var referenceBytes = record.EvidenceReference is null
                ? 0 : Encoding.UTF8.GetByteCount(record.EvidenceReference);
            if (referenceBytes > EvidenceReferenceLimitBytes ||
                referenceBytes > EvidenceReferenceBatchLimitBytes - totalReferenceBytes)
            {
                if (forExport)
                    throw new ExportTooLargeException();
                throw new InvalidOperationException(
                    "Repository returned a registry batch outside pilot metadata read limits.");
            }
            totalReferenceBytes += referenceBytes;
        }

        // #176: bound original UTF8 bytes of V001's four other text
        // columns across the ENTIRE authorized batch (including search
        // lookahead) before validating/hash-reading or exposing any row.
        long totalMetadataBytes = 0;
        foreach (var record in records)
        {
            var bytes = MeasureMetadataTextBytes(record);
            if (bytes < 0 || bytes > MetadataTextBatchLimitBytes - totalMetadataBytes)
            {
                if (forExport)
                    throw new ExportTooLargeException();
                throw new InvalidOperationException(
                    "Repository returned a registry batch outside pilot metadata read limits.");
            }
            totalMetadataBytes += bytes;
        }

        var seenIds = new HashSet<Guid>();
        foreach (var record in records)
        {
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

    /// <summary>
    /// Original UTF-8 lengths of four nonnull V001 registry metadata fields.
    /// A negative sentinel means one field is NULL/over the pilot 16KiB cap.
    /// This is a read RESOURCE check, never a parser/trust approval of OIDs
    /// or issuer identity. Source values are preserved, never trimmed.
    /// </summary>
    private static long MeasureMetadataTextBytes(TimestampRecord record)
    {
        long total = 0;
        foreach (var field in new[]
                 { record.HashAlgorithmOid, record.DigestBase64, record.PolicyOid, record.ProviderId })
        {
            if (field is null)
                return -1;
            var bytes = Encoding.UTF8.GetByteCount(field);
            if (bytes > MetadataTextFieldLimitBytes)
                return -1;
            total += bytes;
        }
        return total;
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
