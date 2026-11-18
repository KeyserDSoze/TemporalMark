using System.IO.Compression;
using System.Text.Json;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Registry;

public sealed class ExportTooLargeException() : Exception("The period contains too many records for a synchronous export. Split the time interval.");

public sealed record RegistrySummary(Guid OrganizationId, long Count, DateTimeOffset FromUtc, DateTimeOffset ToUtcExclusive);

/// <summary>Tenant-bound queries and an integrity-checked export of DER receipts.</summary>
public sealed class TimestampRegistryService(ITimestampRegistry registry)
{
    public const int ExportLimit = 10000;

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
        return record.ResponseDer;
    }

    public async Task<RegistrySummary> SummaryAsync(
        Guid organizationId, UtcPeriod period, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        var count = await registry.CountAsync(organizationId, period, cancellationToken);
        return new RegistrySummary(organizationId, count, period.FromUtc, period.ToUtcExclusive);
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
        // Fail before creating any ZIP or manifest: a duplicate ID could
        // otherwise create ambiguous tokens/{id}.tsr archive paths.
        ValidateReturnedRecords(records, organizationId, period);

        using var buffer = new MemoryStream();
        using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
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

            var index = zip.CreateEntry("manifest.json", CompressionLevel.Optimal);
            await using (var output = index.Open())
                await JsonSerializer.SerializeAsync(output, manifest, cancellationToken: cancellationToken);

            foreach (var record in records)
            {
                var entry = zip.CreateEntry($"tokens/{record.Id:N}.tsr", CompressionLevel.Optimal);
                await using var output = entry.Open();
                await output.WriteAsync(record.ResponseDer, cancellationToken);
            }
        }
        return buffer.ToArray();
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

            if (!seenIds.Add(record.Id))
                throw new InvalidOperationException(
                    "Repository returned duplicate timestamp record identifiers.");
        }
    }

    private static void RequireTenant(Guid organizationId)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization identity must be resolved from the validated token.");
    }
}
