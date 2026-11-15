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

    public async Task<RegistrySummary> SummaryAsync(
        Guid organizationId, UtcPeriod period, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        var count = await registry.CountAsync(organizationId, period, cancellationToken);
        return new RegistrySummary(organizationId, count, period.FromUtc, period.ToUtcExclusive);
    }

    public Task<IReadOnlyList<TimestampRecord>> PageAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        if (offset < 0 || limit < 1 || limit > 200)
            throw new ArgumentOutOfRangeException(nameof(limit), "Use 1..200 records per page and offset >= 0.");
        return registry.PageAsync(organizationId, period, offset, limit, cancellationToken);
    }

    public async Task<byte[]> ExportZipAsync(
        Guid organizationId, UtcPeriod period, CancellationToken cancellationToken)
    {
        RequireTenant(organizationId);
        var records = await registry.ForExportAsync(organizationId, period, ExportLimit + 1, cancellationToken);
        if (records.Count > ExportLimit)
            throw new ExportTooLargeException();

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
                record.Validate();
                if (record.OrganizationId != organizationId || !period.Contains(record.IssuedUtc))
                    throw new InvalidOperationException("Repository returned a record outside authorized tenant/period.");
                var entry = zip.CreateEntry($"tokens/{record.Id:N}.tsr", CompressionLevel.Optimal);
                await using var output = entry.Open();
                await output.WriteAsync(record.ResponseDer, cancellationToken);
            }
        }
        return buffer.ToArray();
    }

    private static void RequireTenant(Guid organizationId)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization identity must be resolved from the validated token.");
    }
}
