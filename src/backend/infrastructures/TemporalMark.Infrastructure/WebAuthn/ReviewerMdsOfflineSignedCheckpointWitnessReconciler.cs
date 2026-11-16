using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// NON-AUTHORIZING observation. A caller-selected RSA test key does not
/// establish independent witness custody, FIDO MDS provenance, or immutable
/// anti-rollback after a database restore. ADR 0033 / #63.
/// </summary>
public sealed record ReviewerMdsSignedWitnessCandidate(
    string ReviewStatus, string PolicyStage, string WitnessSha256,
    int MatchedCandidates);

/// <summary>
/// Offline detached RSA-PSS/SHA-256 witness versus one exact V017
/// source-policy partition, read with PostgreSQL repeatable-read / READ ONLY.
/// Test-only caller-selected key; no trusted root, API/CLI, SQL writes,
/// network, credential enrollment or production witness store.
/// </summary>
public static class ReviewerMdsOfflineSignedCheckpointWitnessReconciler
{
    private const string Domain = "TEMPORALMARK-UNAPPROVED-MDS-CRL-WITNESS-1";
    private const int MaximumManifestBytes = 65536;
    private const int MaximumEntries = 128;
    private static readonly TimeSpan MaximumWitnessAge = TimeSpan.FromHours(24);
    private static readonly TimeSpan MinimumWitnessLifetime = TimeSpan.FromSeconds(60);

    public static async Task<ReviewerMdsSignedWitnessCandidate> ReconcileAsync(
        NpgsqlConnection? ownerConnection,
        byte[]? untrustedManifest,
        byte[]? detachedSignature,
        RSA? callerSelectedTestVerificationKey,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (ownerConnection is null ||
            ownerConnection.State != ConnectionState.Open ||
            nowUtc.Offset != TimeSpan.Zero ||
            untrustedManifest is not { Length: >= 128 and <= MaximumManifestBytes } ||
            detachedSignature is null ||
            callerSelectedTestVerificationKey is null)
            throw Denied();

        try
        {
            if (callerSelectedTestVerificationKey.KeySize is < 2048 or > 4096 ||
                detachedSignature.Length != callerSelectedTestVerificationKey.KeySize / 8 ||
                !callerSelectedTestVerificationKey.VerifyData(
                    untrustedManifest, detachedSignature,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw Denied();

            var expected = ParseSignedCanonicalManifest(untrustedManifest, nowUtc);
            await using var transaction = await ownerConnection.BeginTransactionAsync(
                IsolationLevel.RepeatableRead, cancellationToken);

            // Enforce read-only BEFORE any SELECT and never grant direct
            // checkpoint read access to runtime, reviewer or registrar.
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY",
                ownerConnection, transaction))
            {
                await readOnly.ExecuteNonQueryAsync(cancellationToken);
            }

            await using (var role = new NpgsqlCommand("""
                SELECT current_user, session_user,
                       pg_catalog.pg_get_userbyid(c.relowner)
                FROM pg_catalog.pg_class AS c
                WHERE c.oid = 'public.mds_unapproved_candidate_checkpoints'::pg_catalog.regclass
                """, ownerConnection, transaction))
            await using (var identity = await role.ExecuteReaderAsync(cancellationToken))
            {
                if (!await identity.ReadAsync(cancellationToken) ||
                    identity.IsDBNull(0) || identity.IsDBNull(1) || identity.IsDBNull(2) ||
                    identity.GetString(0) != identity.GetString(2) ||
                    identity.GetString(1) != identity.GetString(2) ||
                    await identity.ReadAsync(cancellationToken))
                    throw Denied();
            }

            await using (var query = new NpgsqlCommand("""
                SELECT candidate_kind, issuer_key_sha256, candidate_serial,
                       signed_evidence_sha256, observed_utc, expires_utc,
                       review_status
                FROM public.mds_unapproved_candidate_checkpoints
                WHERE source_policy_sha256=@policy
                ORDER BY candidate_kind,issuer_key_sha256
                """, ownerConnection, transaction))
            {
                query.Parameters.AddWithValue("policy", expected.PolicySha256);
                await using var rows = await query.ExecuteReaderAsync(cancellationToken);
                var index = 0;
                while (await rows.ReadAsync(cancellationToken))
                {
                    if (index >= expected.Entries.Length)
                        throw Denied();

                    var candidate = expected.Entries[index];
                    if (rows.GetString(0) != candidate.Kind ||
                        rows.GetString(1) != candidate.IssuerSha256 ||
                        rows.GetInt64(2) != candidate.Serial ||
                        rows.GetString(3) != candidate.EvidenceSha256 ||
                        rows.GetString(6) != "UNAPPROVED")
                        throw Denied();

                    var observed = rows.GetDateTime(4).ToUniversalTime();
                    var expires = rows.GetDateTime(5).ToUniversalTime();
                    if (observed > nowUtc.UtcDateTime ||
                        expires <= nowUtc.UtcDateTime ||
                        expires < expected.ExpiresUtc.UtcDateTime)
                        throw Denied();
                    index++;
                }
                if (index != expected.Entries.Length)
                    throw Denied();
            }

            await transaction.CommitAsync(cancellationToken);
            return new ReviewerMdsSignedWitnessCandidate(
                "UNAPPROVED", "SIGNED_WITNESS_ONLY_EXTERNAL_CUSTODY_UNPROVEN",
                Convert.ToHexString(SHA256.HashData(untrustedManifest)),
                expected.Entries.Length);
        }
        catch (Exception exception) when (exception is not OperationCanceledException
                                          and not OutOfMemoryException)
        {
            // No SQL error details, signing key, identifying hash or raw
            // witness leaks through the public surface.
            throw Denied();
        }
    }

    private static ParsedWitness ParseSignedCanonicalManifest(
        byte[] manifest, DateTimeOffset now)
    {
        // Only exact printable 7-bit ASCII and LF; no tabs, CR, NUL or
        // replacement-decoded UTF-8. Sign *original bytes*, never reserialize.
        foreach (var b in manifest)
            if (b != 10 && (b < 33 || b > 126))
                throw Denied();
        if (manifest[^1] != (byte)'\n')
            throw Denied();

        var lines = Encoding.ASCII.GetString(manifest).Split('\n');
        if (lines.Length < 7 || lines[^1].Length != 0 ||
            lines[0] != Domain || !IsSha256(lines[1]))
            throw Denied();

        if (!CanonicalPositiveLong(lines[2], out var issuedSeconds) ||
            !CanonicalPositiveLong(lines[3], out var expiresSeconds) ||
            !CanonicalPositiveInt(lines[4], out var count) ||
            count is < 1 or > MaximumEntries ||
            lines.Length != count + 6)
            throw Denied();

        DateTimeOffset issuedUtc, expiresUtc;
        try
        {
            issuedUtc = DateTimeOffset.FromUnixTimeSeconds(issuedSeconds);
            expiresUtc = DateTimeOffset.FromUnixTimeSeconds(expiresSeconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw Denied();
        }

        if (issuedUtc > now || expiresUtc <= now ||
            expiresUtc - issuedUtc < MinimumWitnessLifetime ||
            expiresUtc - issuedUtc > MaximumWitnessAge)
            throw Denied();

        var entries = new ExpectedEntry[count];
        string? previousScope = null;
        for (var i = 0; i < count; i++)
        {
            var fields = lines[i + 5].Split('|');
            if (fields.Length != 4 ||
                fields[0] is not ("MDS_BLOB" or "ISSUER_CRL") ||
                !IsSha256(fields[1]) ||
                !CanonicalPositiveLong(fields[2], out var serial) ||
                !IsSha256(fields[3]))
                throw Denied();

            var scope = fields[0] + "|" + fields[1];
            if (previousScope is not null &&
                string.CompareOrdinal(previousScope, scope) >= 0)
                throw Denied();
            previousScope = scope;
            entries[i] = new ExpectedEntry(fields[0], fields[1], serial, fields[3]);
        }

        return new ParsedWitness(lines[1], expiresUtc, entries);
    }

    private static bool CanonicalPositiveLong(string raw, out long value) =>
        long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out value) &&
        value > 0 && string.Equals(raw, value.ToString(CultureInfo.InvariantCulture),
            StringComparison.Ordinal);

    private static bool CanonicalPositiveInt(string raw, out int value) =>
        int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out value) &&
        value > 0 && string.Equals(raw, value.ToString(CultureInfo.InvariantCulture),
            StringComparison.Ordinal);

    private static bool IsSha256(string raw) =>
        raw.Length == 64 && raw.All(c => c is (>= '0' and <= '9') or
            (>= 'A' and <= 'F'));

    private static UnauthorizedAccessException Denied() =>
        new("Unapproved MDS/CRL signed witness and local checkpoint mismatch.");

    private sealed record ParsedWitness(
        string PolicySha256, DateTimeOffset ExpiresUtc, ExpectedEntry[] Entries);

    private sealed record ExpectedEntry(
        string Kind, string IssuerSha256, long Serial, string EvidenceSha256);
}
