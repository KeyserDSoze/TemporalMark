using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// NON-AUTHORIZING synthetic result from a distinct CI PostgreSQL server.
/// Neither role separation nor caller-supplied RSA pins imply FIDO trust,
/// independent immutability or any credential activation.
/// </summary>
public sealed record ReviewerMdsIsolatedPostgresWitnessCandidate(
    string ReviewStatus, string PolicyStage, long LatestSerial,
    string SealSha256, int MatchedCandidates);

/// <summary>
/// ADR 0038 / #69. Reads a separate test witness with a restricted SQL
/// role, then delegates signature validation + V017 read-only snapshot
/// verification to the existing ADR 0033/0034 components.
/// No production endpoint, trusted root, SQL mutation or grant.
/// </summary>
public static class ReviewerMdsIsolatedPostgresWitnessReader
{
    private const string SealDomain =
        "TEMPORALMARK-UNAPPROVED-EXTERNAL-WITNESS-SEAL-1";
    private const string ManifestDomain =
        "TEMPORALMARK-UNAPPROVED-MDS-CRL-WITNESS-1";

    public static async Task<ReviewerMdsIsolatedPostgresWitnessCandidate>
        ReconcileAsync(
            NpgsqlConnection? primaryOwner,
            NpgsqlConnection? separateWitnessReader,
            byte[]? originalManifest,
            byte[]? manifestSignature,
            RSA? callerSelectedManifestTestKey,
            byte[]? originalSeal,
            byte[]? sealSignature,
            RSA? callerSelectedSealTestKey,
            string? callerSelectedSealSpkiPin,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (primaryOwner is null || separateWitnessReader is null ||
            ReferenceEquals(primaryOwner, separateWitnessReader) ||
            primaryOwner.State != ConnectionState.Open ||
            separateWitnessReader.State != ConnectionState.Open ||
            primaryOwner.Database == separateWitnessReader.Database ||
            originalManifest is null || manifestSignature is null ||
            callerSelectedManifestTestKey is null || originalSeal is null ||
            sealSignature is null || callerSelectedSealTestKey is null ||
            callerSelectedSealSpkiPin is null ||
            nowUtc.Offset != TimeSpan.Zero)
            throw Denied();

        try
        {
            // Parse only UNTRUSTED scope and serial before SQL lookup. The
            // existing maintained RSA-PSS verifier will later authenticate
            // the ORIGINAL seal + manifest bytes, not this parsed view.
            var (policy, claimedSerial) =
                ParseUntrustedScope(originalManifest, originalSeal);

            await using var tx = await separateWitnessReader.BeginTransactionAsync(
                IsolationLevel.RepeatableRead, cancellationToken);
            await using (var ro = new NpgsqlCommand(
                "SET TRANSACTION READ ONLY", separateWitnessReader, tx))
                await ro.ExecuteNonQueryAsync(cancellationToken);

            // Exact CI-only owner/reader contract and privilege checks:
            // an owner or app account is NOT a valid witness reader.
            await using (var role = new NpgsqlCommand("""
                SELECT current_user, session_user, current_database(),
                       pg_catalog.pg_get_userbyid(c.relowner),
                       has_table_privilege(current_user,
                           'public.unapproved_witness_checkpoints','SELECT'),
                       has_table_privilege(current_user,
                           'public.unapproved_witness_checkpoints','INSERT'),
                       has_table_privilege(current_user,
                           'public.unapproved_witness_checkpoints','UPDATE'),
                       has_table_privilege(current_user,
                           'public.unapproved_witness_checkpoints','DELETE'),
                       has_table_privilege(current_user,
                           'public.unapproved_witness_checkpoints','TRUNCATE'),
                       has_function_privilege(current_user,
                           'public.record_unapproved_highwater_witness(text,bigint,text)',
                           'EXECUTE')
                FROM pg_catalog.pg_class AS c
                WHERE c.oid='public.unapproved_witness_checkpoints'::pg_catalog.regclass
                """, separateWitnessReader, tx))
            await using (var id = await role.ExecuteReaderAsync(cancellationToken))
            {
                if (!await id.ReadAsync(cancellationToken) ||
                    id.GetString(0) != "temporalmark_witness_reader" ||
                    id.GetString(1) != "temporalmark_witness_reader" ||
                    id.GetString(2) != "temporalmark_witness" ||
                    id.GetString(3) != "temporalmark_witness_data_owner" ||
                    !id.GetBoolean(4))
                    throw Denied();
                for (var i = 5; i <= 9; i++)
                    if (id.GetBoolean(i))
                        throw Denied();
                if (await id.ReadAsync(cancellationToken))
                    throw Denied();
            }

            long latestSerial;
            string latestSha;
            DateTime observed;
            await using (var q = new NpgsqlCommand("""
                SELECT candidate_serial, seal_sha256, observed_utc
                FROM public.unapproved_witness_checkpoints
                WHERE source_policy_sha256=@policy
                """, separateWitnessReader, tx))
            {
                q.Parameters.AddWithValue("policy", policy);
                await using var rows = await q.ExecuteReaderAsync(cancellationToken);
                if (!await rows.ReadAsync(cancellationToken))
                    throw Denied();
                latestSerial = rows.GetInt64(0);
                latestSha = rows.GetString(1);
                observed = rows.GetDateTime(2).ToUniversalTime();
                if (await rows.ReadAsync(cancellationToken))
                    throw Denied();
            }

            if (latestSerial != claimedSerial ||
                !IsHash(latestSha) ||
                observed > nowUtc.UtcDateTime ||
                observed <= nowUtc.UtcDateTime.AddHours(-24) ||
                !CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(originalSeal),
                    Convert.FromHexString(latestSha)))
                throw Denied();
            await tx.CommitAsync(cancellationToken);

            // Read-only snapshots across TWO databases are NOT a global
            // atomic transaction. This remains an UNAPPROVED preflight,
            // vulnerable to privileged witness-DB reset and TOCTOU.
            var verified =
                await ReviewerMdsOfflineSealedHighWaterCandidateVerifier.ReconcileAsync(
                    primaryOwner, originalManifest, manifestSignature,
                    callerSelectedManifestTestKey, originalSeal, sealSignature,
                    callerSelectedSealTestKey, callerSelectedSealSpkiPin,
                    latestSha, nowUtc, cancellationToken);
            if (verified.ReviewStatus != "UNAPPROVED" ||
                verified.PolicyStage !=
                    "TEST_HIGH_WATER_SEAL_EXTERNAL_CUSTODY_UNPROVEN")
                throw Denied();

            return new ReviewerMdsIsolatedPostgresWitnessCandidate(
                "UNAPPROVED",
                "SEPARATE_TEST_POSTGRES_WITNESS_NO_IMMUTABLE_CUSTODY",
                latestSerial, latestSha, verified.MatchedCandidates);
        }
        catch (Exception error) when (error is not OperationCanceledException
                                      and not OutOfMemoryException)
        {
            // Missing/unavailable witness: DENY, never fall back to local
            // file or a caller-chosen older supposedly latest seal hash.
            throw Denied();
        }
    }

    private static (string Policy, long Serial) ParseUntrustedScope(
        byte[] manifest, byte[] seal)
    {
        if (manifest.Length is < 128 or > 65536 ||
            seal.Length is < 180 or > 4096 ||
            !IsAscii(manifest) || !IsAscii(seal))
            throw Denied();
        var w = Encoding.ASCII.GetString(manifest).Split('\n');
        var s = Encoding.ASCII.GetString(seal).Split('\n');
        if (w.Length != 7 || w[^1] != "" || w[0] != ManifestDomain ||
            w[4] != "1" || !IsHash(w[1]) ||
            s.Length != 6 || s[^1] != "" || s[0] != SealDomain ||
            s[1] != w[1] || !IsHash(s[2]))
            throw Denied();
        var entry = w[5].Split('|');
        if (entry.Length != 4 ||
            entry[0] is not ("MDS_BLOB" or "ISSUER_CRL") ||
            !IsHash(entry[1]) || !IsHash(entry[3]) ||
            !long.TryParse(entry[2], NumberStyles.None,
                CultureInfo.InvariantCulture, out var serial) ||
            serial <= 0 ||
            entry[2] != serial.ToString(CultureInfo.InvariantCulture))
            throw Denied();
        return (w[1], serial);
    }

    private static bool IsAscii(byte[] b) =>
        b.Length > 0 && b[^1] == 10 &&
        b.All(x => x == 10 || x is >= 33 and <= 126);

    private static bool IsHash(string? s) =>
        s is { Length: 64 } &&
        s.All(x => x is (>= 'A' and <= 'F') or (>= '0' and <= '9'));

    private static UnauthorizedAccessException Denied() =>
        new("Unapproved or inaccessible separate test PostgreSQL witness.");
}
