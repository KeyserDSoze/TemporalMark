using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// Disposable in-memory RSA witness and seal grammar for real PostgreSQL
/// logical restore regression. Never an approved root, HSM, trusted latest
/// high-water authority or legal evidence source. ADR 0035 / #66.
/// </summary>
internal static class MdsFullPgDumpRestoreWitnessFixture
{
    private const string WitnessDomain =
        "TEMPORALMARK-UNAPPROVED-MDS-CRL-WITNESS-1";
    private const string SealDomain =
        "TEMPORALMARK-UNAPPROVED-EXTERNAL-WITNESS-SEAL-1";

    public static byte[] Witness(
        string sourcePolicySha256,
        string issuerSha256,
        long claimedSerial,
        string contentSha256,
        DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero)
            throw new ArgumentException("Only UTC test clocks.", nameof(nowUtc));

        return Encoding.ASCII.GetBytes(string.Join("\n",
        [
            WitnessDomain,
            sourcePolicySha256,
            nowUtc.AddSeconds(-10).ToUnixTimeSeconds()
                .ToString(CultureInfo.InvariantCulture),
            nowUtc.AddMinutes(10).ToUnixTimeSeconds()
                .ToString(CultureInfo.InvariantCulture),
            "1",
            $"MDS_BLOB|{issuerSha256}|{claimedSerial.ToString(CultureInfo.InvariantCulture)}|{contentSha256}",
            ""
        ]));
    }

    public static byte[] Seal(
        string sourcePolicySha256, byte[] witness, DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero)
            throw new ArgumentException("Only UTC test clocks.", nameof(nowUtc));

        return Encoding.ASCII.GetBytes(string.Join("\n",
        [
            SealDomain,
            sourcePolicySha256,
            Convert.ToHexString(SHA256.HashData(witness)),
            nowUtc.AddSeconds(-10).ToUnixTimeSeconds()
                .ToString(CultureInfo.InvariantCulture),
            nowUtc.AddMinutes(10).ToUnixTimeSeconds()
                .ToString(CultureInfo.InvariantCulture),
            ""
        ]));
    }

    /// <summary>
    /// Signed journal record held outside both databases in the scoped
    /// logical-restore CI regression. This is caller-controlled TEST data.
    /// </summary>
    public static byte[] JournalEvent(
        string policySha256, long serial, string sealSha256,
        string previousPayloadSha256, DateTimeOffset observedUtc) =>
        Encoding.ASCII.GetBytes(string.Join("\n",
        [
            "TEMPORALMARK-UNAPPROVED-SIGNED-FILE-HIGHWATER-EVENT-1",
            policySha256,
            serial.ToString(CultureInfo.InvariantCulture),
            sealSha256,
            previousPayloadSha256,
            observedUtc.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ""
        ]));

    public static byte[] Sign(RSA disposableKey, byte[] originalBytes) =>
        disposableKey.SignData(originalBytes, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

    public static string SpkiPin(RSA disposableKey) =>
        Convert.ToHexString(SHA256.HashData(
            disposableKey.ExportSubjectPublicKeyInfo()));
}
