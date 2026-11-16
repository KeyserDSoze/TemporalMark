using System.Globalization;
using System.Security.Cryptography;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Require a canonical operator-approved RFC3161 policy OID, both in the
/// outbound TimeStampReq.reqPolicy and signed TSTInfo.policy. A matching
/// service policy is NOT evidence of QTSP qualification or Trusted Lists.
/// </summary>
public static class ExternalRfc3161ApprovedPolicy
{
    private const string ConfigurationError =
        "A valid operator-approved RFC 3161 timestamp policy OID is required.";
    private const string ResponseError =
        "The signed RFC 3161 timestamp policy does not match the approved TSA policy.";

    public static Oid ParseRequiredPolicyOid(string? raw)
    {
        // Bound parser input and forbid names, Unicode digits, whitespace,
        // noncanonical leading zeros, ambiguous dotted-decimal encodings.
        if (string.IsNullOrEmpty(raw) || raw.Length > 160)
            throw new TimestampProviderUnavailableException(ConfigurationError);

        var arcs = raw.Split('.');
        if (arcs.Length is < 2 or > 32)
            throw new TimestampProviderUnavailableException(ConfigurationError);

        var numbers = new uint[arcs.Length];
        for (var i = 0; i < arcs.Length; i++)
        {
            var arc = arcs[i];
            if (arc.Length == 0 || arc.Length > 10 ||
                (arc.Length > 1 && arc[0] == '0'))
                throw new TimestampProviderUnavailableException(ConfigurationError);

            foreach (var digit in arc)
            {
                if (digit is < '0' or > '9')
                    throw new TimestampProviderUnavailableException(ConfigurationError);
            }

            if (!uint.TryParse(arc, NumberStyles.None,
                    CultureInfo.InvariantCulture, out numbers[i]))
                throw new TimestampProviderUnavailableException(ConfigurationError);
        }

        if (numbers[0] > 2 ||
            (numbers[0] < 2 && numbers[1] > 39) ||
            (numbers[0] == 2 && numbers[1] > uint.MaxValue - 80))
            throw new TimestampProviderUnavailableException(ConfigurationError);

        try
        {
            return new Oid(raw);
        }
        catch (CryptographicException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
        catch (ArgumentException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
    }

    public static void ValidateIssuedPolicy(Oid? signedTokenPolicy, Oid approvedPolicy)
    {
        if (signedTokenPolicy is null ||
            !string.Equals(signedTokenPolicy.Value, approvedPolicy?.Value,
                StringComparison.Ordinal))
            throw new TimestampProviderResponseException(ResponseError);
    }
}
