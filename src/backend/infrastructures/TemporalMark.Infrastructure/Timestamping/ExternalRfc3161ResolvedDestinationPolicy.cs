using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Conservative connection-time DNS answer policy for a delegated TSA.
/// An eligible public IP address is NOT proof of QTSP identity or DNS authenticity.
/// </summary>
public static class ExternalRfc3161ResolvedDestinationPolicy
{
    // Conservatively deny IANA special-use/non-globally-routable IPv4 ranges,
    // including link-local cloud instance metadata, carrier NAT and documentation.
    // This is not an authorization allowlist of approved QTSP-owned prefixes.
    private static readonly (uint Network, int PrefixBits)[] BlockedIpv4Ranges =
    [
        (0x00000000u, 8),  // current-network / unspecified
        (0x0a000000u, 8),  // RFC 1918 10/8
        (0x64400000u, 10), // RFC 6598 carrier-grade NAT
        (0x7f000000u, 8),  // loopback
        (0xa9fe0000u, 16), // link-local / metadata
        (0xac100000u, 12), // RFC 1918 172.16/12
        (0xc0000000u, 24), // IETF protocol assignments
        (0xc0000200u, 24), // TEST-NET-1
        (0xc0586300u, 24), // deprecated 6to4 relay anycast
        (0xc0a80000u, 16), // RFC 1918 192.168/16
        (0xc6120000u, 15), // benchmarking 198.18/15
        (0xc6336400u, 24), // TEST-NET-2
        (0xcb007100u, 24), // TEST-NET-3
        (0xe0000000u, 4),  // multicast
        (0xf0000000u, 4)   // reserved / future-use / broadcast
    ];

    public static bool IsEligiblePublicAddress(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        // Never allow IPv4-mapped IPv6 to bypass the IPv4 syntax policy or
        // trigger surprising dual-stack socket behavior.
        if (address.IsIPv4MappedToIPv6)
            return false;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var value = BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());
            foreach (var (network, bits) in BlockedIpv4Ranges)
            {
                var mask = uint.MaxValue << (32 - bits);
                if ((value & mask) == (network & mask))
                    return false;
            }
            return true;
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            return false;

        var bytes = address.GetAddressBytes();

        // Conservative global-unicast 2000::/3 only; reject all local,
        // multicast, IPv4-compatible/mapped, NAT64, documentation and ULA.
        if (bytes[0] < 0x20 || bytes[0] > 0x3f)
            return false;

        // 2001::/23 IETF special use, 2001:20::/28 ORCHIDv2,
        // 2001:db8::/32 documentation, 2002::/16 6to4,
        // 3fff::/20 documentation (RFC 9637).
        if (bytes[0] == 0x20 && bytes[1] == 0x01)
        {
            if ((bytes[2] & 0xfe) == 0x00)
                return false;
            if (bytes[2] == 0x00 && (bytes[3] & 0xf0) == 0x20)
                return false;
            if (bytes[2] == 0x0d && bytes[3] == 0xb8)
                return false;
        }
        if (bytes[0] == 0x20 && bytes[1] == 0x02)
            return false;
        if (bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0x00)
            return false;

        return true;
    }

    /// <summary>
    /// Reject the entire answer set if empty or if even one address would
    /// cross the public-egress boundary. Do not filter-and-try the good ones.
    /// Only explicit development loopback URIs may use ALL-loopback answers.
    /// </summary>
    public static void ValidateResolvedAddresses(
        Uri endpoint,
        IReadOnlyList<IPAddress> addresses,
        bool allowDevelopmentLoopback = false)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        try
        {
            ExternalRfc3161EndpointPolicy.Validate(endpoint, allowDevelopmentLoopback);
        }
        catch (TimestampProviderUnavailableException)
        {
            throw new HttpRequestException("TSA DNS destination is not permitted.");
        }

        if (addresses is null || addresses.Count == 0)
            throw new HttpRequestException("TSA DNS resolution returned no eligible addresses.");

        var allowOnlyLoopback = allowDevelopmentLoopback && endpoint.IsLoopback;
        foreach (var address in addresses)
        {
            if (address is null ||
                !(allowOnlyLoopback
                    ? IPAddress.IsLoopback(address)
                    : IsEligiblePublicAddress(address)))
                throw new HttpRequestException("TSA DNS resolution contains a prohibited network address.");
        }
    }
}
