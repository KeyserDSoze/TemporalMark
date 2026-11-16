using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Strict RFC 3161 client. Checks the nonce/imprint and cryptographic signer
/// but NOT certificate revocation, historical Trusted List or legal qualification.
/// This MUST NOT be used to label timestamps as qualified.
/// </summary>
public sealed class ExternalRfc3161TimestampProvider(
    HttpClient http,
    Uri? providerEndpoint,
    string providerId,
    bool allowDevelopmentLoopback = false,
    string? approvedSignerCertificateSha256 = null,
    string? approvedPolicyOid = null,
    string? approvedTrustAnchorCertificateBase64Der = null,
    string? approvedIssuerCrlBase64Der = null,
    string? approvedIntermediateIssuerCrlBase64Der = null) : ITimestampProvider
{
    private const int MaxResponseBytes = 1024 * 1024;

    public async Task<ProviderTimestamp> RequestAsync(byte[] sha256Digest, CancellationToken cancellationToken)
    {
        if (providerEndpoint is null)
            throw new TimestampProviderUnavailableException("No external TSA endpoint is configured.");
        // Fail closed even when this provider is constructed outside the API:
        // local TSA access requires an explicit Development-only flag.
        ExternalRfc3161EndpointPolicy.Validate(providerEndpoint, allowDevelopmentLoopback);
        if (string.IsNullOrWhiteSpace(providerId))
            throw new TimestampProviderUnavailableException("An explicit TSA provider identity is required.");

        // No explicit independent signer approval -> do not send the imprint.
        // The pin identifies the RFC 3161 CMS signer, NOT the HTTPS server.
        var signerPin = ExternalRfc3161SignerPinPolicy.ParseRequiredSha256(
            approvedSignerCertificateSha256);
        // The caller may not let the TSA choose an arbitrary signing policy.
        // Enforce canonical operator-owned reqPolicy before any outbound HTTP.
        var reviewedPolicy = ExternalRfc3161ApprovedPolicy.ParseRequiredPolicyOid(
            approvedPolicyOid);
        // An operator-approved CA root is mandatory before transmitting any
        // imprint. Keep parsing entirely local; never fetch CA certs by URL.
        using var approvedRoot =
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
                approvedTrustAnchorCertificateBase64Der);
        // One complete reviewed issuer CRL is mandatory before sending the
        // imprint. Only direct root-issued TSA signing leaves are supported
        // by this deliberately restricted revocation policy.
        var reviewedIssuerCrl = ExternalRfc3161IssuerCrlPolicy.ParseRequiredCrlBase64Der(
            approvedIssuerCrlBase64Der);
        // A second offline complete CRL is required only when the *actual*
        // validated signer chain contains one intermediate CA. When set,
        // reject malformed/ambiguous CRL before transmitting the imprint.
        var reviewedIntermediateIssuerCrl =
            string.IsNullOrEmpty(approvedIntermediateIssuerCrlBase64Der)
                ? Array.Empty<byte>()
                : ExternalRfc3161IssuerCrlPolicy.ParseRequiredCrlBase64Der(
                    approvedIntermediateIssuerCrlBase64Der);

        if (sha256Digest.Length != 32)
            throw new ArgumentException("RFC 3161 SHA-256 imprint must have 32 bytes.", nameof(sha256Digest));

        using var request = new HttpRequestMessage(HttpMethod.Post, providerEndpoint);
        var nonce = RandomNumberGenerator.GetBytes(16);
        var timeRequest = Rfc3161TimestampRequest.CreateFromHash(
            sha256Digest.AsMemory(), HashAlgorithmName.SHA256,
            requestedPolicyId: reviewedPolicy,
            nonce: nonce.AsMemory(), requestSignerCertificates: true);
        request.Content = new ByteArrayContent(timeRequest.Encode());
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/timestamp-reply"));

        try
        {
            // Bound the *CMS-signed* genTime to this actual outbound HTTP
            // request interval; not to the tenant's or TSA's unsigned date.
            var requestStartedAt = DateTimeOffset.UtcNow;
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            // Strict local RFC 3161 HTTP profile: no polling, partial responses or
            // non-200 success. Reject mismatched MIME *before reading any body*.
            // RFC 3161 §3.4's verified erratum 1879 confirms timestamp-reply,
            // not the mistyped timestamp-response alternative.
            if (response.StatusCode != HttpStatusCode.OK)
                throw new TimestampProviderResponseException("TSA returned an unexpected HTTP status.");
            if (!string.Equals(response.Content.Headers.ContentType?.MediaType,
                    "application/timestamp-reply", StringComparison.OrdinalIgnoreCase))
                throw new TimestampProviderResponseException("TSA response Content-Type is invalid.");
            if (response.Content.Headers.ContentLength is > MaxResponseBytes)
                throw new TimestampProviderResponseException("TSA response exceeds 1 MiB.");
            await using var input = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            while (true)
            {
                var read = await input.ReadAsync(chunk, cancellationToken);
                if (read == 0) break;
                if (buffer.Length + read > MaxResponseBytes)
                    throw new TimestampProviderResponseException("TSA response exceeds 1 MiB.");
                await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
            }

            var rawResponse = buffer.ToArray();
            var responseReceivedAt = DateTimeOffset.UtcNow;
            Rfc3161TimestampToken token;
            int bytesConsumed;
            try
            {
                token = timeRequest.ProcessResponse(rawResponse, out bytesConsumed);
                if (bytesConsumed != rawResponse.Length)
                    throw new TimestampProviderResponseException("Unexpected trailing bytes in RFC 3161 response.");
                if (!token.VerifySignatureForHash(
                        sha256Digest, HashAlgorithmName.SHA256, out var signerCertificate))
                    throw new TimestampProviderResponseException("The RFC 3161 signature/imprint is invalid.");

                // Examine the *verified* CMS signer rather than any arbitrary
                // certificate bundled in the reply. RFC 3161 §2.3 requires
                // the timeStamping EKU to be critical and its sole key purpose.
                // This check does not establish chain/revocation/QTSP status.
                ExternalRfc3161SignerCertificatePolicy.Validate(signerCertificate);
                // Verify the operator-reviewed full DER SHA-256 fingerprint of
                // exactly the same cryptographically verified CMS signer.
                ExternalRfc3161SignerPinPolicy.ValidateVerifiedSigner(signerCertificate, signerPin);
                // RFC3161 §2.4.2: the signed TSTInfo.policy must be the
                // explicitly requested, operator-approved TSA service policy.
                ExternalRfc3161ApprovedPolicy.ValidateIssuedPolicy(
                    token.TokenInfo.PolicyId, reviewedPolicy);
                // Enforce a fresh live issuance time relative to local HTTP
                // start and full-body receipt before using it for X509.
                // This is a consistency guard, NOT attested UTC accuracy.
                var signedGenTime = token.TokenInfo.Timestamp;
                ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
                    signedGenTime, requestStartedAt, responseReceivedAt);

                // Establish the actual CMS signer's custom-root X.509
                // chain (only CMS-provided intermediates) at signed genTime,
                // then check the root-signed CRL for its directly issued
                // child and, if present, the intermediate-signed CRL for
                // the TSA leaf. Missing or untrusted coverage fails closed.
                ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                    signerCertificate, approvedRoot, token.AsSignedCms().Certificates,
                    reviewedIssuerCrl, reviewedIntermediateIssuerCrl, signedGenTime);
            }
            catch (CryptographicException)
            {
                throw new TimestampProviderResponseException("Malformed RFC 3161 token or invalid signature.");
            }

            var tokenTime = token.TokenInfo.Timestamp.ToUniversalTime();
            var policy = token.TokenInfo.PolicyId.Value ?? "";
            return new ProviderTimestamp(rawResponse, tokenTime, policy, providerId);
        }
        catch (HttpRequestException)
        {
            throw new TimestampProviderUnavailableException("Unable to reach the configured external TSA.");
        }
        catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimestampProviderUnavailableException("External TSA request timed out.");
        }
    }
}
