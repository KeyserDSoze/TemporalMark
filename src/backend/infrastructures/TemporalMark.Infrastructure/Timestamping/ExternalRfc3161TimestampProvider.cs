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
    string providerId) : ITimestampProvider
{
    private const int MaxResponseBytes = 1024 * 1024;

    public async Task<ProviderTimestamp> RequestAsync(byte[] sha256Digest, CancellationToken cancellationToken)
    {
        if (providerEndpoint is null)
            throw new TimestampProviderUnavailableException("No external TSA endpoint is configured.");
        if (providerEndpoint.Scheme != Uri.UriSchemeHttps &&
            !(providerEndpoint.IsLoopback && providerEndpoint.Scheme == Uri.UriSchemeHttp))
            throw new TimestampProviderUnavailableException("TSA endpoint must use HTTPS (except local test servers).");
        if (string.IsNullOrWhiteSpace(providerId))
            throw new TimestampProviderUnavailableException("An explicit TSA provider identity is required.");
        if (sha256Digest.Length != 32)
            throw new ArgumentException("RFC 3161 SHA-256 imprint must have 32 bytes.", nameof(sha256Digest));

        using var request = new HttpRequestMessage(HttpMethod.Post, providerEndpoint);
        var nonce = RandomNumberGenerator.GetBytes(16);
        var timeRequest = Rfc3161TimestampRequest.CreateFromHash(
            sha256Digest.AsMemory(), HashAlgorithmName.SHA256,
            nonce: nonce.AsMemory(), requestSignerCertificates: true);
        request.Content = new ByteArrayContent(timeRequest.Encode());
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/timestamp-reply"));

        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
                throw new TimestampProviderResponseException("TSA returned an unsuccessful HTTP status.");
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
            Rfc3161TimestampToken token;
            int bytesConsumed;
            try
            {
                token = timeRequest.ProcessResponse(rawResponse, out bytesConsumed);
                if (bytesConsumed != rawResponse.Length)
                    throw new TimestampProviderResponseException("Unexpected trailing bytes in RFC 3161 response.");
                if (!token.VerifySignatureForHash(sha256Digest, HashAlgorithmName.SHA256, out _))
                    throw new TimestampProviderResponseException("The RFC 3161 signature/imprint is invalid.");
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
