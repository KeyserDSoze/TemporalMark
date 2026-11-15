namespace TemporalMark.Api;

/// <summary>The original document never traverses the API. Only a 32-byte SHA-256 hash in Base64.</summary>
public sealed record StampIssueRequest(string DigestBase64);
