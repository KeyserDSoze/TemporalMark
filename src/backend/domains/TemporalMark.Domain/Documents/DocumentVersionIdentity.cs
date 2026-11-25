namespace TemporalMark.Domain.Documents;

/// <summary>
/// Immutable identity of an unapproved document version. This value object
/// neither stores bytes nor proves custody, source provenance, qualified time,
/// or fiscal preservation. No source category allows paper disposal.
/// </summary>
public sealed class DocumentVersionIdentity
{
    public Guid OrganizationId { get; }
    public Guid DocumentId { get; }
    public Guid VersionId { get; }
    public string Sha256Hex { get; }
    public long ByteLength { get; }
    public DateTimeOffset AcquiredUtc { get; }
    public DocumentSourceClass SourceClass { get; }

    // Deliberate stop-line: only a future independently approved release
    // policy may determine eligibility. Never accept this from a caller.
    public bool PaperDisposalEligible => false;

    public DocumentVersionIdentity(
        Guid organizationId,
        Guid documentId,
        Guid versionId,
        string sha256Hex,
        long byteLength,
        DateTimeOffset acquiredUtc,
        DocumentSourceClass sourceClass)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("A nonempty organization ID is required.", nameof(organizationId));
        if (documentId == Guid.Empty)
            throw new ArgumentException("A nonempty document ID is required.", nameof(documentId));
        if (versionId == Guid.Empty)
            throw new ArgumentException("A nonempty version ID is required.", nameof(versionId));
        if (!IsCanonicalSha256(sha256Hex))
            throw new ArgumentException("A canonical lowercase SHA-256 hex digest is required.", nameof(sha256Hex));
        if (byteLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(byteLength), "Document length must be positive.");
        if (acquiredUtc.Offset != TimeSpan.Zero)
            throw new ArgumentException("Acquisition time must use UTC (+00:00).", nameof(acquiredUtc));
        if (!Enum.IsDefined(sourceClass))
            throw new ArgumentOutOfRangeException(nameof(sourceClass), "Unknown source class value.");

        OrganizationId = organizationId;
        DocumentId = documentId;
        VersionId = versionId;
        Sha256Hex = sha256Hex;
        ByteLength = byteLength;
        AcquiredUtc = acquiredUtc;
        SourceClass = sourceClass;
    }

    /// <summary>
    /// Defense in depth for a tenant identity already authorized by the
    /// server. This is not authentication or database access control.
    /// </summary>
    public void RequireTenant(Guid authorizedOrganizationId)
    {
        if (authorizedOrganizationId == Guid.Empty || authorizedOrganizationId != OrganizationId)
            throw new ArgumentException("Document access denied.", nameof(authorizedOrganizationId));
    }

    private static bool IsCanonicalSha256(string? value)
    {
        if (value is null || value.Length != 64)
            return false;

        foreach (var c in value)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                return false;
        }

        return true;
    }
}
