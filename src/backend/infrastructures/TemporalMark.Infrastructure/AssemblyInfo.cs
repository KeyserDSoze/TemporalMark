using System.Runtime.CompilerServices;

// Allow existing offline xUnit suite to supply its in-memory HTTP handler
// for ADR 0097. Production API/CLI can only access the hardened public factory.
[assembly: InternalsVisibleTo("TemporalMark.Provisioner.Tests")]
