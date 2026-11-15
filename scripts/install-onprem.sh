#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" != "--dev" ]]; then
  cat <<'EOF'
TemporalMark on-prem production installer has NOT passed acceptance/audit.
Production requires an approved HSM, metrologically traceable time, signed WORM evidence,
qualified provider status, secret management, TLS ingress and secure DB/IdP configuration.
For local functional development ONLY:
  bash scripts/install-onprem.sh --dev
See docs/COMPLIANCE.md and docker/README.md.
EOF
  exit 2
fi

command -v docker >/dev/null || { echo "Docker is required" >&2; exit 1; }
docker compose -f "$ROOT/docker/compose.yml" up --build -d
echo "Local development console: http://localhost:3000"
