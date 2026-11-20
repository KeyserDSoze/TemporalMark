#!/usr/bin/env python3
"""Run real disposable Keycloak MFA Playwright test with primary loopback
callback intentionally occupied, forcing an exact preapproved fallback.

Only local CI fixture; never use with production identity. No auth code,
password, OTP seed or JWT is inspected or written by this wrapper.
"""
from pathlib import Path
import os
import socket
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FRONTEND = ROOT / "tests/frontend"


def main():
    if os.environ.get("TEMPORALMARK_CI_MFA_FALLBACK") != "1":
        raise SystemExit("Explicit disposable Keycloak CI fixture flag required")

    socket_holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            socket_holder.bind(("127.0.0.1", 45678))
            socket_holder.listen(1)
        except OSError as exc:
            # Another runner process may already own this address. We still
            # run the browser security suite: it must pick an approved backup.
            if exc.errno != 98:  # Linux EADDRINUSE on pinned Ubuntu runner
                raise
        subprocess.run(
            ["npx", "playwright", "test", "--config", "mfa.config.ts"],
            cwd=FRONTEND,
            check=True,
        )
    finally:
        socket_holder.close()


if __name__ == "__main__":
    main()
