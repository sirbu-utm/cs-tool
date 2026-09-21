#!/usr/bin/env bash
set -e
if ! command -v uv &> /dev/null; then
    # Pinned version + SHA-256 check instead of `curl | sh` (see scripts/install-uv.sh).
    sh "$(dirname "$0")/scripts/install-uv.sh"
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
uv sync --extra dev --no-install-workspace --inexact
uv run --no-sync python -m cyberfw.cli "$@"
