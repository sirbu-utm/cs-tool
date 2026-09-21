#!/usr/bin/env bash
set -e
if ! command -v uv &> /dev/null; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi
uv sync --extra dev --no-install-workspace --inexact
uv run --no-sync python -m cyberfw.cli "$@"
