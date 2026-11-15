#!/usr/bin/env bash
# Configuration is supplied through exported CYBERGUARD_* variables (see README).
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v uv >/dev/null 2>&1; then
  echo 'Error: uv is required. Install uv, then run uv sync --frozen --group dev.' >&2
  exit 127
fi
cd -- "$project_root"
export PYTHONPATH="$project_root/src${PYTHONPATH:+:$PYTHONPATH}"
if ! uv run --frozen --no-sync python -c 'import fastapi, pydantic, uvicorn, sklearn, joblib' ; then
  echo 'Error: missing/incompatible project dependencies. Run uv sync --frozen --group dev.' >&2
  exit 1
fi
exec uv run --frozen --no-sync python -m cyberguard.api.main
