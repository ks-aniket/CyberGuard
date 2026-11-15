#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v uv >/dev/null 2>&1; then
  echo 'Error: uv is required. Install uv, then run uv sync --frozen --group dev.' >&2
  exit 127
fi
cd -- "$project_root"
export PYTHONPATH="$project_root/src${PYTHONPATH:+:$PYTHONPATH}"
if ! uv run --frozen --no-sync python -c 'import streamlit, plotly, pandas, pydantic'; then
  echo 'Error: missing/incompatible dashboard dependencies. Run uv sync --frozen --group dev.' >&2
  exit 1
fi
echo 'CyberGuard dashboard: http://127.0.0.1:8501'
exec uv run --frozen --no-sync streamlit run src/cyberguard/dashboard/app.py --server.address 127.0.0.1 --server.port 8501
