"""Inspect, predict and evaluate with the saved model; never train or refit."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberguard.testing.network_model_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
