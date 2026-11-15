"""Run the tested, fixed BoT-IoT baseline using only the supplied training CSV.

First run: .venv/bin/pytest -q tests/unit/test_preprocessing.py tests/unit/test_network_training.py
Then run: .venv/bin/python scripts/train_network_baseline.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberguard.training.evaluate import write_validation_report
from cyberguard.training.train_network import train_baseline

if __name__ == "__main__":
    result = train_baseline(ROOT)
    write_validation_report(result, ROOT)
    print(f"Validation macro-F1: {result['evaluation']['macro_f1']:.6f}")
    print(
        f"Benign false-positive rate: {result['evaluation']['benign_false_positive_rate']:.6f}"
    )
    print(f"Saved {result['model_path']}; peak RSS {result['peak_rss_mib']:.1f} MiB")
