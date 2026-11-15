"""Evaluate the frozen NF-CSE model once, or inspect published results read-only."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cyberguard.training.evaluate_nf_cse import inspect, run


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--allow-final-test",
        action="store_true",
        help="Consume the reserved test once at both frozen thresholds",
    )
    action.add_argument(
        "--inspect",
        action="store_true",
        help="Verify and print existing results without opening data/model",
    )
    parser.add_argument(
        "--threads", type=int, default=4, help="CPU threads (default: 4)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50000,
        help="Compact prediction batch size (default: 50000)",
    )
    args = parser.parse_args(argv)
    output = ROOT / "reports/model_evaluation/nf_cse_binary/final_test"
    try:
        if args.inspect:
            print(json.dumps(inspect(output), indent=2))
        else:
            run(
                ROOT / "data/processed/nf_cse_cic_ids2018",
                ROOT / "models/network/nf_cse_binary_completed_flow.joblib",
                ROOT / "reports/model_evaluation/nf_cse_binary/validation_metrics.json",
                output,
                allow=args.allow_final_test,
                threads=args.threads,
                batch_size=args.batch_size,
            )
    except (OSError, ValueError, KeyError, RuntimeError, TypeError) as exc:
        parser.exit(2, f"NF-CSE final evaluation refused/failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
