"""Prepare sealed, group-disjoint NF-CSE binary partitions; never train a model."""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cyberguard.features.nf_cse_preparation import (
    DEFAULT_SEED,
    preparation_report,
    prepare,
)


def positive(value):
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return n


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-dir", type=Path, default=ROOT / "data/raw/nf-cse-cic-ids2018"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "data/processed/nf_cse_cic_ids2018"
    )
    parser.add_argument("--chunk-size", type=positive, default=50000)
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Fixed experiment seed; not a balance-search parameter (default 20261115)",
    )
    parser.add_argument("--temp-dir", type=Path, default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Full normalization/group/support preflight; do not publish processed files",
    )
    args = parser.parse_args(argv)
    try:
        result = prepare(
            args.input_dir,
            args.output_dir,
            chunk_size=args.chunk_size,
            seed=args.seed,
            temp_dir=args.temp_dir,
            dry_run=args.dry_run,
        )
        if args.dry_run:
            print(json.dumps(result, indent=2))
        else:
            report = (
                ROOT
                / "reports/dataset_analysis/nf_cse_cic_ids2018/preparation_report.md"
            )
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(preparation_report(result))
            print(f"Preparation {result['status']}; report: {report}")
        return 2 if result["status"] == "blocked" else 0
    except (ValueError, OSError, UnicodeError, sqlite3.Error, KeyError) as exc:
        parser.exit(2, f"Preparation error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
