"""Train, inspect or verify the offline NF-CSE binary artifact; no API integration."""

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cyberguard.training.train_nf_cse import (
    run_experiment,
    training_config,
    validate_artifact,
    verify_artifact,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    train = sub.add_parser(
        "train", help="Exactly two configured fits; train/validation only"
    )
    train.add_argument(
        "--processed-dir", type=Path, default=ROOT / "data/processed/nf_cse_cic_ids2018"
    )
    train.add_argument("--output-dir", type=Path, default=ROOT / "models/network")
    train.add_argument(
        "--report-dir",
        type=Path,
        default=ROOT / "reports/model_evaluation/nf_cse_binary",
    )
    train.add_argument(
        "--config", type=Path, default=ROOT / "configs/nf_cse_training.json"
    )
    train.add_argument("--threads", type=int, default=min(4, os.cpu_count() or 1))
    train.add_argument("--seed", type=int, default=20261115)
    train.add_argument(
        "--dev-fraction",
        type=float,
        default=1.0,
        help="Training-only deterministic group fraction; default full; not split/seed search",
    )
    train.add_argument("--batch-size", type=int, default=50000)
    for name in ["info", "verify"]:
        p = sub.add_parser(
            name, help="Trusted local artifact inspection/software verification only"
        )
        p.add_argument(
            "--model",
            type=Path,
            default=ROOT / "models/network/nf_cse_binary_completed_flow.joblib",
        )
        if name == "verify":
            p.add_argument("--threads", type=int, default=min(4, os.cpu_count() or 1))
    args = parser.parse_args(argv)
    try:
        if args.command == "train":
            run_experiment(
                args.processed_dir,
                args.output_dir,
                args.report_dir,
                config=training_config(args.config),
                threads=args.threads,
                seed=args.seed,
                dev_fraction=args.dev_fraction,
                batch_size=args.batch_size,
            )
        elif args.command == "info":
            _model, metadata = validate_artifact(args.model)
            print(json.dumps(metadata, indent=2))
        else:
            print(json.dumps(verify_artifact(args.model, args.threads), indent=2))
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        parser.exit(2, f"NF-CSE error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
