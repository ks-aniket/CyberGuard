#!/usr/bin/env python3
"""Run Phase 7A research without deployment or reserved-test access."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cyberguard.research.attack_family import DEFAULT_DATA, DEFAULT_OUTPUT, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA,
        help="Sealed NF-CSE root; only train/validation opened",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="New research report directory; existing output is refused",
    )
    parser.add_argument("--threads", type=int, choices=range(1, 9), default=4)
    args = parser.parse_args()
    try:
        run(args.data_dir, args.output_dir, threads=args.threads)
    except (ValueError, OSError) as exc:
        parser.exit(2, f"Study stopped: {exc}\n")


if __name__ == "__main__":
    main()
