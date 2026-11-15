"""Stream training-derived NF feature records; no packets, inference or workers."""

import argparse
import json
import resource
import sys
import time
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberguard.simulation.generator import TrafficGenerator
from cyberguard.simulation.profiles import DEFAULT_PROFILES, Profiles
from cyberguard.simulation.schemas import GeneratorConfig
from cyberguard.simulation.serialization import export


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", type=Path, default=DEFAULT_PROFILES)
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=42)
    composition = parser.add_mutually_exclusive_group()
    composition.add_argument(
        "--benign-ratio", type=float, help="0..1; default 0.9, rounded count half up"
    )
    composition.add_argument(
        "--attack-ratio", type=float, help="0..1; benign ratio is its complement"
    )
    parser.add_argument(
        "--mode", choices=["empirical", "synthetic"], default="empirical"
    )
    parser.add_argument(
        "--protocol",
        type=int,
        action="append",
        default=[],
        help="Repeat integral byte restriction (e.g. --protocol 6 --protocol 17)",
    )
    parser.add_argument(
        "--destination-port",
        type=int,
        action="append",
        default=[],
        help="Repeat TCP/UDP destination service restriction",
    )
    parser.add_argument(
        "--perturbation",
        type=float,
        default=0.1,
        help="Synthetic shared scale +/- bound, (0,0.25]; default 0.1",
    )
    parser.add_argument("--format", choices=["jsonl", "csv"], default="jsonl")
    parser.add_argument(
        "--output",
        type=Path,
        help="New output path; default runtime/simulation/traffic.<format>; never overwrite",
    )
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="JSONL envelope / namespaced CSV columns; never model inputs",
    )
    args = parser.parse_args(argv)
    try:
        ratio = (
            float(Decimal(1) - Decimal(str(args.attack_ratio)))
            if args.attack_ratio is not None
            else (0.9 if args.benign_ratio is None else args.benign_ratio)
        )
        config = GeneratorConfig(
            count=args.count,
            seed=args.seed,
            benign_ratio=ratio,
            mode=args.mode,
            protocols=tuple(args.protocol),
            destination_ports=tuple(args.destination_port),
            perturbation=args.perturbation,
        )
        started = time.perf_counter()
        profiles = Profiles(args.profiles)
        generator = TrafficGenerator(profiles, config)
        setup_seconds = time.perf_counter() - started
        started = time.perf_counter()
        output = args.output or ROOT / f"runtime/simulation/traffic.{args.format}"
        count = export(generator, output, args.format, args.metadata)
        elapsed = time.perf_counter() - started
        print(
            json.dumps(
                {
                    "output": str(output),
                    "records": count,
                    "benign_records": config.benign_count,
                    "attack_profile_records": count - config.benign_count,
                    "load_and_filter_seconds": setup_seconds,
                    "export_seconds": elapsed,
                    "export_records_per_second": count / elapsed,
                    "peak_rss_mib_linux": resource.getrusage(
                        resource.RUSAGE_SELF
                    ).ru_maxrss
                    / 1024,
                },
                indent=2,
            )
        )
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        parser.exit(2, f"Generation error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
