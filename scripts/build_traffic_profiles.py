"""Build sealed training-only simulation profiles and deterministic diagnostics."""

import argparse
import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cyberguard.simulation.diagnostics import audit_profiles
from cyberguard.simulation.profiles import (
    DEFAULT_PROFILES,
    DEFAULT_SOURCE,
    Profiles,
    build_profiles,
    check_destination,
    dump_json,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--processed-dir",
        type=Path,
        default=DEFAULT_SOURCE,
        help="Sealed processed root; only train/ and common contract/manifest read",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_PROFILES,
        help="New dedicated simulation profile directory; never overwrite",
    )
    parser.add_argument(
        "--audit-count",
        type=int,
        default=5000,
        help="Bounded deterministic sample per mode/profile, 1..100000",
    )
    parser.add_argument("--audit-seed", type=int, default=20261115)
    parser.add_argument(
        "--audit-report",
        type=Path,
        default=ROOT / "reports/simulation/statistical_validation.json",
    )
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.audit_count <= 100000 or args.audit_seed < 0:
            raise ValueError("Audit count must be in 1..100000 and seed nonnegative")
        report = check_destination(args.audit_report, args.processed_dir)
        if report.exists() or report.is_relative_to(args.output_dir.resolve()):
            raise ValueError(
                "Choose a new audit-report path outside the profile directory"
            )
        started = time.perf_counter()
        metadata = build_profiles(args.processed_dir, args.output_dir)
        build_seconds = time.perf_counter() - started
        profiles = Profiles(args.output_dir)
        audit = audit_profiles(profiles, args.audit_count, args.audit_seed)
        audit["build_seconds"] = build_seconds
        audit["profile_metadata"] = metadata
        audit["peak_rss_mib_linux"] = (
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        )
        report.parent.mkdir(parents=True, exist_ok=True)
        dump_json(report, audit)
        print(
            json.dumps(
                {
                    "profile_directory": str(args.output_dir),
                    "audit_report": str(report),
                    "build_seconds": build_seconds,
                    "peak_rss_mib_linux": audit["peak_rss_mib_linux"],
                },
                indent=2,
            )
        )
    except (ValueError, OSError, KeyError, RuntimeError) as exc:
        parser.exit(2, f"Profile error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
