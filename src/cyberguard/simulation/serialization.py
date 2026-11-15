"""Streaming exports; source labels are simulation metadata, never model inputs."""

import csv
import json
import platform
from dataclasses import asdict
from pathlib import Path

import numpy as np

from cyberguard.features.nf_cse import RAW_FEATURES
from cyberguard.features.nf_cse_preparation import sha256
from cyberguard.simulation.profiles import check_destination, dump_json

META_FIELDS = (
    "mode",
    "source_profile",
    "sequence",
    "generator_version",
    "profile_version",
)


def write_stream(generator, stream, format="jsonl", metadata=False):
    if format not in {"jsonl", "csv"}:
        raise ValueError("format must be csv or jsonl")
    writer = None
    if format == "csv":
        fields = list(RAW_FEATURES) + (
            ["simulation_" + c for c in META_FIELDS] if metadata else []
        )
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
    count = 0
    for item in generator:
        if writer:
            row = dict(item["record"])
            if metadata:
                row.update(
                    {"simulation_" + k: v for k, v in item["simulation"].items()}
                )
            writer.writerow(row)
        else:
            stream.write(
                json.dumps(
                    item if metadata else item["record"],
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n"
            )
        count += 1
    return count


def export(generator, path, format="jsonl", metadata=False):
    path = check_destination(path)
    if path.is_relative_to(
        generator.profiles.directory
    ) or generator.profiles.directory.is_relative_to(path):
        raise ValueError("Cannot write exports inside profile artifacts")
    sidecar = Path(str(path) + ".simulation.json")
    if path.exists() or sidecar.exists():
        raise FileExistsError(
            "Output or provenance sidecar exists; choose another path"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="") as stream:
        count = write_stream(generator, stream, format, metadata)
    dump_json(
        sidecar,
        {
            "configuration": asdict(generator.config),
            "software": {"python": platform.python_version(), "numpy": np.__version__},
            "profile_metadata_sha256": sha256(
                generator.profiles.directory / "metadata.json"
            ),
            "output_sha256": sha256(path),
            "records": count,
            "format": format,
            "simulation_metadata": metadata,
            "warning": "Training-derived feature records; source_profile is not independently verified ground truth. Never combine with final-test metrics.",
        },
    )
    return count
