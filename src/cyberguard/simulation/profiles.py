"""Sealed train-only profiles: memory-mapped vectors and exact membership index."""

from __future__ import annotations

import contextvars
import json
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import numpy as np

from cyberguard.features import nf_cse as nf
from cyberguard.features.nf_cse_preparation import sha256
from cyberguard.simulation import GENERATOR_VERSION, PROFILE_VERSION
from cyberguard.simulation.validation import export_vectors
from cyberguard.training.train_nf_cse import ManifestSubset

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SOURCE = ROOT / "data/processed/nf_cse_cic_ids2018"
DEFAULT_PROFILES = ROOT / "models/simulation/nf_cse"
ACTIVE = contextvars.ContextVar("simulation_train_only", default=None)
HOOK_INSTALLED = False


class TrainManifest(ManifestSubset):
    def allowed(self, path):
        if path[0] in {"identity", "status"}:
            return True
        if path[0] == "artifacts":
            return (
                len(path) == 1
                or path[1].startswith("train/")
                or path[1] == "metadata/feature_contract.json"
            )
        if path[0] == "plan":
            return len(path) == 1 or (
                path[1] == "partitions"
                and (
                    len(path) == 2
                    or (
                        path[2] == "train"
                        and (
                            len(path) == 3
                            or path[3]
                            in {"rows", "compact_records", "groups", "binary_counts"}
                        )
                    )
                )
            )
        return False


def _audit(event, args):
    guard = ACTIVE.get()
    if (
        event != "open"
        or guard is None
        or not isinstance(args[0], (str, bytes, os.PathLike))
    ):
        return
    path = Path(os.fsdecode(args[0])).resolve()
    if path.is_relative_to(ROOT / "data/raw"):
        raise PermissionError("Simulation may not read raw datasets")
    root = guard["root"]
    if not path.is_relative_to(root):
        return
    relative = path.relative_to(root).as_posix()
    allowed = relative in {
        "metadata/split_manifest.json",
        "metadata/split_manifest.sha256",
        "metadata/feature_contract.json",
    } or (path.parent == root / "train" and path.suffix == ".npz")
    mode, flags = args[1:3]
    writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
        isinstance(flags, int)
        and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
    )
    if not allowed or writing:
        raise PermissionError(
            f"Simulation permits immutable training shards/common manifest only: {relative}"
        )
    guard["opened"].add(relative)


@contextmanager
def train_only(root):
    global HOOK_INSTALLED
    if not HOOK_INSTALLED:
        sys.addaudithook(_audit)
        HOOK_INSTALLED = True
    guard = {"root": Path(root).resolve(), "opened": set()}
    token = ACTIVE.set(guard)
    try:
        yield guard
    finally:
        ACTIVE.reset(token)


def check_destination(path, source=None):
    path = Path(path).resolve()
    protected = [ROOT / "data", ROOT / "models/network"]
    if source is not None:
        protected.append(Path(source).resolve())
    if any(path.is_relative_to(p) for p in protected):
        raise ValueError("Output cannot overwrite datasets or classifier artifacts")
    return path


def dump_json(path, value):
    Path(path).write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def training_manifest(root):
    path = root / "metadata/split_manifest.json"
    digest = sha256(path)
    if (root / "metadata/split_manifest.sha256").read_text().strip() != digest:
        raise ValueError("Partition manifest checksum mismatch")
    with path.open() as stream:
        manifest = TrainManifest(stream).value()
    identity = manifest["identity"]
    if (
        manifest.get("status") != "complete"
        or identity["schema_version"] != nf.CONTRACT_VERSION
        or identity["preprocessing_version"] != nf.PREPROCESSING_VERSION
    ):
        raise ValueError("Incomplete/unsupported processed training contract")
    if identity["implementation_sha256"]["nf_cse.py"] != sha256(nf.__file__):
        raise ValueError("Normalizer differs from sealed training implementation")
    path = root / "metadata/feature_contract.json"
    if (
        sha256(path)
        != manifest["artifacts"]["metadata/feature_contract.json"]["sha256"]
    ):
        raise ValueError("Feature contract checksum mismatch")
    contract = json.loads(path.read_text())
    if (
        contract["raw_feature_order"] != list(nf.RAW_FEATURES)
        or contract["model_feature_order"] != list(nf.MODEL_FEATURES)
        or contract["preprocessing_version"] != nf.PREPROCESSING_VERSION
    ):
        raise ValueError("Feature contract mismatch")
    return manifest, digest


def build_profiles(source=DEFAULT_SOURCE, output=DEFAULT_PROFILES):
    """One bounded shard at a time. Never expand original multiplicities."""
    source = Path(source).resolve()
    output = check_destination(output, source)
    if output.exists():
        raise FileExistsError(
            f"Profile destination exists (choose a new directory): {output}"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".nf-profile-", dir=output.parent))
    try:
        with train_only(source) as guard:
            manifest, digest = training_manifest(source)
            support = manifest["plan"]["partitions"]["train"]
            n = support["compact_records"]
            if not isinstance(n, int) or n <= 0:
                raise ValueError("Empty training partition")
            vectors = np.lib.format.open_memmap(
                stage / "vectors.npy", mode="w+", dtype="<i8", shape=(n, 7)
            )
            weights = np.lib.format.open_memmap(
                stage / "weights.npy", mode="w+", dtype="<u8", shape=(n,)
            )
            labels = np.lib.format.open_memmap(
                stage / "labels.npy", mode="w+", dtype="u1", shape=(n,)
            )
            connection = sqlite3.connect(stage / "membership.sqlite")
            connection.execute("PRAGMA cache_size=-16384")
            connection.execute(
                "CREATE TABLE vectors (key BLOB PRIMARY KEY) WITHOUT ROWID"
            )
            position, totals = 0, [0, 0]
            protocol_counts = [{}, {}]
            try:
                for relative, artifact in sorted(manifest["artifacts"].items()):
                    if not relative.startswith("train/"):
                        continue
                    path = source / relative
                    if (
                        path.parent.resolve() != source / "train"
                        or path.suffix != ".npz"
                    ):
                        raise ValueError("Unsafe training artifact path")
                    if (
                        path.stat().st_size != artifact["bytes"]
                        or sha256(path) != artifact["sha256"]
                    ):
                        raise ValueError(
                            f"Training shard checksum mismatch: {relative}"
                        )
                    with np.load(path, allow_pickle=False) as shard:
                        canonical, y, w = (
                            shard["features"],
                            shard["Label"],
                            shard["multiplicity"],
                        )
                    raw = export_vectors(canonical)
                    size = len(raw)
                    if (
                        y.shape != (size,)
                        or w.shape != (size,)
                        or y.dtype != np.uint8
                        or w.dtype != np.uint64
                        or not np.isin(y, [0, 1]).all()
                        or (w == 0).any()
                        or position + size > n
                    ):
                        raise ValueError("Invalid training labels/multiplicities/shape")
                    (
                        vectors[position : position + size],
                        weights[position : position + size],
                        labels[position : position + size],
                    ) = raw, w, y
                    for label in (0, 1):
                        totals[label] += sum(map(int, w[y == label]))
                        for protocol in np.unique(raw[:, 0]):
                            mass = sum(
                                map(int, w[(y == label) & (raw[:, 0] == protocol)])
                            )
                            if mass:
                                key = str(int(protocol))
                                protocol_counts[label][key] = (
                                    protocol_counts[label].get(key, 0) + mass
                                )
                    connection.executemany(
                        "INSERT OR IGNORE INTO vectors VALUES (?)",
                        (
                            (row.astype("<i8", copy=False).tobytes(),)
                            for row in canonical
                        ),
                    )
                    connection.commit()
                    position += size
                if (
                    position != n
                    or sum(totals) != support["rows"]
                    or {str(i): totals[i] for i in (0, 1)} != support["binary_counts"]
                ):
                    raise ValueError(
                        "Training population does not match sealed manifest"
                    )
                if not all(totals) or sum(totals) > np.iinfo(np.int64).max:
                    raise ValueError(
                        "Empty profile or unsupported cumulative weight overflow"
                    )
                unique = connection.execute("SELECT COUNT(*) FROM vectors").fetchone()[
                    0
                ]
                if unique != support["groups"]:
                    raise ValueError(
                        "Training feature groups differ from sealed manifest"
                    )
            finally:
                connection.close()
            for array in (vectors, weights, labels):
                array.flush()
            del vectors, weights, labels
            artifacts = {
                p.name: {"sha256": sha256(p), "bytes": p.stat().st_size}
                for p in sorted(stage.iterdir())
            }
            metadata = {
                "profile_version": PROFILE_VERSION,
                "generator_version": GENERATOR_VERSION,
                "contract": nf.CONTRACT_VERSION,
                "preprocessing_version": nf.PREPROCESSING_VERSION,
                "feature_order": list(nf.RAW_FEATURES),
                "software": {
                    "python": platform.python_version(),
                    "numpy": np.__version__,
                },
                "source_manifest_sha256": digest,
                "source_identity": manifest["identity"],
                "training_artifacts": {
                    k: v
                    for k, v in manifest["artifacts"].items()
                    if k.startswith("train/")
                },
                "opened_source_files": sorted(guard["opened"]),
                "compact_records": n,
                "unique_training_vectors": unique,
                "profile_original_rows": dict(
                    zip(("benign", "attack"), totals, strict=True)
                ),
                "weighted_protocol_counts": dict(
                    zip(("benign", "attack"), protocol_counts, strict=True)
                ),
                "artifacts": artifacts,
                "representation": "Complete canonical vectors exported to API scalars; nontransport ports -3 -> raw 0; sentinel -4 -> raw -1. Model information preserved, discarded raw ports unrecoverable. No excluded rows; unsupported statuses fail closed.",
                "method": "Multiplicity-weighted complete-vector anchors; synthetic mode shares one bounded scale across all four counters, retaining protocol/ports and structural zeros.",
            }
            dump_json(stage / "metadata.json", metadata)
        stage.rename(output)
        return metadata
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


class Profiles:
    """Read-only arrays; checksum once per reusable loaded instance. No datasets."""

    def __init__(self, directory=DEFAULT_PROFILES):
        self.directory = Path(directory).resolve()
        self.metadata = json.loads((self.directory / "metadata.json").read_text())
        m = self.metadata
        if (
            m["profile_version"] != PROFILE_VERSION
            or m["generator_version"] != GENERATOR_VERSION
            or m["preprocessing_version"] != nf.PREPROCESSING_VERSION
            or m["contract"] != nf.CONTRACT_VERSION
            or m["feature_order"] != list(nf.RAW_FEATURES)
        ):
            raise ValueError("Unsupported profile contract/version")
        expected = {"vectors.npy", "weights.npy", "labels.npy", "membership.sqlite"}
        if set(m["artifacts"]) != expected:
            raise ValueError("Unexpected profile artifacts")
        for name, info in m["artifacts"].items():
            path = self.directory / name
            if path.stat().st_size != info["bytes"] or sha256(path) != info["sha256"]:
                raise ValueError(f"Profile checksum mismatch: {name}")
        self.vectors = np.load(
            self.directory / "vectors.npy", mmap_mode="r", allow_pickle=False
        )
        self.weights = np.load(
            self.directory / "weights.npy", mmap_mode="r", allow_pickle=False
        )
        self.labels = np.load(
            self.directory / "labels.npy", mmap_mode="r", allow_pickle=False
        )
        n = m["compact_records"]
        if (
            self.vectors.shape != (n, 7)
            or self.weights.shape != (n,)
            or self.labels.shape != (n,)
            or self.vectors.dtype != np.int64
            or self.weights.dtype != np.uint64
            or self.labels.dtype != np.uint8
        ):
            raise ValueError("Invalid profile arrays")

    @contextmanager
    def membership(self):
        connection = sqlite3.connect(
            (self.directory / "membership.sqlite").as_uri() + "?mode=ro", uri=True
        )
        try:
            connection.execute("PRAGMA cache_size=-8192")
            yield connection
        finally:
            connection.close()
