"""Disk-backed NF-CSE preparation only. Never imports model-training code."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import resource
import sqlite3
import tempfile
import time
from collections import Counter
from contextlib import closing
from pathlib import Path

import numpy as np
import pandas as pd

from cyberguard.features import nf_cse as nf

ROOT = Path(__file__).resolve().parents[3]
PARTITIONS = ("train", "validation", "test")
DEFAULT_SEED = 20261115
STORAGE_VERSION = "nf-cse-compact-npz-v1"
METHOD = "sha256(schema_version,seed,canonical_integer_vector); first64; <floor(3*2^64/5) train; <floor(4*2^64/5) validation; else test"
# Engineering stop guards frozen before inspecting the actual split. No search/retry.
GUARDS = {
    "maximum_absolute_row_fraction_deviation": 0.10,
    "minimum_groups_per_binary_label_per_partition": 10,
}
TARGETS = {"train": 0.6, "validation": 0.2, "test": 0.2}


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def json_bytes(value):
    return (
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode()


def discover(input_dir):
    files = sorted(Path(input_dir).resolve().rglob("NF-CSE-CIC-IDS2018.csv"))
    if len(files) != 1:
        raise ValueError(
            f"Expected exactly one NF-CSE-CIC-IDS2018.csv; found {len(files)}"
        )
    source = files[0]
    dictionary = source.with_name("NetFlow_v1_Features.csv")
    if not dictionary.is_file():
        raise ValueError(f"Missing supplied feature dictionary: {dictionary}")
    with source.open(newline="", encoding="utf-8") as stream:
        columns = next(csv.reader(stream), [])
    if (
        not columns
        or any(not c.strip() for c in columns)
        or len(columns) != len(set(columns))
    ):
        raise ValueError("CSV headers must be nonempty and unique")
    if not {*nf.RAW_FEATURES, "Label", "Attack"} <= set(columns):
        raise ValueError("Missing required completed-flow fields or label metadata")
    with dictionary.open(newline="", encoding="utf-8") as stream:
        definitions = {
            row["Feature"]: row["Description"] for row in csv.DictReader(stream)
        }
    for field in nf.feature_contract()["fields"]:
        if definitions.get(field["name"]) != field["description"]:
            raise ValueError(
                f"Feature definition mismatch for {field['name']}; review a new contract"
            )
    return source, dictionary, columns


def partition_for_key(key, seed=DEFAULT_SEED):
    payload = json.dumps(
        [nf.CONTRACT_VERSION, seed, json.loads(key)], separators=(",", ":")
    ).encode()
    number = int.from_bytes(hashlib.sha256(payload).digest()[:8], "big")
    return (
        "train"
        if number < 3 * 2**64 // 5
        else "validation"
        if number < 4 * 2**64 // 5
        else "test"
    )


def group_id(key):
    return hashlib.sha256((nf.CONTRACT_VERSION + "\n" + key).encode()).hexdigest()


def build_index(source, db, *, chunk_size, seed):
    db.execute(
        "CREATE TABLE examples(k TEXT,b INTEGER,a TEXT,n INTEGER,p TEXT,PRIMARY KEY(k,b,a)) WITHOUT ROWID"
    )
    rows = 0
    status_counts = {c: Counter() for c in nf.RAW_FEATURES}
    for chunk in pd.read_csv(
        source,
        usecols=[*nf.RAW_FEATURES, "Label", "Attack"],
        dtype=str,
        keep_default_na=False,
        encoding="utf-8",
        encoding_errors="strict",
        chunksize=chunk_size,
    ):
        labels = nf.validate_labels(chunk.Label, chunk.Attack)
        normalized = nf.normalize(chunk)
        for c in nf.RAW_FEATURES:
            codes = normalized[c].where(normalized[c] < 0, 0)
            status_counts[c].update(
                {str(int(k)): int(v) for k, v in codes.value_counts().items()}
            )
        pairs = Counter(
            zip(
                nf.canonical_keys(normalized),
                map(int, labels),
                chunk.Attack,
                strict=True,
            )
        )
        db.executemany(
            "INSERT INTO examples VALUES(?,?,?,?,?) ON CONFLICT(k,b,a) DO UPDATE SET n=n+excluded.n",
            [
                (k, b, a, n, partition_for_key(k, seed))
                for (k, b, a), n in pairs.items()
            ],
        )
        db.commit()
        rows += len(chunk)
        if rows % (chunk_size * 10) == 0:
            print(f"Normalized/indexed {rows:,} source records", flush=True)
    if not rows:
        raise ValueError("No source records")
    return rows, {c: dict(counts) for c, counts in status_counts.items()}


def summarize(db):
    print(
        "Computing full-dataset ambiguity and proposed partition supports", flush=True
    )
    grouped = """SELECT k,min(p) p,sum(n) n,sum(CASE WHEN b=0 THEN n ELSE 0 END) n0,
        sum(CASE WHEN b=1 THEN n ELSE 0 END) n1,count(DISTINCT a) attacks,
        count(DISTINCT p) partitions FROM examples GROUP BY k"""
    values = db.execute(f"""SELECT count(*),sum(n),sum(attacks>1),sum(n0>0 AND n1>0),
        coalesce(sum(CASE WHEN n0>0 AND n1>0 THEN n ELSE 0 END),0),
        coalesce(sum(CASE WHEN n0>0 AND n1>0 THEN n0 ELSE 0 END),0),
        coalesce(sum(CASE WHEN n0>0 AND n1>0 THEN n1 ELSE 0 END),0),
        sum(max(n0,n1)),max(n),sum(partitions>1) FROM ({grouped})""").fetchone()
    names = [
        "normalized_groups",
        "original_rows",
        "groups_multiple_Attack_labels",
        "binary_conflicting_groups",
        "rows_in_binary_conflicts",
        "benign_rows_in_binary_conflicts",
        "attack_rows_in_binary_conflicts",
        "binary_majority_correct_rows",
        "largest_group_rows",
        "groups_crossing_partitions",
    ]
    stats = dict(zip(names, map(int, values), strict=True))
    stats["binary_majority_label_accuracy_ceiling"] = (
        stats["binary_majority_correct_rows"] / stats["original_rows"]
    )
    stats["compact_records"] = db.execute("SELECT count(*) FROM examples").fetchone()[0]
    stats["projected_feature_label_metadata_duplicate_excess"] = (
        stats["original_rows"] - stats["compact_records"]
    )
    stats["normalized_vector_duplicate_excess"] = (
        stats["original_rows"] - stats["normalized_groups"]
    )
    stats["distinct_feature_binary_records"] = db.execute(
        "SELECT count(*) FROM (SELECT k,b FROM examples GROUP BY k,b)"
    ).fetchone()[0]
    partitions = {
        p: {
            "rows": 0,
            "compact_records": 0,
            "groups": 0,
            "binary_counts": {"0": 0, "1": 0},
            "binary_group_support": {"0": 0, "1": 0},
            "Attack_counts": {},
        }
        for p in PARTITIONS
    }
    for p, b, n, records, groups in db.execute(
        "SELECT p,b,sum(n),count(*),count(DISTINCT k) FROM examples GROUP BY p,b"
    ):
        d = partitions[p]
        d["rows"] += n
        d["compact_records"] += records
        d["binary_counts"][str(b)] = n
        d["binary_group_support"][str(b)] = groups
    for p, groups in db.execute(f"SELECT p,count(*) FROM ({grouped}) GROUP BY p"):
        partitions[p]["groups"] = groups
    for p, a, n in db.execute("SELECT p,a,sum(n) FROM examples GROUP BY p,a"):
        partitions[p]["Attack_counts"][a] = n
    attacks = sorted({a for d in partitions.values() for a in d["Attack_counts"]})
    for p, d in partitions.items():
        d["row_fraction"] = d["rows"] / stats["original_rows"]
        d["Attack_counts"] = {a: d["Attack_counts"].get(a, 0) for a in attacks}
    errors = []
    if stats["groups_crossing_partitions"]:
        errors.append("Identical normalized vectors cross partitions")
    for p, d in partitions.items():
        if (
            abs(d["row_fraction"] - TARGETS[p])
            > GUARDS["maximum_absolute_row_fraction_deviation"]
        ):
            errors.append(
                f"{p}: row fraction {d['row_fraction']:.6f} outside fixed +/-10 percentage-point guard"
            )
        if any(
            n < GUARDS["minimum_groups_per_binary_label_per_partition"]
            for n in d["binary_group_support"].values()
        ):
            errors.append(f"{p}: fewer than 10 groups for at least one binary label")
    return {
        "ambiguity": stats,
        "partitions": partitions,
        "guards": GUARDS,
        "guard_errors": errors,
        "can_materialize": not errors,
    }


def signature(source, dictionary, seed):
    contract = nf.feature_contract()
    return {
        "source_sha256": sha256(source),
        "dictionary_sha256": sha256(dictionary),
        "feature_contract_sha256": hashlib.sha256(json_bytes(contract)).hexdigest(),
        "schema_version": nf.CONTRACT_VERSION,
        "preprocessing_version": nf.PREPROCESSING_VERSION,
        "storage_version": STORAGE_VERSION,
        "seed": seed,
        "split_method": METHOD,
        "implementation_sha256": {
            p.name: sha256(p) for p in [Path(nf.__file__), Path(__file__)]
        },
    }


def verify_existing(output, expected):
    manifest_path = output / "metadata/split_manifest.json"
    if not manifest_path.is_file():
        raise ValueError(
            "Output already exists without a complete manifest; choose a new output directory; no overwrite is supported"
        )
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("identity") != expected:
        raise ValueError(
            "Output exists with incompatible source/contract/code/seed; refusing overwrite or resealing test"
        )
    sidecar = output / "metadata/split_manifest.sha256"
    if not sidecar.is_file() or sidecar.read_text().strip() != sha256(manifest_path):
        raise ValueError("Existing split manifest hash mismatch")
    for name, item in manifest["artifacts"].items():
        path = (output / name).resolve()
        if (
            not path.is_relative_to(output.resolve())
            or not path.is_file()
            or sha256(path) != item["sha256"]
        ):
            raise ValueError(f"Existing artifact missing/changed: {name}")
    expected_names = set(manifest["artifacts"]) | {
        "metadata/split_manifest.json",
        "metadata/split_manifest.sha256",
    }
    actual = {
        p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()
    }
    if actual != expected_names:
        raise ValueError("Existing output inventory changed; refusing a silent reuse")
    return manifest


def materialize(db, stage, *, chunk_size, seed):
    # Query order is independent of input/chunk order; ties retain each Attack label.
    files = []
    for p in PARTITIONS:
        folder = stage / p
        folder.mkdir()
        cursor = db.execute(
            "SELECT k,b,a,n,p FROM examples WHERE p=? ORDER BY k,b,a", (p,)
        )
        shard = 0
        while rows := cursor.fetchmany(chunk_size):
            vectors = []
            labels = []
            attacks = []
            counts = []
            identifiers = []
            for key, b, a, n, stored_partition in rows:
                if stored_partition != partition_for_key(key, seed):
                    raise ValueError("Partition/key mismatch before writing")
                vectors.append(json.loads(key))
                labels.append(b)
                attacks.append(a)
                counts.append(n)
                identifiers.append(group_id(key))
            path = folder / f"part-{shard:05d}.npz"
            np.savez_compressed(
                path,
                features=np.asarray(vectors, dtype=np.int64),
                Label=np.asarray(labels, dtype=np.uint8),
                Attack=np.asarray(attacks, dtype=str),
                multiplicity=np.asarray(counts, dtype=np.uint64),
                group_id=np.asarray(identifiers, dtype="S64"),
            )
            # Reopen every staged shard with pickle disabled, check totals/shape/hash.
            with np.load(path, allow_pickle=False) as saved:
                if saved["features"].shape != (len(rows), 7) or int(
                    saved["multiplicity"].sum()
                ) != sum(counts):
                    raise ValueError("Staged NPZ roundtrip verification failed")
            files.append(path)
            shard += 1
        print(f"Staged {p}: {shard} compact shards", flush=True)
    return files


def processed_readme():
    return """# NF-CSE prepared binary dataset

Generated by scripts/prepare_nf_cse.py. Source is immutable; these are normalized,
compact projected records, not full raw flows and not a trained model.

train/, validation/, test/ contain NPZ shards. Load with numpy.load(allow_pickle=False)
or cyberguard.features.nf_cse_preparation.iter_partition. features is canonical
int64 (column order in metadata/feature_contract.json), Label is uint8 0/1,
Attack is original Unicode metadata, multiplicity is uint64 original row count,
group_id is ASCII SHA-256 identifying the canonical schema/vector. Equality/grouping
uses exact canonical vectors, not a probabilistic digest comparison. Attack and
multiplicity/group_id must never enter the predictor matrix. Every normalized
vector and all its original label/Attack multiplicities stay in one partition.

Apply NFCSECompletedFlowFeatures/model_features to canonical values only via the
documented canonical model_features function; do NOT normalize canonical negative
status codes as if they were raw inputs. Future raw inference uses the same
NFCSECompletedFlowFeatures.transform. No learned parameters/scaling/imputation
statistics exist in this preparation. Do not cast counts to float32.

Use multiplicity as sample_weight for original-record population metrics. Optional
class weights must be computed from train only, multiplying multiplicity. Do not
weight validation/test by class frequency. Equal-vector diagnostics are a separate
estimand. Compact rows are not independent events; weighted fitting can differ from
expanded fitting in min_samples_leaf and other unweighted sample-count constraints.

Test is RESERVED and sealed by artifact hashes, not encrypted or access-controlled.
Only preparation integrity/support checks have read it; no predictions, selection,
threshold tuning or fitting. Freeze the model before future authorized evaluation.
Do not use validation in final fitting under this experiment. No capture/session/
time/host independence is established. The data require completed bidirectional
export records and do not support first-packet/partial-flow or live IDS claims.

Manifests record source/contract/code versions, fixed hash assignment, supports,
ambiguity, checksums and measurements. split_manifest.sha256 seals the manifest;
local hashes detect changes but do not authenticate untrusted files. Rerunning
with the same identity verifies and reuses the existing sealed output; incompatible
or changed artifacts fail. There is no overwrite option. Preserve this snapshot.
"""


def prepare(
    input_dir,
    output_dir,
    *,
    chunk_size=50000,
    seed=DEFAULT_SEED,
    temp_dir=None,
    dry_run=False,
):
    if chunk_size <= 0 or not 0 <= seed < 2**63:
        raise ValueError(
            "Chunk size must be positive; seed must be an integer in [0,2^63)"
        )
    started = time.monotonic()
    source, dictionary, header = discover(input_dir)
    output = Path(output_dir).resolve()
    raw = (ROOT / "data/raw").resolve()
    temp_root = (
        Path(temp_dir).resolve() if temp_dir else Path(tempfile.gettempdir()).resolve()
    )
    for dest in [output, temp_root]:
        if dest.is_relative_to(Path(input_dir).resolve()) or dest.is_relative_to(raw):
            raise ValueError(
                "Output/temporary paths must be outside raw input directories"
            )
    if source.is_relative_to(output):
        raise ValueError("Output cannot contain the raw source")
    identity = signature(source, dictionary, seed)
    if output.exists() and not dry_run:
        existing = verify_existing(output, identity)
        print(
            "Existing compatible sealed output verified; no files rewritten", flush=True
        )
        return existing
    snapshot = {
        p: (p.stat().st_size, p.stat().st_mtime_ns) for p in [source, dictionary]
    }
    with (
        tempfile.TemporaryDirectory(
            prefix="cyberguard_nf_prepare_", dir=temp_dir
        ) as tmp,
        closing(sqlite3.connect(str(Path(tmp) / "groups.sqlite"))) as db,
    ):
        db.execute("PRAGMA cache_size=-65536")
        db.execute("PRAGMA temp_store=FILE")
        db.execute("PRAGMA journal_mode=OFF")
        original_rows, statuses = build_index(
            source, db, chunk_size=chunk_size, seed=seed
        )
        plan = summarize(db)
        if plan["ambiguity"]["original_rows"] != original_rows:
            raise AssertionError("Multiplicity conservation failed")
        print(json.dumps(plan, indent=2), flush=True)
        if (
            snapshot != {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in snapshot}
            or sha256(source) != identity["source_sha256"]
            or sha256(dictionary) != identity["dictionary_sha256"]
        ):
            raise ValueError("Raw source/dictionary changed during preparation")
        metrics = {
            "seconds": round(time.monotonic() - started, 2),
            "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
            "sqlite_bytes": (Path(tmp) / "groups.sqlite").stat().st_size,
        }
        result = {
            "identity": identity,
            "source_path": str(source),
            "output_path": str(output),
            "source_columns": header,
            "plan": plan,
            "normalization_counts": statuses,
            "resources": metrics,
            "test_usage": "Reserved. Descriptive preparation and integrity checks only; no fitting, predictions or model selection.",
        }
        if dry_run or not plan["can_materialize"]:
            result["status"] = "dry_run" if dry_run else "blocked"
            if plan["guard_errors"]:
                result["status"] = "blocked"
            return result
        # The preflight above precedes even creation of a processed staging directory.
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="." + output.name + "-staging-", dir=output.parent
        ) as staging:
            stage = Path(staging)
            materialize(db, stage, chunk_size=chunk_size, seed=seed)
            metadata = stage / "metadata"
            metadata.mkdir()
            (metadata / "feature_contract.json").write_bytes(
                json_bytes(nf.feature_contract())
            )
            (metadata / "class_distribution.json").write_bytes(
                json_bytes(plan["partitions"])
            )
            preprocessing = {
                "version": nf.PREPROCESSING_VERSION,
                "learned_parameters": None,
                "fit_scope": "No learned transforms; fixed rules only",
                "source_dictionary_sha256": identity["dictionary_sha256"],
                "normalization_counts": statuses,
                "versions": {
                    "python": platform.python_version(),
                    "numpy": np.__version__,
                    "pandas": pd.__version__,
                    "sqlite": sqlite3.sqlite_version,
                },
                "storage": {
                    "version": STORAGE_VERSION,
                    "shard_compact_rows_maximum": chunk_size,
                    "features_dtype": "int64",
                    "Label_dtype": "uint8",
                    "multiplicity_dtype": "uint64",
                    "Attack": "Unicode metadata; never predictor",
                    "group_id": "S64 SHA-256(schema + exact canonical vector); exact values retained",
                },
            }
            (metadata / "preprocessing_manifest.json").write_bytes(
                json_bytes(preprocessing)
            )
            (stage / "README.md").write_text(processed_readme())
            artifacts = {
                p.relative_to(stage).as_posix(): {
                    "sha256": sha256(p),
                    "bytes": p.stat().st_size,
                }
                for p in sorted(stage.rglob("*"))
                if p.is_file()
            }
            if (
                sha256(source) != identity["source_sha256"]
                or sha256(dictionary) != identity["dictionary_sha256"]
            ):
                raise ValueError("Raw source changed during materialization")
            result["artifacts"] = artifacts
            metrics.update(
                {
                    "seconds": round(time.monotonic() - started, 2),
                    "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                    / 1024,
                    "artifact_bytes_excluding_split_manifest": sum(
                        x["bytes"] for x in artifacts.values()
                    ),
                }
            )
            result["status"] = "complete"
            manifest = metadata / "split_manifest.json"
            manifest.write_bytes(json_bytes(result))
            (metadata / "split_manifest.sha256").write_text(sha256(manifest) + "\n")
            verify_existing(stage, identity)
            if output.exists():
                raise ValueError(
                    "Output appeared during preparation; refusing overwrite"
                )
            os.rename(stage, output)  # same-filesystem atomic directory publication
        return result


def iter_partition(output_dir, partition):
    """Bounded future reader. Test access must be explicitly named by its caller."""
    if partition not in PARTITIONS:
        raise ValueError("Expected train, validation or test partition")
    output = Path(output_dir)
    manifest_path = output / "metadata/split_manifest.json"
    if (output / "metadata/split_manifest.sha256").read_text().strip() != sha256(
        manifest_path
    ):
        raise ValueError("Split manifest checksum mismatch")
    manifest = json.loads(manifest_path.read_text())
    if manifest["identity"]["schema_version"] != nf.CONTRACT_VERSION:
        raise ValueError("Unsupported partition schema version")
    for name, item in sorted(manifest["artifacts"].items()):
        if name.startswith(partition + "/") and name.endswith(".npz"):
            path = (output / name).resolve()
            if not path.is_relative_to(output.resolve()):
                raise ValueError("Unsafe shard path")
            if sha256(path) != item["sha256"]:
                raise ValueError(f"Partition shard checksum mismatch: {name}")
            with np.load(path, allow_pickle=False) as shard:
                yield {k: shard[k] for k in shard.files}


def preparation_report(result):
    plan = result["plan"]
    stats = plan["ambiguity"]

    def table(headers, rows):
        return "\n".join(
            [
                "| " + " | ".join(headers) + " |",
                "| " + " | ".join(["---"] * len(headers)) + " |",
            ]
            + ["| " + " | ".join(map(str, row)) + " |" for row in rows]
        )

    dist = table(
        [
            "Partition",
            "Original rows",
            "Row %",
            "Groups",
            "Compact records",
            "Benign",
            "Attack",
        ],
        [
            (
                p,
                d["rows"],
                f"{100 * d['row_fraction']:.6f}",
                d["groups"],
                d["compact_records"],
                d["binary_counts"]["0"],
                d["binary_counts"]["1"],
            )
            for p, d in plan["partitions"].items()
        ],
    )
    ambiguity = table(["Measure", "Observed value"], list(stats.items()))
    contract = table(
        ["Exact raw column", "Type/range", "Unit / definition"],
        [
            (f["name"], f"integer {f['minimum']}..{f['maximum']}", f["units"])
            for f in nf.feature_contract()["fields"]
        ],
    )
    return f"""# NF-CSE Phase 5B preparation report

Status: **{result["status"]}**. No classifier trained, no predictions evaluated, no test-based selection, no existing model/API/dashboard changes. This is a binary-only preparation using Label 0=Benign, 1=Attack; Attack is original offline metadata, never a predictor. [Phase 5A audit](overview.md) remains historical; it did not create these partitions.

## Frozen completed-flow contract

`{nf.CONTRACT_VERSION}`; preprocessing `{nf.PREPROCESSING_VERSION}`. Exact raw order:

{contract}

The supplied feature dictionary calls IN incoming and OUT outgoing. Treat these as exporter-relative forward/reverse totals within this dataset, not verified initiator/responder semantics. Byte-layer accounting, timeout, sampling and orientation parity with another exporter remain unknown. All seven fields are required; a missing column rejects header-only inputs. Explicit null values are represented by status. This is an offline **completed-flow, bidirectional** contract, never first-packet/partial-flow/live IDS inference. Both IPs, duration, L7_PROTO, cumulative TCP_FLAGS, labels and all other columns are excluded by an explicit allowlist.

Normalization: fixed protocol aliases and byte categories 0/1/2/6/17/47/58; other valid byte codes coalesce to other. Null/blank/NA-like values are missing, malformed/fractional/nonfinite/out-of-range/booleans invalid. Exact integral decimal/exponent numeric forms normalize identically; ports also accept hexadecimal. TCP/UDP ports retain valid zero, with -/-1 sentinel distinct. Known nontransport ports are not-applicable; unknown protocol ports have a separate unknown-protocol status. Final counts preserve zero and are bounded at 2^53−1 for exact float64 interoperability. There is no clipping, outlier removal or float32 conversion. Encoded model fields use deterministic zero fill plus categorical statuses, preserving canonical-vector information; protocol category codes are categorical, not an ordinal measurement. No vocabulary, imputation statistic, scaler, class weight or target encoder is learned. Future tree preprocessing can reuse NFCSECompletedFlowFeatures; raw and canonical entry points are deliberately distinct.

## Provenance and integrity

Source `{result["source_path"]}`; SHA-256 `{result["identity"]["source_sha256"]}`. Dictionary SHA-256 `{result["identity"]["dictionary_sha256"]}`. Input files were opened read-only and rehashed after indexing and materialization. No BoT-IoT or DNS data are opened by this workflow. Code/contract hashes, dependencies, input schema and per-file artifact hashes are in metadata. The processed snapshot is atomically published only after guards, roundtrips, checksum and inventory checks pass. Compatible reruns verify/reuse; incompatible or altered output is refused. There is no overwrite flag. Local checksums do not authenticate untrusted datasets.

## Full-data descriptive ambiguity (not model tuning)

{ambiguity}

The empirical binary ceiling sums max(benign count, attack count) within every canonical group / all original rows. It describes best possible deterministic labeling of these observed vectors, **not trained accuracy, validation/test performance or a generalization bound**. Groups with multiple Attack names include benign-vs-attack and attack-vs-attack ambiguity. No group or record is relabeled or discarded. All original class multiplicities survive. Status counts and original Attack supports are recorded in manifests.

## Fixed split and actual supports

Phase 5A found no capture/session/timestamp mapping. Endpoint graph connectivity makes a three-way both-endpoint-disjoint split with attack support infeasible. Use canonical feature groups as the documented fallback, not invented sessions. Seed **{result["identity"]["seed"]}**, method: `{METHOD}`. Exact canonical JSON vector plus schema/seed determines assignment, with no labels, IPs or row positions. No seed searching. No identical normalized vector crosses partitions; all binary-conflicting groups stay intact. Fixed encodings are injective on canonical vectors; no learned transform can create additional collisions in this preparation.

{dist}

Binary feature-group supports: { {p: d["binary_group_support"] for p, d in plan["partitions"].items()} }.

Predeclared stop guards: absolute deviation <=10 percentage points from each target 60/20/20 and at least 10 distinct feature groups supporting each binary label per partition. These are engineering checks, not statistical independence guarantees. Errors: {plan["guard_errors"]}. Counts were computed before staging partitions. Any failure blocks publication; no seed, label or guard is silently changed. Minority Attack names may have low or zero per-partition support; they are kept and reported, not silently dropped. No multiclass fit is authorized.

{table(["Attack (metadata)", *PARTITIONS], [(a, *[plan["partitions"][p]["Attack_counts"].get(a, 0) for p in PARTITIONS]) for a in sorted({a for d in plan["partitions"].values() for a in d["Attack_counts"]})])}

## Duplicate policy / population

Each shard stores one canonical vector + binary label + original Attack name with its uint64 multiplicity. This compacts the **projected normalized representation**, not a claimed removal of full raw records. Phase 5A's 1,077,740 full-record duplicate excess differs from these projected duplicate counts. Exact canonical vectors, not hash equality alone, define groups. SHA-256 group IDs are convenience identifiers; canonical values remain available for exact comparisons.

Use multiplicity as sample_weight for original-row population fitting/evaluation. Later optional balancing must derive only from train class mass and multiply multiplicity; validation/test use original multiplicities without balancing. Equal-vector metrics estimate something else and must be labelled separately. Weighting does not turn repeated flows into independent episodes, and compact fitting can change estimator constraints based on unweighted row counts (e.g. min_samples_leaf). No synthetic benign samples or oversampling are performed.

## Storage / resources / reproduction

Output is under data/processed/nf_cse_cic_ids2018 by default: train/, validation/, test/ NPZ shards; metadata/feature_contract.json, split_manifest.json + SHA-256 sidecar, class_distribution.json, preprocessing_manifest.json; one generated dataset README. NumPy loading disables pickle. Canonical fields are int64; labels uint8; multiplicity uint64; Attack Unicode; group IDs S64. No extra full-size raw CSV copies. Source chunks, compact shard batches and SQLite's 64 MiB page cache bound memory; SQLite grouping/sorts use disk. No GPU or worker pool.

Measured resources: `{result["resources"]}`. Manifest byte count excludes its own JSON/sidecar to avoid circular hash/size claims. Temporary indexes are deleted. Run `uv run python scripts/prepare_nf_cse.py --help`; `--dry-run` computes the complete descriptive plan but publishes no processed files. Materialize with `uv run python scripts/prepare_nf_cse.py --chunk-size 50000 --seed 20261115`. Same-identity reruns verify the sealed snapshot; do not create new seeds to optimize balance. Example options and test commands are in the root README.

## Future integration and remaining gates

Existing `bot_iot_restricted_baseline` accepts proto/sport/dport and returns four categories. Future `nf_cse_binary_completed_flow` requires seven finalized-flow inputs and returns Benign/Attack. Current Pydantic schemas, NetworkDetector, CLI validation and dashboard form/batch/response checks enforce the BoT contract and cannot accept a swapped artifact safely. Later work needs an allowlisted model registry, separate versioned input schemas/preprocessors/vocabularies, model-specific forms/CSV validation and explicit observation-boundary warnings. Header-only frontend records must never be forwarded to this model. No switching or endpoint/frontend behavior is implemented here; see [integration plan](integration_plan.md).

Test is reserved/sealed by checksums, **not encrypted/access-controlled**; preparation inspected only integrity, labels and support. Future modeling must fit/select on train/validation only, keep validation out of final fitting under this design, and freeze model/thresholds before an authorized final test evaluation. Group separation does not establish session/capture/host/time independence. Service signatures, collection artifacts, missing provenance, scarce SQL Injection records and unverified exporter semantics remain. Duration stays excluded despite its class-aligned artifact patterns. Obtain independently sourced capture/time/host evidence before operational claims.

## Software verification

Focused synthetic tests check normalization/order/exclusion, invalid/missing/zero values, label agreement, ambiguity accounting, deterministic group assignment, supports, atomic publication, rerun identity/hashes, dry-run behavior, source preservation and no access to other raw datasets. Synthetic fixtures test software, not generalization. Full-suite results for this execution are recorded below after regression checks.
"""
