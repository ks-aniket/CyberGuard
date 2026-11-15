"""Two bounded CPU fits on Phase 5B train/validation only. Reserved test is denied."""

from __future__ import annotations

import contextvars
import gc
import hashlib
import html
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import warnings
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from threadpoolctl import threadpool_limits

from cyberguard.features import nf_cse as nf
from cyberguard.features.nf_cse_preparation import sha256
from cyberguard.inference.nf_cse_model import NFCSEBinaryModel, NFLinearTransform
from cyberguard.training import nf_cse_metrics as evaluation

ROOT = Path(__file__).resolve().parents[3]
MODEL_ID = "nf_cse_binary_completed_flow"
TITLE = "Offline group-disjoint validation on NF-CSE-CIC-IDS2018."
DEFAULT_CONFIG = {
    "balance_classes": False,
    "logistic": {"C": 1.0, "max_iter": 200, "tol": 1e-4},
    "hist_gradient_boosting": {
        "max_iter": 150,
        "max_leaf_nodes": 31,
        "learning_rate": 0.1,
        "l2_regularization": 1.0,
        "min_samples_leaf": 20,
    },
}
ACTIVE_GUARD = contextvars.ContextVar("nf_cse_training_guard", default=None)
HOOK_INSTALLED = False


def audit_open(event, args):
    guard = ACTIVE_GUARD.get()
    if (
        event != "open"
        or guard is None
        or not isinstance(args[0], (str, bytes, os.PathLike))
    ):
        return
    path = Path(os.fsdecode(args[0])).resolve()
    root = guard["root"]
    if (
        path.is_relative_to(root / "test")
        or path == root / "metadata/class_distribution.json"
    ):
        raise PermissionError(
            "Reserved test data/evaluation metadata are prohibited in Phase 5C"
        )
    if path.is_relative_to(root):
        mode = args[1]
        flags = args[2]
        if (
            isinstance(mode, str)
            and any(c in mode for c in "wax+")
            or isinstance(flags, int)
            and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
        ):
            raise PermissionError("Processed data are immutable")
        guard["opened"].add(path.relative_to(root).as_posix())


@contextmanager
def deny_reserved(root):
    global HOOK_INSTALLED
    if not HOOK_INSTALLED:
        sys.addaudithook(audit_open)
        HOOK_INSTALLED = True
    guard = {"root": Path(root).resolve(), "opened": set()}
    token = ACTIVE_GUARD.set(guard)
    try:
        yield guard
    finally:
        ACTIVE_GUARD.reset(token)


class ManifestSubset:
    """Streaming JSON allowlist: skipped test objects are never decoded/retained.

    Common manifest bytes must be streamed for hashing and delimiters; only identity,
    train/validation artifact hashes/supports and the common feature contract survive.
    """

    def __init__(self, stream):
        self.stream = stream
        self.ch = stream.read(1)

    def take(self):
        ch = self.ch
        self.ch = self.stream.read(1)
        return ch

    def whitespace(self):
        while self.ch and self.ch.isspace():
            self.take()

    def string(self):
        raw = self.take()
        escaped = False
        while self.ch:
            c = self.take()
            raw += c
            if c == '"' and not escaped:
                return json.loads(raw)
            escaped = c == "\\" and not escaped
        raise ValueError("Truncated JSON string")

    def skip(self):
        self.whitespace()
        depth = 0
        in_string = False
        escaped = False
        while self.ch:
            c = self.ch
            if not in_string and depth == 0 and c in ",}]":
                break
            self.take()
            if in_string:
                if c == '"' and not escaped:
                    in_string = False
                escaped = c == "\\" and not escaped
            elif c == '"':
                in_string = True
            elif c in "[{":
                depth += 1
            elif c in "]}":
                depth -= 1
                if depth == 0:
                    break
            elif depth == 0 and c.isspace():
                break
        if in_string or depth:
            raise ValueError("Truncated skipped JSON")

    def allowed(self, path):
        if path[0] == "identity":
            return True
        if path[0] == "status":
            return True
        if path[0] == "artifacts":
            return (
                len(path) == 1
                or path[1].startswith(("train/", "validation/"))
                or path[1] == "metadata/feature_contract.json"
            )
        if path[0] == "plan":
            if len(path) == 1:
                return True
            if path[1] != "partitions":
                return False
            if len(path) == 2:
                return True
            if path[2] not in {"train", "validation"}:
                return False
            return len(path) == 3 or path[3] in {
                "rows",
                "compact_records",
                "groups",
                "binary_counts",
                "binary_group_support",
            }
        return False

    def value(self, path=()):
        self.whitespace()
        if path and not self.allowed(path):
            self.skip()
            return None
        if self.ch == "{":
            self.take()
            out = {}
            self.whitespace()
            while self.ch != "}":
                if self.ch != '"':
                    raise ValueError("Invalid manifest key")
                key = self.string()
                self.whitespace()
                if self.take() != ":":
                    raise ValueError("Invalid JSON separator")
                keep = self.allowed((*path, key))
                value = self.value((*path, key))
                if keep:
                    out[key] = value
                self.whitespace()
                if self.ch == ",":
                    self.take()
                    self.whitespace()
                elif self.ch != "}":
                    raise ValueError("Invalid JSON object")
            self.take()
            return out
        if self.ch == '"':
            return self.string()
        if self.ch == "[":
            self.take()
            out = []
            self.whitespace()
            while self.ch != "]":
                out.append(self.value(path))
                self.whitespace()
                if self.ch == ",":
                    self.take()
                    self.whitespace()
                elif self.ch != "]":
                    raise ValueError("Invalid JSON array")
            self.take()
            return out
        raw = ""
        while self.ch and self.ch not in ",}]" and not self.ch.isspace():
            raw += self.take()
        return json.loads(raw)


def load_manifest(root):
    path = root / "metadata/split_manifest.json"
    digest = sha256(path)
    if (root / "metadata/split_manifest.sha256").read_text().strip() != digest:
        raise ValueError("Partition manifest checksum mismatch")
    with path.open(encoding="utf-8") as stream:
        manifest = ManifestSubset(stream).value()
    if (
        manifest.get("status") != "complete"
        or manifest["identity"]["schema_version"] != nf.CONTRACT_VERSION
    ):
        raise ValueError("Incomplete/unsupported processed dataset")
    expected_code = manifest["identity"]["implementation_sha256"].get("nf_cse.py")
    if expected_code != sha256(nf.__file__):
        raise ValueError(
            "Normalizer source differs from sealed Phase 5B implementation"
        )
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
        raise ValueError("Feature order/preprocessing mismatch")
    return manifest, digest


def sample_mask(ids, fraction, seed):
    if fraction == 1:
        return np.ones(len(ids), dtype=bool)
    bound = int(fraction * 2**64)
    return np.fromiter(
        (
            int.from_bytes(
                hashlib.sha256(
                    str(seed).encode() + b"/development/" + bytes(g)
                ).digest()[:8],
                "big",
            )
            < bound
            for g in ids
        ),
        dtype=bool,
        count=len(ids),
    )


def load_partition(root, manifest, partition, *, fraction=1.0, seed=20261115):
    if partition not in {"train", "validation"}:
        raise ValueError("Training loader permits train/validation only")
    if partition != "train" and fraction != 1:
        raise ValueError("Validation sampling is prohibited")
    expected = manifest["plan"]["partitions"][partition]
    capacity = expected["compact_records"]
    X = np.empty((capacity, len(nf.MODEL_FEATURES)), dtype=np.float64)
    y = np.empty(capacity, dtype=np.uint8)
    weight = np.empty(capacity, dtype=np.float64)
    codes = np.empty(capacity, dtype=np.uint16) if partition == "validation" else None
    groups = np.empty(capacity, dtype="S64") if partition == "validation" else None
    names = []
    name_codes = {}
    filled = 0
    read_records = 0
    original_mass = 0
    binary_mass = np.zeros(2, dtype=np.int64)
    used = {}
    for name, item in sorted(manifest["artifacts"].items()):
        if not name.startswith(partition + "/") or not name.endswith(".npz"):
            continue
        path = (root / name).resolve()
        if not path.is_relative_to(root / partition) or sha256(path) != item["sha256"]:
            raise ValueError(f"Unsafe/modified {partition} shard: {name}")
        used[name] = item["sha256"]
        with np.load(path, allow_pickle=False) as shard:
            canonical = shard["features"]
            labels = shard["Label"]
            multiplicity = shard["multiplicity"]
            if (
                canonical.dtype != np.int64
                or canonical.shape != (len(labels), 7)
                or multiplicity.shape != labels.shape
                or not set(np.unique(labels)) <= {0, 1}
                or np.any(multiplicity <= 0)
            ):
                raise ValueError("Invalid compact shard schema/weights")
            read_records += len(labels)
            original_mass += int(multiplicity.sum())
            for b in [0, 1]:
                binary_mass[b] += int(multiplicity[labels == b].sum())
            keep = (
                sample_mask(shard["group_id"], fraction, seed)
                if fraction != 1
                else np.ones(len(labels), dtype=bool)
            )
            count = int(keep.sum())
            end = filled + count
            X[filled:end] = nf.model_features(
                pd.DataFrame(canonical[keep], columns=nf.RAW_FEATURES)
            ).to_numpy(dtype=np.float64)
            y[filled:end] = labels[keep]
            weight[filled:end] = multiplicity[keep]
            if partition == "validation":
                attack = shard["Attack"]
                if not np.all((attack == "Benign") == (labels == 0)):
                    raise ValueError("Validation metadata label disagreement")
                for a in np.unique(attack):
                    a = str(a)
                    if a not in name_codes:
                        if len(names) >= 65535:
                            raise ValueError("Excessive validation family cardinality")
                        name_codes[a] = len(names)
                        names.append(a)
                codes[filled:end] = np.fromiter(
                    (name_codes[str(a)] for a in attack), dtype=np.uint16, count=count
                )
                groups[filled:end] = shard["group_id"]
            filled = end
    if (
        read_records != capacity
        or original_mass != expected["rows"]
        or binary_mass.tolist()
        != [expected["binary_counts"]["0"], expected["binary_counts"]["1"]]
    ):
        raise ValueError(f"{partition} multiplicity/support conservation failed")
    if not filled or set(np.unique(y[:filled])) != {0, 1}:
        raise ValueError("Training/validation selection lacks both binary classes")
    print(
        f"Loaded {partition}: {filled:,} compact / {int(weight[:filled].sum()):,} weighted records; fraction={fraction}",
        flush=True,
    )
    return {
        "X": X[:filled],
        "y": y[:filled],
        "weight": weight[:filled],
        "codes": codes,
        "groups": groups,
        "names": names,
        "used_files": used,
        "source_compact_records": capacity,
        "source_original_records": original_mass,
    }


def training_config(path=None):
    config = (
        json.loads(Path(path).read_text())
        if path
        else json.loads(json.dumps(DEFAULT_CONFIG))
    )
    if set(config) != set(DEFAULT_CONFIG) or not isinstance(
        config["balance_classes"], bool
    ):
        raise ValueError("Invalid training configuration keys")
    for model in ["logistic", "hist_gradient_boosting"]:
        if set(config[model]) != set(DEFAULT_CONFIG[model]):
            raise ValueError(f"Unexpected {model} configuration keys")
        if not 1 <= config[model]["max_iter"] <= 1000:
            raise ValueError("max_iter must be 1..1000")
    l = config["logistic"]
    h = config["hist_gradient_boosting"]
    if not np.isfinite(list(l.values())).all() or l["C"] <= 0 or l["tol"] <= 0:
        raise ValueError("Invalid logistic configuration")
    if (
        not np.isfinite(list(h.values())).all()
        or not 2 <= h["max_leaf_nodes"] <= 127
        or not 0 < h["learning_rate"] <= 1
        or h["l2_regularization"] < 0
        or h["min_samples_leaf"] < 2
    ):
        raise ValueError("Invalid bounded histogram configuration")
    return config


def fit_model(name, train, config, seed):
    class_mass = np.bincount(train["y"], weights=train["weight"], minlength=2)
    class_factor = (
        class_mass.sum() / (2 * class_mass) if config["balance_classes"] else np.ones(2)
    )
    weights = train["weight"] * class_factor[train["y"]]
    start = time.perf_counter()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        transform = None
        if name == "logistic":
            transform = NFLinearTransform().fit(
                train["X"], sample_weight=train["weight"]
            )
            matrix = transform.transform(train["X"])
            classifier = LogisticRegression(
                solver="lbfgs", random_state=seed, **config["logistic"]
            )
            classifier.fit(matrix, train["y"], sample_weight=weights)
            del matrix
        else:
            categorical = np.zeros(len(nf.MODEL_FEATURES), dtype=bool)
            categorical[[0, 7, 8, 9, 10, 11, 12]] = True
            classifier = HistGradientBoostingClassifier(
                categorical_features=categorical,
                early_stopping=False,
                random_state=seed,
                **config["hist_gradient_boosting"],
            )
            classifier.fit(train["X"], train["y"], sample_weight=weights)
    elapsed = time.perf_counter() - start
    return NFCSEBinaryModel(classifier, transform), {
        "fit_seconds": elapsed,
        "warnings": [str(w.message) for w in caught],
        "class_weight_factors": class_factor.tolist(),
        "iterations": np.asarray(getattr(classifier, "n_iter_", [])).tolist(),
        "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
    }


def probe_frame():
    return pd.DataFrame(
        [
            {
                "PROTOCOL": "tcp",
                "L4_SRC_PORT": 49152,
                "L4_DST_PORT": 443,
                "IN_BYTES": 1200,
                "OUT_BYTES": 2400,
                "IN_PKTS": 8,
                "OUT_PKTS": 12,
            },
            {
                "PROTOCOL": "icmp",
                "L4_SRC_PORT": None,
                "L4_DST_PORT": None,
                "IN_BYTES": 0,
                "OUT_BYTES": 0,
                "IN_PKTS": 0,
                "OUT_PKTS": 0,
            },
        ]
    )


def score_validation(model, validation, batch_size):
    score = np.empty(len(validation["y"]), dtype=np.float64)
    start = time.perf_counter()
    for begin in range(0, len(score), batch_size):
        score[begin : begin + batch_size] = model.score_encoded(
            validation["X"][begin : begin + batch_size]
        )
    seconds = time.perf_counter() - start
    probe = probe_frame().iloc[:1]
    model.predict_proba(probe)
    latency = []
    for _ in range(50):
        start = time.perf_counter()
        model.predict_proba(probe)
        latency.append((time.perf_counter() - start) * 1000)
    return score, {
        "validation_score_seconds": seconds,
        "scored_compact_records": len(score),
        "compact_records_per_second": len(score) / seconds,
        "amortized_ms_per_compact_record": 1000 * seconds / len(score),
        "raw_synthetic_single_record_latency_ms_median": float(np.median(latency)),
        "raw_synthetic_single_record_latency_ms_p95": float(np.quantile(latency, 0.95)),
        "batch_size": batch_size,
        "timing_scope": "Validation canonical encoded input -> probabilities (including fitted LR transform), excludes disk IO. Raw single-record latency uses 50 repeated software probes, not deployment traffic.",
    }


def json_dump(value, path):
    def convert(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        if isinstance(obj, np.generic):
            return obj.item()
        raise TypeError(type(obj).__name__)

    Path(path).write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False, default=convert)
        + "\n"
    )


def validate_artifact(path):
    path = Path(path)
    metadata = json.loads(path.with_suffix(".metadata.json").read_text())
    if sha256(path) != metadata["artifact_sha256"]:
        raise ValueError("Model checksum mismatch")
    model = joblib.load(path)  # only explicitly trusted local artifacts
    for key in [
        "model_id",
        "model_type",
        "feature_contract_version",
        "feature_order",
        "class_mapping",
        "selected_threshold",
        "source_dataset_sha256",
        "partition_manifest_sha256",
    ]:
        if metadata.get(key) != model.metadata_.get(key):
            raise ValueError(f"Artifact metadata mismatch: {key}")
    if (
        model.metadata_["feature_contract_version"] != nf.CONTRACT_VERSION
        or list(model.feature_names_in_) != list(nf.RAW_FEATURES)
        or list(model.classes_) != [0, 1]
        or model.threshold != metadata["selected_threshold"]
    ):
        raise ValueError("Artifact feature/class/threshold metadata mismatch")
    return model, metadata


def verify_artifact(path, threads=4):
    with threadpool_limits(limits=threads):
        model, metadata = validate_artifact(path)
        frame = probe_frame()
        probabilities = model.predict_proba(frame)
        prediction = model.predict(frame)
        if not np.allclose(probabilities.sum(axis=1), 1) or not np.array_equal(
            prediction, (probabilities[:, 1] >= model.threshold).astype(np.uint8)
        ):
            raise ValueError("Probability/threshold alignment failed")
        return {
            "software_verification_only": True,
            "feature_contract_version": metadata["feature_contract_version"],
            "selected_threshold": model.threshold,
            "predictions": prediction.tolist(),
            "labels": model.predict_labels(frame).tolist(),
            "probabilities_Benign_Attack": probabilities.tolist(),
            "normalizer_fit_not_called": True,
        }


def run_experiment(
    processed_dir,
    output_dir,
    report_dir,
    *,
    config=None,
    threads=4,
    seed=20261115,
    dev_fraction=1.0,
    batch_size=50000,
):
    if (
        not 1 <= threads <= max(os.cpu_count() or 1, 1)
        or not 0 < dev_fraction <= 1
        or batch_size < 1
        or not 0 <= seed < 2**63
    ):
        raise ValueError("Invalid threads/seed/development fraction/batch size")
    config = training_config() if config is None else config
    root = Path(processed_dir).resolve()
    output = Path(output_dir).resolve()
    reports = Path(report_dir).resolve()
    for dest in [output, reports]:
        if dest.is_relative_to(root) or dest.is_relative_to(ROOT / "data/raw"):
            raise ValueError("Outputs must be outside processed/raw data")
    final_model = output / (MODEL_ID + ".joblib")
    final_meta = final_model.with_suffix(".metadata.json")
    if final_model.exists() or final_meta.exists():
        raise ValueError("NF-CSE model output exists; no overwrite is supported")
    if reports.exists() and any(reports.iterdir()):
        raise ValueError(
            "Report directory is nonempty; choose a new experiment directory"
        )
    started = time.perf_counter()
    timestamp = datetime.now(UTC).isoformat()
    with deny_reserved(root) as access, threadpool_limits(limits=threads):
        manifest, manifest_hash = load_manifest(root)
        train = load_partition(
            root, manifest, "train", fraction=dev_fraction, seed=seed
        )
        validation = load_partition(root, manifest, "validation")
        output.mkdir(parents=True, exist_ok=True)
        reports.parent.mkdir(parents=True, exist_ok=True)
        results = {}
        curve_data = {}
        scores_by_model = {}
        with (
            tempfile.TemporaryDirectory(prefix=".nf-cse-fit-", dir=output) as tmp,
            tempfile.TemporaryDirectory(
                prefix=".nf-cse-report-", dir=reports.parent
            ) as report_tmp,
        ):
            tmp = Path(tmp)
            stage = Path(report_tmp)
            for name in ["logistic", "hist_gradient_boosting"]:
                print(
                    f"Fitting {name}: compact records={len(train['y']):,}, threads={threads}",
                    flush=True,
                )
                model, resources = fit_model(name, train, config, seed)
                score, timing = score_validation(model, validation, batch_size)
                curve = evaluation.curves(validation["y"], score, validation["weight"])
                threshold, index = evaluation.select_threshold(curve)
                selected = evaluation.metrics(
                    validation["y"], score, validation["weight"], threshold
                )
                fixed = evaluation.metrics(
                    validation["y"], score, validation["weight"], 0.5
                )
                families = evaluation.family_recall(
                    validation["y"],
                    score,
                    validation["weight"],
                    validation["codes"],
                    validation["names"],
                    validation["groups"],
                    threshold,
                )
                fixed_families = evaluation.family_recall(
                    validation["y"],
                    score,
                    validation["weight"],
                    validation["codes"],
                    validation["names"],
                    validation["groups"],
                    0.5,
                )
                candidate = tmp / (name + ".joblib")
                joblib.dump(model, candidate, compress=3)
                results[name] = {
                    "fixed_0_5": fixed,
                    "selected": selected,
                    "families_selected": families,
                    "families_fixed_0_5": fixed_families,
                    "fit": resources,
                    "inference": timing,
                    "candidate_bytes": candidate.stat().st_size,
                    "selection_index": index,
                    "threshold_rule": "Maximize weighted validation attack recall with benign FPR <=0.01; tie: lower FPR then higher threshold. Score >= threshold is Attack. No split/test tuning.",
                }
                curve_data[name] = curve
                scores_by_model[name] = score
                print(
                    f"{name}: fit {resources['fit_seconds']:.2f}s; selected threshold={threshold:.10g}; recall={selected['recall']:.6f}; FPR={selected['benign_fpr']:.6f}",
                    flush=True,
                )
                del model
                gc.collect()

            def rank(name):
                d = results[name]
                s = d["selected"]
                return (
                    s["recall"],
                    s["precision"],
                    s["average_precision"],
                    min(row["recall"] for row in d["families_selected"]),
                    d["inference"]["compact_records_per_second"],
                    -d["candidate_bytes"],
                )

            selected_name = max(results, key=rank)
            selected_result = results[selected_name]
            metadata = {
                "model_id": MODEL_ID,
                "model_type": selected_name,
                "feature_contract_version": nf.CONTRACT_VERSION,
                "preprocessing_version": nf.PREPROCESSING_VERSION,
                "feature_order": list(nf.RAW_FEATURES),
                "encoded_feature_order": list(nf.MODEL_FEATURES),
                "class_mapping": {"0": "Benign", "1": "Attack"},
                "selected_threshold": selected_result["selected"]["threshold"],
                "threshold_rule": selected_result["threshold_rule"],
                "training_configuration": config,
                "random_seed": seed,
                "threads": threads,
                "development_training_fraction": dev_fraction,
                "training_population": {
                    "compact_records": len(train["y"]),
                    "original_record_mass": int(train["weight"].sum()),
                    "binary_mass": np.bincount(
                        train["y"], weights=train["weight"], minlength=2
                    )
                    .astype(int)
                    .tolist(),
                },
                "validation_population": {
                    "compact_records": len(validation["y"]),
                    "original_record_mass": int(validation["weight"].sum()),
                },
                "source_dataset_sha256": manifest["identity"]["source_sha256"],
                "partition_manifest_sha256": manifest_hash,
                "split_seed": manifest["identity"]["seed"],
                "training_timestamp_utc": timestamp,
                "versions": {
                    "python": sys.version.split()[0],
                    "sklearn": sklearn.__version__,
                    "numpy": np.__version__,
                    "pandas": pd.__version__,
                },
                "validation_metrics": selected_result["selected"],
                "warning": TITLE
                + " Completed-flow bidirectional exports only; uncalibrated scores. No independent-capture, packet-level or live deployment performance is established. Not integrated into the API/dashboard.",
                "selection_rationale": "Ranked by validation recall at FPR<=1%, then precision, AP, minimum family recall, compact-record throughput, smaller artifact. Exactly two configured fits; no search.",
            }
            chosen = joblib.load(tmp / (selected_name + ".joblib"))
            chosen.threshold = metadata["selected_threshold"]
            chosen.metadata_ = metadata
            staged_model = tmp / (MODEL_ID + ".joblib")
            joblib.dump(chosen, staged_model, compress=3)
            expected = chosen.score_encoded(
                validation["X"][: min(1000, len(validation["y"]))]
            )
            loaded = joblib.load(staged_model)
            if not np.array_equal(
                expected, loaded.score_encoded(validation["X"][: len(expected)])
            ):
                raise ValueError("Serialization changed validation scores")
            metadata = {
                **metadata,
                "artifact_sha256": sha256(staged_model),
                "artifact_bytes": staged_model.stat().st_size,
            }
            json_dump(metadata, staged_model.with_suffix(".metadata.json"))
            environment = {
                **os.environ,
                "PYTHONPATH": str(ROOT / "src"),
                "OMP_NUM_THREADS": str(threads),
                "OPENBLAS_NUM_THREADS": str(threads),
                "MKL_NUM_THREADS": str(threads),
            }
            command = [
                sys.executable,
                str(ROOT / "scripts/train_nf_cse.py"),
                "verify",
                "--model",
                str(staged_model),
                "--threads",
                str(threads),
            ]
            fresh = subprocess.run(
                command,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if fresh.returncode:
                raise RuntimeError(
                    "Fresh-process model verification failed: " + fresh.stderr[-1000:]
                )
            fresh_verification = json.loads(fresh.stdout)
            # Only selected train/validation shards and common manifests are rehashed.
            for name, digest in {
                **train["used_files"],
                **validation["used_files"],
            }.items():
                if sha256(root / name) != digest:
                    raise ValueError("Processed train/validation data changed")
            if sha256(root / "metadata/split_manifest.json") != manifest_hash:
                raise ValueError("Shared partition manifest changed")
            metadata["resources"] = {
                "wall_seconds": time.perf_counter() - started,
                "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                / 1024,
                "timing_scope": "Through fitting, validation, serialization and fresh-process verification; excludes report rendering/publication.",
            }
            run = {
                "scope": TITLE,
                "selected_model": selected_name,
                "metadata": metadata,
                "models": results,
                "fresh_process_verification": fresh_verification,
                "processed_files_opened": sorted(access["opened"]),
                "reserved_test_access": "Blocked by the training-process audit hook; no test shard, class_distribution.json or test evaluation object is loaded. Common manifest test objects are skipped without JSON decoding.",
                "sampling": "Full training partition"
                if dev_fraction == 1
                else "TRAINING-ONLY HASH-GROUP DEVELOPMENT SAMPLE; not full-data training. Validation is unchanged/full.",
            }
            write_reports(run, curve_data, stage)
            json_dump(metadata, staged_model.with_suffix(".metadata.json"))
            shutil.copyfile(staged_model, final_model)
            shutil.copyfile(staged_model.with_suffix(".metadata.json"), final_meta)
            if reports.exists():
                reports.rmdir()
            os.rename(stage, reports)
            print(
                f"Selected {selected_name}; model: {final_model}; report: {reports / 'training_report.md'}",
                flush=True,
            )
            return run


def downsample(length, maximum=700, extra=()):
    return np.unique(
        np.r_[
            np.linspace(0, max(length - 1, 0), min(length, maximum), dtype=int),
            np.asarray(extra, dtype=int),
        ]
    )


def svg_lines(path, title, xlabel, ylabel, series, *, xmax=1.0, vertical=None):
    colors = ["#2563eb", "#ea580c", "#16a34a", "#9333ea"]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1050" height="650" role="img"><title>{html.escape(title)}</title><rect width="100%" height="100%" fill="white"/><g font-family="sans-serif" font-size="13">',
        f'<text x="60" y="25">{html.escape(title)}</text>',
        '<text x="60" y="46">Weighted validation; display downsampled, metrics/threshold choice use all scores.</text>',
    ]
    for i in range(6):
        px = 80 + 840 * i / 5
        py = 540 - 450 * i / 5
        parts.extend(
            [
                f'<path d="M80 {py}H920 M{px} 90V540" stroke="#ddd" fill="none"/>',
                f'<text x="35" y="{py}">{i / 5:.1f}</text>',
                f'<text x="{px}" y="560">{xmax * i / 5:.2g}</text>',
            ]
        )
    if vertical is not None:
        x = 80 + 840 * vertical / xmax
        parts.append(f'<path d="M{x} 90V540" stroke="#666" stroke-dasharray="5,5"/>')
    for i, (name, x, y) in enumerate(series):
        x, y = np.asarray(x), np.asarray(y)
        mask = np.isfinite(x) & np.isfinite(y) & (x <= xmax)
        x, y = x[mask], y[mask]
        idx = downsample(len(x))
        points = " ".join(
            f"{80 + 840 * a / xmax:.3f},{540 - 450 * b:.3f}"
            for a, b in zip(x[idx], y[idx], strict=True)
        )
        color = colors[i % len(colors)]
        parts.append(
            f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2"/><text x="{100 + i % 2 * 450}" y="{590 + i // 2 * 20}" fill="{color}">{html.escape(name)}</text>'
        )
    parts.append(
        f'<text x="390" y="640">{html.escape(xlabel)}</text><text x="10" y="75">{html.escape(ylabel)}</text></g></svg>'
    )
    path.write_text("".join(parts))


def write_reports(run, curve_data, stage):
    stage.mkdir(exist_ok=True)
    fig = stage / "figures"
    fig.mkdir()
    rows = []
    classification = []
    confusion = []
    families = []
    thresholds = []
    for name, d in run["models"].items():
        s = d["selected"]
        rows.append(
            {
                "model": name,
                "selected_threshold": s["threshold"],
                "recall_at_FPR_constraint": s["recall"],
                "benign_fpr": s["benign_fpr"],
                "precision": s["precision"],
                "f1": s["f1"],
                "accuracy": s["accuracy"],
                "balanced_accuracy": s["balanced_accuracy"],
                "roc_auc": s["roc_auc"],
                "average_precision": s["average_precision"],
                "fit_seconds": d["fit"]["fit_seconds"],
                "compact_records_per_second": d["inference"][
                    "compact_records_per_second"
                ],
                "candidate_bytes": d["candidate_bytes"],
            }
        )
        for mode in ["fixed_0_5", "selected"]:
            m = d[mode]
            for label in ["Benign", "Attack"]:
                classification.append(
                    {
                        "model": name,
                        "operating_point": mode,
                        "class": label,
                        **m["classification_report"][label],
                    }
                )
            for i, a in enumerate(["Benign", "Attack"]):
                for j, p in enumerate(["Benign", "Attack"]):
                    confusion.append(
                        {
                            "model": name,
                            "operating_point": mode,
                            "actual": a,
                            "predicted": p,
                            "original_records": m["confusion_matrix"][i][j],
                        }
                    )
            for family in d[
                "families_fixed_0_5" if mode == "fixed_0_5" else "families_selected"
            ]:
                families.append(
                    {
                        "model": name,
                        "operating_point": mode,
                        "threshold": m["threshold"],
                        **family,
                    }
                )
        c = curve_data[name]
        indices = downsample(len(c["threshold"]), 1000, [d["selection_index"]])
        for i in indices:
            thresholds.append(
                {
                    "model": name,
                    "threshold": float(c["threshold"][i]),
                    "benign_fpr": float(c["fpr"][i]),
                    "attack_recall": float(c["recall"][i]),
                    "selected": int(i == d["selection_index"]),
                    "point": "exact ROC threshold (display subset)",
                }
            )
        thresholds.append(
            {
                "model": name,
                "threshold": 0.5,
                "benign_fpr": d["fixed_0_5"]["benign_fpr"],
                "attack_recall": d["fixed_0_5"]["recall"],
                "selected": int(s["threshold"] == 0.5),
                "point": "fixed 0.5",
            }
        )
    pd.DataFrame(rows).to_csv(stage / "model_comparison.csv", index=False)
    pd.DataFrame(classification).to_csv(
        stage / "classification_report.csv", index=False
    )
    pd.DataFrame(confusion).to_csv(stage / "confusion_matrix.csv", index=False)
    pd.DataFrame(families).to_csv(stage / "attack_family_recall.csv", index=False)
    pd.DataFrame(thresholds).to_csv(stage / "threshold_analysis.csv", index=False)
    json_dump(run, stage / "validation_metrics.json")
    svg_lines(
        fig / "roc.svg",
        TITLE + " ROC",
        "Benign FPR",
        "Attack recall",
        [(n, c["fpr"], c["recall"]) for n, c in curve_data.items()],
        vertical=0.01,
    )
    svg_lines(
        fig / "precision_recall.svg",
        TITLE + " PR",
        "Attack recall",
        "Attack precision",
        [(n, c["pr_recall"], c["precision"]) for n, c in curve_data.items()],
    )
    svg_lines(
        fig / "fpr_recall_zoom.svg",
        "Validation FPR budget trade-off",
        "Benign FPR (zoom 0..0.05)",
        "Attack recall",
        [(n, c["fpr"], c["recall"]) for n, c in curve_data.items()],
        xmax=0.05,
        vertical=0.01,
    )
    svg_lines(
        fig / "threshold_fpr_recall.svg",
        "Validation threshold sensitivity (>= boundary)",
        "Attack probability threshold",
        "Weighted rate",
        [
            (n + " FPR", c["threshold"][::-1], c["fpr"][::-1])
            for n, c in curve_data.items()
        ]
        + [
            (n + " recall", c["threshold"][::-1], c["recall"][::-1])
            for n, c in curve_data.items()
        ],
    )
    # Two exact weighted confusion matrices at the selected operating points.
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="440" role="img"><title>Weighted validation confusion matrices, selected thresholds</title><rect width="100%" height="100%" fill="white"/><g font-family="sans-serif" font-size="16"><text x="25" y="30">Actual rows / predicted columns; original-record multiplicities</text>'
    ]
    for i, (name, d) in enumerate(run["models"].items()):
        left = 50 + i * 530
        parts.append(f'<text x="{left}" y="70">{html.escape(name)}</text>')
        for k, label in enumerate(["Benign", "Attack"]):
            parts.append(
                f'<text x="{left + 145 + k * 160}" y="105">{label}</text><text x="{left}" y="{175 + k * 120}">{label}</text>'
            )
        for a in range(2):
            for p in range(2):
                count = d["selected"]["confusion_matrix"][a][p]
                color = "#dbeafe" if a == p else "#ffedd5"
                parts.append(
                    f'<rect x="{left + 110 + p * 160}" y="{120 + a * 120}" width="150" height="110" fill="{color}"/><text x="{left + 120 + p * 160}" y="{175 + a * 120}">{count:,}</text>'
                )
    (fig / "confusion_matrix.svg").write_text("".join(parts) + "</g></svg>")
    family_names = [
        row["attack_family"]
        for row in run["models"][run["selected_model"]]["families_selected"]
    ]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1150" height="{100 + len(family_names) * 55}" role="img"><title>Validation attack-family recall</title><rect width="100%" height="100%" fill="white"/><g font-family="sans-serif" font-size="12"><text x="20" y="25">Selected operating thresholds; weighted family recall. Blue=logistic, orange=histogram.</text>'
    ]
    for i, family in enumerate(family_names):
        y = 65 + i * 55
        parts.append(f'<text x="10" y="{y + 12}">{html.escape(family)}</text>')
        for j, (name, d) in enumerate(run["models"].items()):
            row = next(
                r for r in d["families_selected"] if r["attack_family"] == family
            )
            value = row["recall"]
            color = ["#2563eb", "#ea580c"][j]
            parts.append(
                f'<rect x="235" y="{y + j * 22}" height="18" width="{500 * value:.3f}" fill="{color}"/><text x="750" y="{y + j * 22 + 13}">{value:.4f}; FN {row["false_negatives"]:,}/{row["validation_records"]:,}; groups {row["distinct_feature_groups"]:,}</text>'
            )
    (fig / "attack_family_recall.svg").write_text("".join(parts) + "</g></svg>")

    def md(headers, rows):
        return "\n".join(
            [
                "| " + " | ".join(headers) + " |",
                "| " + " | ".join(["---"] * len(headers)) + " |",
            ]
            + [
                "| " + " | ".join(str(x).replace("|", "\\|") for x in row) + " |"
                for row in rows
            ]
        )

    summary = md(
        [
            "Model",
            "Operating point",
            "Threshold",
            "Accuracy",
            "Balanced accuracy",
            "Precision",
            "Attack recall",
            "F1",
            "Benign FPR",
            "FP / 10k benign",
            "ROC-AUC",
            "Average precision",
        ],
        [
            (
                n,
                mode,
                f"{d[mode]['threshold']:.17g}",
                *[
                    f"{d[mode][k]:.6f}"
                    for k in [
                        "accuracy",
                        "balanced_accuracy",
                        "precision",
                        "recall",
                        "f1",
                        "benign_fpr",
                        "false_positives_per_10000_benign",
                        "roc_auc",
                        "average_precision",
                    ]
                ],
            )
            for n, d in run["models"].items()
            for mode in ["fixed_0_5", "selected"]
        ],
    )
    selected = run["models"][run["selected_model"]]
    warning = (
        "No useful recall at the FPR constraint; reject-all is a trade-off, not success."
        if selected["selected"]["recall"] < 0.1
        else "The 1% FPR constraint is satisfied on this threshold-selection validation set; it is not an independent false-alarm guarantee."
    )
    report = f"""# NF-CSE binary training and validation

**{TITLE}** Neither independent-capture nor deployment performance. Reserved test untouched; not integrated into FastAPI or Streamlit.

Selected: **{run["selected_model"]}**, using declared validation-only ranking: attack recall at benign FPR <=1%, then precision, average precision, minimum family recall, CPU throughput and smaller candidate size. Exactly two configured fits, no hyperparameter search, no split regeneration/seed search. {warning}

## Populations, contract and fitting

Model ID `{MODEL_ID}`, raw contract `{nf.CONTRACT_VERSION}`: `{", ".join(nf.RAW_FEATURES)}`. Seven raw finalized bidirectional-export inputs; IPs, duration, labels, Attack names and identifiers excluded. Existing Phase 5B normalization/model encoding reused, not duplicated. Never normalize stored canonical negative statuses as raw fields. Required field order and preprocessing version are in the artifact. There is no packet, partial-flow or live detection capability. Export orientation, accounting, timeout and cross-exporter parity remain unverified.

Training population: `{run["metadata"]["training_population"]}`. Validation population: `{run["metadata"]["validation_population"]}`. Experiment: **{run["sampling"]}**. Original multiplicities remain sample weights, retaining conflicting labels and Attack metadata counts. No expansion, vote relabeling, silent deduplication or synthetic benign data. Balancing setting: `{run["metadata"]["training_configuration"]["balance_classes"]}`. Optional balancing multiplies train-only class factors once; estimator class_weight stays None. Validation uses only original multiplicities. Compact rows can change min_samples_leaf and other rules based on unweighted row counts; weighted objectives do not make this identical to expanded fitting.

Logistic: fixed log1p of four counters, port/65535, multiplicity-weighted numeric StandardScaler fitted only on selected training records; fixed protocol/status one-hot categories. No validation fitting. Histogram: Phase 5B's 13 fields, native categorical protocol/status fields, no scaling; early_stopping=False, no internal random-row validation. Thresholds/probabilities are uncalibrated.

Config: `{run["metadata"]["training_configuration"]}`; seed {run["metadata"]["random_seed"]}; CPU threads {run["metadata"]["threads"]}. [Detailed metrics/config/provenance](validation_metrics.json).

## Validation metrics

{summary}

Confusion order is actual rows/predicted columns `[Benign, Attack]`. CSVs distinguish both models and both operating points. Average precision is weighted sklearn average_precision_score (step-wise AP), **not trapezoidal PR-AUC**. All aggregate/family metrics use original-record weights, not training class weights. Selection is an empirical validation constraint, not calibrated probabilities or generalization confidence. A Normal/Benign prediction does not prove safety against unknown threats.

![ROC](figures/roc.svg)
![Precision recall](figures/precision_recall.svg)
![FPR/recall budget](figures/fpr_recall_zoom.svg)
![Confusion](figures/confusion_matrix.svg)
![Threshold sensitivity](figures/threshold_fpr_recall.svg)

## Thresholds and family weaknesses

Scores >= selected threshold predict Attack. The exact full weighted ROC sweep selects maximum attack recall subject to FPR <=0.01; ties use lower FPR then higher threshold. Equal scores are indivisible. Reject-all uses nextafter(1,+infinity), a finite threshold above every probability, if necessary. Fixed 0.5 results are reported separately. Curves/threshold CSV are bounded display subsets of actual full-data points; numerical AUC/AP and selected threshold use all predictions.

{md(["Attack family", "Validation records", "Distinct groups", "False negatives", "Selected-model recall"], [(r["attack_family"], r["validation_records"], r["distinct_feature_groups"], r["false_negatives"], f"{r['recall']:.6f}") for r in selected["families_selected"]])}

Family metadata is validation-only and never a predictor. Small or repeated supports (notably SQL Injection) cannot establish independent family performance. Family recall may reveal severe weaknesses despite high aggregate recall/accuracy; preserve those failures, do not change categories or seeds. All-family results for both thresholds/models: [attack_family_recall.csv](attack_family_recall.csv).

![Family recall](figures/attack_family_recall.svg)

## CPU, timing and artifact

{md(["Model", "Fit seconds", "Process peak MiB at fit", "Validation score seconds", "Compact records/s", "Amortized ms/record", "Raw probe median / p95 ms", "Warnings"], [(n, f"{d['fit']['fit_seconds']:.3f}", f"{d['fit']['peak_rss_mib']:.1f}", f"{d['inference']['validation_score_seconds']:.3f}", f"{d['inference']['compact_records_per_second']:.1f}", f"{d['inference']['amortized_ms_per_compact_record']:.6f}", f"{d['inference']['raw_synthetic_single_record_latency_ms_median']:.4f} / {d['inference']['raw_synthetic_single_record_latency_ms_p95']:.4f}", d["fit"]["warnings"]) for n, d in run["models"].items()])}

Timing excludes shard disk IO for validation scoring, uses batches of {selected["inference"]["batch_size"]}, and counts actually scored **compact records**, not weighted row mass. Raw single-record latency uses 50 repeated synthetic software probes of a preloaded model, not a production latency benchmark. Process peak is cumulative Linux ru_maxrss, not isolated per-estimator memory. Total resources: `{run["metadata"]["resources"]}`. CPU only, models fit sequentially, no GPU or cross-validation. Saved artifact {run["metadata"]["artifact_bytes"]:,} bytes; SHA-256 `{run["metadata"]["artifact_sha256"]}`. Runtime/dependency/code differences can affect fits and timings.

Source dataset SHA-256 `{run["metadata"]["source_dataset_sha256"]}`; sealed partition manifest SHA-256 `{run["metadata"]["partition_manifest_sha256"]}`. Training timestamp `{run["metadata"]["training_timestamp_utc"]}`. Library versions `{run["metadata"]["versions"]}`. Metadata and checksum accompany trusted joblib; only deserialize trusted local files. Selected artifact includes frozen normalization, any fitted LR transforms, estimator, class mapping, threshold and provenance. Both candidate predictions were validation-only; selected scores were checked after serialization. Fresh Python process verification: `{run["fresh_process_verification"]}`. Synthetic inputs validate software only, never accuracy.

## Test boundary and limitations

{run["reserved_test_access"]} The shared manifest is hashed as opaque bytes; only train/validation entries and common contract/provenance are decoded. The dedicated loader rejects any partition other than train/validation. Train/validation input files were rehashed after use. No raw datasets opened, no processed files modified, no BoT/DNS fitting and no API/dashboard edits. Validation is not used for final fitting. Selected thresholds/model use validation, so reported results are selection-set estimates; the reserved test remains for a later explicitly authorized frozen evaluation. No test performance is reported here.

Group separation prevents identical retained inputs crossing the frozen split; it does not establish capture/session/host/time independence. Generation/service artifacts, label ambiguity, related flows and unobserved attacks remain risks. Obtain independent captures and exporter parity before deployment claims. Integration requires separate NF schema/model registry/frontend work; the existing three-field/four-class BoT endpoints cannot serve this artifact by swapping file paths.

Run `uv run python scripts/train_nf_cse.py info` to inspect the trusted selected artifact; `uv run python scripts/train_nf_cse.py verify` repeats synthetic software checks. Full training command/config and test commands are documented in the root README. Software test results for this run are appended after regression checks.
"""
    (stage / "training_report.md").write_text(report)
