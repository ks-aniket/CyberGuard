"""One fixed restricted-feature baseline; reads only the original training CSV."""

from __future__ import annotations

import hashlib
import json
import platform
import resource
import sqlite3
import tempfile
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

from cyberguard.features.network import (
    RAW_FEATURES,
    TARGETS,
    VERSION,
    RestrictedNetworkFeatures,
    canonical_keys,
    raw_from_key,
    validate_targets,
)
from cyberguard.features.preprocessing import make_network_pipeline
from cyberguard.training.evaluate import evaluate_predictions
from cyberguard.training.sampling import validation_group

DEFAULT_TRAIN = Path(
    "data/raw/bot_iot/train/UNSW_2018_IoT_Botnet_Final_10_best_Training.csv"
)


def sha256(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def build_training_index(source, db, *, chunk_size=50000, seed=20261115):
    """Compress multiplicity on disk, never resolve conflicting labels by voting."""
    db.execute(
        "CREATE TABLE examples(k TEXT,y TEXT,n INTEGER,partition TEXT,PRIMARY KEY(k,y)) WITHOUT ROWID"
    )
    counts, normalization = Counter(), Counter()
    normalizer = RestrictedNetworkFeatures()
    for chunk in pd.read_csv(
        source,
        usecols=[*RAW_FEATURES, "category"],
        dtype=str,
        keep_default_na=False,
        chunksize=chunk_size,
    ):
        labels, eligible = validate_targets(chunk.category)
        counts.update(labels)
        retained = chunk.loc[eligible]
        normalized = normalizer.fit_transform(retained)
        for col in ("protocol", "sport_status", "dport_status"):
            normalization.update(
                {
                    f"{col}={k}": int(v)
                    for k, v in normalized[col].value_counts().items()
                }
            )
        pairs = Counter(zip(canonical_keys(normalized), labels[eligible], strict=True))
        db.executemany(
            "INSERT INTO examples VALUES(?,?,?,?) ON CONFLICT(k,y) DO UPDATE SET n=n+excluded.n",
            [
                (k, y, n, "validation" if validation_group(k, seed) else "train")
                for (k, y), n in pairs.items()
            ],
        )
        db.commit()
        if sum(counts.values()) % (chunk_size * 10) == 0:
            print(f"Indexed {sum(counts.values()):,} training-file rows", flush=True)
    return counts, normalization


def train_baseline(root: Path, *, chunk_size=50000, seed=20261115):
    started = time.monotonic()
    source = root / DEFAULT_TRAIN  # intentionally no test-path parameter
    source_hash = sha256(source)
    output = root / "reports/model_evaluation"
    artifacts = root / "models/network"
    output.mkdir(parents=True, exist_ok=True)
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cyberguard_network_") as temp:
        db = sqlite3.connect(str(Path(temp) / "training.sqlite"))
        try:
            db.execute("PRAGMA cache_size=-65536")
            db.execute("PRAGMA temp_store=FILE")
            db.execute("PRAGMA journal_mode=OFF")
            counts, normalization = build_training_index(
                source, db, chunk_size=chunk_size, seed=seed
            )
            frame = pd.read_sql_query(
                "SELECT k,y,n,partition FROM examples ORDER BY k,y", db
            )
        finally:
            db.close()
    if not len(frame):
        raise ValueError("No eligible training rows")
    grouping = frame.groupby("k", sort=False)
    if grouping.partition.nunique().max() != 1:
        raise AssertionError("Feature-vector group crossed partitions")
    train_mask = frame.partition.eq("train").to_numpy()
    validation_mask = ~train_mask
    split_counts = {}
    for split in ["train", "validation"]:
        part = frame.loc[frame.partition.eq(split)]
        split_counts[split] = {
            label: int(part.loc[part.y.eq(label), "n"].sum()) for label in TARGETS
        }
        if any(n == 0 for n in split_counts[split].values()):
            raise ValueError(
                f"Fixed split lacks class support: {split_counts}. Do not silently resample seeds."
            )
    raw = pd.DataFrame([raw_from_key(key) for key in frame.k])
    checked = canonical_keys(RestrictedNetworkFeatures().fit_transform(raw))
    if checked != frame.k.tolist():
        raise AssertionError(
            "Canonical compact records do not reproduce the input representation"
        )
    pipeline = make_network_pipeline(seed)
    class_counts = split_counts["train"]
    total = sum(class_counts.values())
    class_weights = {
        label: total / (len(TARGETS) * n) for label, n in class_counts.items()
    }
    weights = (
        frame.loc[train_mask, "n"].to_numpy(dtype=float)
        * frame.loc[train_mask, "y"].map(class_weights).to_numpy()
    )
    print(
        f"Validated {sum(counts.values()):,} rows; fitting {int(train_mask.sum()):,} weighted feature-label records",
        flush=True,
    )
    fit_started = time.monotonic()
    pipeline.fit(
        raw.loc[train_mask],
        frame.loc[train_mask, "y"],
        classifier__sample_weight=weights,
    )
    fit_seconds = time.monotonic() - fit_started
    predicted = pipeline.predict(raw.loc[validation_mask])
    evaluation = evaluate_predictions(
        frame.loc[validation_mask, "y"], predicted, frame.loc[validation_mask, "n"]
    )
    group_totals = frame.groupby("k")["n"].transform("sum")
    group_evaluation = evaluate_predictions(
        frame.loc[validation_mask, "y"],
        predicted,
        frame.loc[validation_mask, "n"] / group_totals[validation_mask],
    )
    # Reference predictions are a fixed majority-class rule using training counts only.
    majority = max(class_counts, key=class_counts.get)
    reference = evaluate_predictions(
        frame.loc[validation_mask, "y"],
        np.repeat(majority, len(predicted)),
        frame.loc[validation_mask, "n"],
    )
    model_path = artifacts / "bot_iot_restricted_baseline.joblib"
    joblib.dump(pipeline, model_path, compress=3)
    loaded = joblib.load(model_path)
    if not np.array_equal(predicted, loaded.predict(raw.loc[validation_mask])):
        raise AssertionError("Saved model predictions differ from the fitted model")
    manifest = artifacts / "bot_iot_split_manifest.csv.gz"
    frame.to_csv(manifest, index=False, compression={"method": "gzip", "mtime": 0})
    if source_hash != sha256(source):
        raise RuntimeError("Raw training CSV changed")
    per_partition_groups = {
        s: int(frame.loc[frame.partition.eq(s), "k"].nunique())
        for s in ["train", "validation"]
    }
    collisions = frame.groupby("k").y.nunique()
    ambiguous = set(collisions[collisions > 1].index)
    unique_groups_per_class = {
        s: {
            label: int(
                frame.loc[frame.partition.eq(s) & frame.y.eq(label), "k"].nunique()
            )
            for label in TARGETS
        }
        for s in ["train", "validation"]
    }
    encoded_names = pipeline.named_steps["encode"].get_feature_names_out().tolist()
    model = pipeline.named_steps["classifier"]
    code_root = Path(__file__).resolve().parents[3]
    result = {
        "source": str(DEFAULT_TRAIN),
        "source_sha256": source_hash,
        "preprocessing_version": VERSION,
        "supplied_test_opened": False,
        "dns_model_trained": False,
        "raw_class_counts": dict(counts),
        "eligible_class_order": list(TARGETS),
        "theft_policy": "Exclude from the four-class development task; unsupported malicious category, never Normal. No Theft detection claim.",
        "normalization_counts": dict(normalization),
        "split_counts": split_counts,
        "split_unique_groups": per_partition_groups,
        "class_unique_groups": unique_groups_per_class,
        "split_method": "SHA256(seed + ':' + canonical retained feature vector), first 64 bits < 2^64//5 is validation; labels excluded from group key",
        "split_seed": seed,
        "vector_groups": int(frame.k.nunique()),
        "feature_label_records": len(frame),
        "duplicate_feature_label_excess": int(frame.n.sum() - len(frame)),
        "conflicting_feature_vector_groups": len(ambiguous),
        "rows_in_conflicting_groups": int(
            frame.loc[frame.k.isin(ambiguous), "n"].sum()
        ),
        "cross_partition_shared_groups": 0,
        "class_weights_train_only": class_weights,
        "classifier_parameters": model.get_params(),
        "encoded_feature_names": encoded_names,
        "feature_importances": dict(
            zip(encoded_names, map(float, model.feature_importances_), strict=True)
        ),
        "evaluation": evaluation,
        "equal_vector_weight_evaluation": group_evaluation,
        "majority_reference": reference,
        "classifier_depth": int(model.get_depth()),
        "classifier_leaves": int(model.get_n_leaves()),
        "fit_seconds": fit_seconds,
        "model_path": str(model_path.relative_to(root)),
        "model_sha256": sha256(model_path),
        "model_bytes": model_path.stat().st_size,
        "manifest_path": str(manifest.relative_to(root)),
        "manifest_sha256": sha256(manifest),
        "python": platform.python_version(),
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "code_sha256": {
            str(p.relative_to(code_root)): sha256(p)
            for p in [
                code_root / "src/cyberguard/features/network.py",
                code_root / "src/cyberguard/features/preprocessing.py",
                code_root / "src/cyberguard/training/sampling.py",
                code_root / "src/cyberguard/training/evaluate.py",
                code_root / "src/cyberguard/training/train_network.py",
            ]
        },
        "wall_seconds": time.monotonic() - started,
        "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
    }
    pd.DataFrame(evaluation["confusion_matrix"], index=TARGETS, columns=TARGETS).to_csv(
        output / "bot_iot_validation_confusion.csv", index_label="actual / predicted"
    )
    (output / "bot_iot_validation_metrics.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )
    return result
