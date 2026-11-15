"""Phase 7A: weighted, frozen-group NF-CSE feasibility study; never reads test shards."""

from __future__ import annotations

import gc
import hashlib
import html
import json
import platform
import resource
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import confusion_matrix
from threadpoolctl import threadpool_limits

from cyberguard.features import nf_cse as nf
from cyberguard.features.nf_cse_preparation import group_id, partition_for_key, sha256
from cyberguard.inference.model_registry import NF_MODES
from cyberguard.inference.nf_cse_model import NFLinearTransform
from cyberguard.training.train_nf_cse import deny_reserved, load_manifest

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATA = ROOT / "data/processed/nf_cse_cic_ids2018"
DEFAULT_OUTPUT = ROOT / "reports/model_evaluation/nf_cse_attack_family"
SEED = 20261115
PLAN = {
    "phase": "7A",
    "seed": SEED,
    "population": "Full sealed train and validation, original multiplicities; no test records",
    "taxonomy": "Benign plus every original Attack name in training; no merges",
    "feature_contract": nf.CONTRACT_VERSION,
    "fits": ["direct_linear", "family_linear", "direct_histogram", "family_histogram"],
    "linear": {
        "loss": "log_loss",
        "alpha": 0.0001,
        "epochs": 5,
        "batch_rows": 50000,
        "weighting": "original multiplicity; SGD order shuffled within compact shard batches, fixed seed",
    },
    "histogram": {
        "max_iter": 60,
        "max_leaf_nodes": 15,
        "learning_rate": 0.1,
        "l2_regularization": 1.0,
        "min_samples_leaf": 20,
        "early_stopping": False,
    },
    "class_balance": False,
    "abstention_score_cutoffs": [0.0, 0.5, 0.7, 0.9, 0.95],
    "selection": "No search or refit; report all four fits and both frozen binary modes. Validation reused exploratorily, no independent selection estimate.",
    "criteria": {
        "macro_f1_min": 0.80,
        "benign_fpr_max": 0.01,
        "attack_detection_recall_min": 0.90,
        "supported_family_recall_min": 0.70,
        "reliable_validation_groups_min": 100,
        "reliable_validation_records_min": 100,
        "peak_rss_mib_max": 12288,
        "total_wall_seconds_max": 1800,
        "all_family_go": "All original families must meet recall/support gates; rare families block an unqualified GO.",
        "conditional_go": "At least half the attack families meet recall and support gates; an end-to-end candidate meets detection/FPR gates and resource budget. Unsupported families must remain explicit/experimental.",
    },
}


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def encode_names(values, names):
    mapping = {v: i for i, v in enumerate(names)}
    if set(map(str, np.unique(values))) - set(mapping):
        raise ValueError("Validation contains a family absent from training")
    return np.asarray([mapping[str(v)] for v in values], dtype=np.uint8)


def load_data(root, manifest, split, names=None):
    """Allowlisted loader, verifies hashes, canonical grouping and lineage on every row."""
    if split not in {"train", "validation"}:
        raise ValueError(
            "Only train/validation are allowed; reserved test is prohibited"
        )
    root = Path(root).resolve()
    expected = manifest["plan"]["partitions"][split]
    size = expected["compact_records"]
    vectors = np.empty((size, 7), dtype=np.int64)
    encoded = np.empty((size, len(nf.MODEL_FEATURES)), dtype=np.float64)
    weight = np.empty(size, dtype=np.float64)
    groups = np.empty(size, dtype="S64")
    y = np.empty(size, dtype=np.uint8)
    discovered = [] if names is None else list(names)
    used = {}
    offset = 0
    for relative, item in sorted(manifest["artifacts"].items()):
        if not relative.startswith(split + "/") or not relative.endswith(".npz"):
            continue
        path = (root / relative).resolve()
        if path.parent != root / split or sha256(path) != item["sha256"]:
            raise ValueError("Unsafe or modified partition shard")
        used[relative] = item["sha256"]
        with np.load(path, allow_pickle=False) as shard:
            x, b, w, a, g = (
                shard[k]
                for k in ("features", "Label", "multiplicity", "Attack", "group_id")
            )
            if (
                x.dtype != np.int64
                or x.shape != (len(b), 7)
                or w.dtype != np.uint64
                or w.shape != b.shape
                or np.any(w == 0)
                or len(a) != len(b)
                or len(g) != len(b)
            ):
                raise ValueError("Invalid compact schema")
            nf.validate_labels(b.astype(str), a)
            keys = nf.canonical_keys(pd.DataFrame(x, columns=nf.RAW_FEATURES))
            if any(
                group_id(k).encode() != gi
                or partition_for_key(k, manifest["identity"]["seed"]) != split
                for k, gi in zip(keys, g, strict=True)
            ):
                raise ValueError("Frozen feature group/partition lineage mismatch")
            for family in sorted(map(str, np.unique(a))):
                if family not in discovered:
                    if names is not None:
                        raise ValueError("Validation contains unseen training family")
                    discovered.append(family)
            end = offset + len(b)
            if end > size:
                raise ValueError("Shard row count exceeds manifest")
            vectors[offset:end], weight[offset:end], groups[offset:end] = x, w, g
            y[offset:end] = encode_names(a, discovered)
            encoded[offset:end] = nf.model_features(
                pd.DataFrame(x, columns=nf.RAW_FEATURES)
            ).to_numpy()
            offset = end
    if names is None:
        ordered = ["Benign"] + sorted(set(discovered) - {"Benign"})
        remap = np.asarray([ordered.index(n) for n in discovered], dtype=np.uint8)
        y = remap[y]
        discovered = ordered
    benign = discovered.index("Benign")
    if (
        offset != size
        or int(weight.sum()) != expected["rows"]
        or int(weight[y == benign].sum()) != expected["binary_counts"]["0"]
        or int(weight[y != benign].sum()) != expected["binary_counts"]["1"]
    ):
        raise ValueError("Original multiplicity/support conservation failed")
    print(
        f"Verified {split}: {offset:,} compact / {int(weight.sum()):,} original records",
        flush=True,
    )
    return {
        "vectors": vectors,
        "X": encoded,
        "y": y,
        "w": weight,
        "groups": groups,
        "names": discovered,
        "used": used,
    }


def verify_disjoint(train, validation):
    # IDs were recomputed from exact canonical vectors during load; compare all unique IDs.
    overlap = np.intersect1d(train["groups"], validation["groups"])
    if len(overlap):
        raise ValueError("Feature groups overlap across training and validation")
    return {
        "train_groups": len(np.unique(train["groups"])),
        "validation_groups": len(np.unique(validation["groups"])),
        "overlap": 0,
        "proof": "Every canonical key rehashed and checked against frozen partition rule, plus exact group-ID intersection",
    }


def collision_analysis(data):
    """Exact seven-int vectors, weighted plurality ceiling; no relabeling for fitting."""
    x, y, w, names = (data[k] for k in ("vectors", "y", "w", "names"))
    order = np.lexsort(x.T[::-1])
    xx, yy, ww = x[order], y[order], w[order]
    starts = np.r_[0, np.flatnonzero(np.any(xx[1:] != xx[:-1], axis=1)) + 1]
    sizes = np.diff(np.r_[starts, len(y)])
    lo, hi = np.minimum.reduceat(yy, starts), np.maximum.reduceat(yy, starts)
    ambiguous = lo != hi
    group_codes = np.repeat(np.arange(len(starts)), sizes)
    ambiguous_ids = np.flatnonzero(ambiguous)
    selected = ambiguous[group_codes]
    mapping = np.full(len(starts), -1, dtype=np.int64)
    mapping[ambiguous_ids] = np.arange(len(ambiguous_ids))
    counts = np.bincount(
        mapping[group_codes[selected]] * len(names) + yy[selected],
        weights=ww[selected],
        minlength=len(ambiguous_ids) * len(names),
    ).reshape(-1, len(names))
    total = counts.sum(axis=1)
    majority = counts.max(axis=1) if len(counts) else np.array([])
    all_mass = float(w.sum())
    attack_counts = counts[:, 1:]
    attack_ambiguous = (attack_counts > 0).sum(axis=1) > 1
    binary_ambiguous = (counts[:, 0] > 0) & (attack_counts.sum(axis=1) > 0)
    minority = total - majority
    attack_majority = attack_counts.max(axis=1) if len(counts) else np.array([])
    attack_total = attack_counts.sum(axis=1)
    inventory = []
    pairs = []
    for c, name in enumerate(names):
        mask = y == c
        group_present = counts[:, c] > 0
        same_group_mass = total[group_present].sum()
        # Unique vectors for this family equal distinct groups; count directly, including unambiguous.
        unique = len(np.unique(data["groups"][mask]))
        inventory.append(
            {
                "family": name,
                "weighted_records": int(w[mask].sum()),
                "compact_rows": int(mask.sum()),
                "unique_feature_vectors": unique,
                "distinct_feature_groups": unique,
                "percent_of_attack_records": None
                if c == 0
                else float(100 * w[mask].sum() / w[y != 0].sum()),
                "ambiguous_groups_any_label": int(group_present.sum()),
                "records_in_ambiguous_groups": int(counts[group_present, c].sum()),
                "own_label_share_in_ambiguous_groups": None
                if same_group_mass == 0
                else float(counts[group_present, c].sum() / same_group_mass),
                "weighted_majority_label_proportion_in_ambiguous_groups": None
                if same_group_mass == 0
                else float(majority[group_present].sum() / same_group_mass),
            }
        )
        for other in range(c + 1, len(names)):
            both = group_present & (counts[:, other] > 0)
            if np.any(both):
                pairs.append(
                    {
                        "family_a": name,
                        "family_b": names[other],
                        "shared_vectors": int(both.sum()),
                        "a_records": int(counts[both, c].sum()),
                        "b_records": int(counts[both, other].sum()),
                    }
                )
    summary = {
        "original_records": int(all_mass),
        "compact_rows": len(y),
        "unique_vectors": len(starts),
        "ambiguous_groups_any_label": int(ambiguous.sum()),
        "records_in_ambiguous_groups": int(total.sum()),
        "minimum_deterministic_errors": int(minority.sum()),
        "empirical_multiclass_collision_ceiling": float(1 - minority.sum() / all_mass),
        "attack_family_conflicting_groups": int(attack_ambiguous.sum()),
        "benign_attack_conflicting_groups": int(binary_ambiguous.sum()),
        "benign_attack_records_in_conflicts": int(total[binary_ambiguous].sum()),
        "attack_only_minimum_errors": int((attack_total - attack_majority).sum()),
        "attack_only_collision_ceiling": float(
            1 - (attack_total - attack_majority).sum() / w[y != 0].sum()
        ),
        "weighted_majority_share_ambiguous": None
        if not len(total)
        else float(majority.sum() / total.sum()),
        "scope": "Observed population lookup ceiling for identical seven-feature vectors, not a universal generalization bound",
    }
    return inventory, pairs, summary


def metrics(y, pred, weight, names):
    cm = confusion_matrix(
        y, pred, labels=np.arange(len(names)), sample_weight=weight
    ).astype(float)
    support = cm.sum(axis=1)
    correct = cm.diagonal()
    recall = np.divide(correct, support, out=np.zeros_like(correct), where=support != 0)
    precision = np.divide(
        correct, cm.sum(axis=0), out=np.zeros_like(correct), where=cm.sum(axis=0) != 0
    )
    f1 = np.divide(
        2 * recall * precision,
        recall + precision,
        out=np.zeros_like(correct),
        where=recall + precision != 0,
    )
    per_class = [
        {
            "family": n,
            "support": int(support[i]),
            "correct_final_family": int(correct[i]),
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "attack_detection_recall": None
            if i == 0 or support[i] == 0
            else float(1 - cm[i, 0] / support[i]),
            "family_identification_recall": None if i == 0 else float(recall[i]),
        }
        for i, n in enumerate(names)
    ]
    return {
        "names": list(names),
        "confusion_matrix": cm.astype(int).tolist(),
        "weighted_records": int(support.sum()),
        "accuracy": float(correct.sum() / support.sum()),
        "macro_f1": float(f1.mean()),
        "weighted_f1": float(np.dot(f1, support) / support.sum()),
        "balanced_accuracy": float(recall[support > 0].mean()),
        "benign_fpr": None if support[0] == 0 else float(1 - cm[0, 0] / support[0]),
        "attack_detection_recall": None
        if support[1:].sum() == 0
        else float(1 - cm[1:, 0].sum() / support[1:].sum()),
        "per_class": per_class,
        "undefined_precision_policy": "Zero when no predictions; all taxonomy labels included in macro-F1",
    }


def route(scores, family_pred, threshold):
    if len(scores) != len(family_pred) or not 0 <= threshold <= 1:
        raise ValueError("Invalid hierarchical routing inputs")
    return np.where(np.asarray(scores) >= threshold, family_pred, 0)


def abstention(y, pred, score, weight, names, *, eligible=None):
    """Abstention on raw maximum class score; never described as calibrated confidence."""
    eligible = np.ones(len(y), dtype=bool) if eligible is None else np.asarray(eligible)
    output = []
    for cutoff in PLAN["abstention_score_cutoffs"]:
        accept = (~eligible) | (score >= cutoff)
        accepted = float(weight[accept].sum())
        per_family = {}
        for i, name in enumerate(names):
            mask = y == i
            support = float(weight[mask].sum())
            per_family[name] = {
                "support": int(support),
                "rejected": int(weight[mask & ~accept].sum()),
                "rejection_rate": None
                if support == 0
                else float(weight[mask & ~accept].sum() / support),
            }
        accepted_metrics = (
            metrics(y[accept], pred[accept], weight[accept], names)
            if accepted
            else None
        )
        output.append(
            {
                "raw_max_score_cutoff": cutoff,
                "coverage": accepted / float(weight.sum()),
                "selective_accuracy": None
                if not accepted
                else accepted_metrics["accuracy"],
                "accepted_error_rate": None
                if not accepted
                else 1 - accepted_metrics["accuracy"],
                "selective_macro_f1_fixed_taxonomy": None
                if not accepted
                else accepted_metrics["macro_f1"],
                "accepted_families_with_support": sorted(
                    {names[i] for i in np.unique(y[accept])}
                ),
                "per_family": per_family,
            }
        )
    return output


def fit_candidate(kind, data, attack_only, threads):
    keep = data["y"] != 0 if attack_only else np.ones(len(data["y"]), dtype=bool)
    x, y, w = data["X"][keep], data["y"][keep], data["w"][keep]
    start = time.perf_counter()
    transform = None
    with (
        threadpool_limits(limits=threads),
        warnings.catch_warnings(record=True) as caught,
    ):
        warnings.simplefilter("always")
        if kind == "linear":
            transform = NFLinearTransform().fit(x, sample_weight=w)
            estimator = SGDClassifier(
                loss="log_loss",
                alpha=PLAN["linear"]["alpha"],
                random_state=SEED,
                average=True,
                shuffle=False,
            )
            rng = np.random.default_rng(SEED)
            classes = np.unique(y)
            batch = PLAN["linear"]["batch_rows"]
            for _ in range(PLAN["linear"]["epochs"]):
                for start_row in range(0, len(y), batch):
                    ix = np.arange(start_row, min(start_row + batch, len(y)))
                    rng.shuffle(ix)
                    estimator.partial_fit(
                        transform.transform(x[ix]),
                        y[ix],
                        classes=classes,
                        sample_weight=w[ix],
                    )
        else:
            categorical = np.zeros(len(nf.MODEL_FEATURES), dtype=bool)
            categorical[[0, 7, 8, 9, 10, 11, 12]] = True
            estimator = HistGradientBoostingClassifier(
                categorical_features=categorical, random_state=SEED, **PLAN["histogram"]
            )
            estimator.fit(x, y, sample_weight=w)
    return (estimator, transform), {
        "fit_seconds": time.perf_counter() - start,
        "peak_process_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        / 1024,
        "training_compact_rows": len(y),
        "training_original_weight": int(w.sum()),
        "warnings": [str(w.message) for w in caught],
    }


def predict_candidate(model, x, threads=4):
    estimator, transform = model
    pred = np.empty(len(x), dtype=np.uint8)
    score = np.empty(len(x), dtype=float)
    start = time.perf_counter()
    with threadpool_limits(limits=threads):
        for offset in range(0, len(x), 50000):
            chunk = x[offset : offset + 50000]
            probability = estimator.predict_proba(
                transform.transform(chunk) if transform is not None else chunk
            )
            if not np.isfinite(probability).all():
                raise ValueError("Nonfinite research scores")
            ix = probability.argmax(axis=1)
            pred[offset : offset + len(chunk)] = estimator.classes_[ix]
            score[offset : offset + len(chunk)] = probability[np.arange(len(chunk)), ix]
    elapsed = time.perf_counter() - start
    return (
        pred,
        score,
        {
            "predict_seconds": elapsed,
            "compact_rows_per_second": len(x) / elapsed,
            "scope": "All compact validation rows including encoding transform, excludes data loading; does not expand duplicates",
        },
    )


def discrete_table(data, columns):
    labels = data["y"]
    values = data["vectors"][:, columns]
    keys, inverse = np.unique(values, axis=0, return_inverse=True)
    counts = np.bincount(
        inverse * len(data["names"]) + labels,
        weights=data["w"],
        minlength=len(keys) * len(data["names"]),
    ).reshape(-1, len(data["names"]))
    return keys, counts


def weighted_quantiles(values, weights):
    ix = np.argsort(values, kind="stable")
    cumulative = np.cumsum(weights[ix])
    return [
        float(values[ix[np.searchsorted(cumulative, q * cumulative[-1], side="left")]])
        for q in (0.5, 0.9, 0.99)
    ]


def feature_analysis(data, split, directory):
    names, x, y, w = (data[k] for k in ("names", "vectors", "y", "w"))
    rows, tv = [], []
    for label, columns in [
        ("protocol", [0]),
        ("source_port", [1]),
        ("destination_port", [2]),
        ("protocol_port_pair", [0, 1, 2]),
    ]:
        keys, counts = discrete_table(data, columns)
        totals = counts.sum(axis=0)
        for i, family in enumerate(names):
            for index in np.argsort(-counts[:, i], kind="stable")[:10]:
                if counts[index, i] > 0:
                    rows.append(
                        {
                            "split": split,
                            "family": family,
                            "distribution": label,
                            "key": json.dumps(keys[index].tolist()),
                            "weight": int(counts[index, i]),
                            "within_family_fraction": float(
                                counts[index, i] / totals[i]
                            ),
                        }
                    )
            for j in range(i + 1, len(names)):
                tv.append(
                    {
                        "split": split,
                        "family_a": family,
                        "family_b": names[j],
                        "distribution": label,
                        "total_variation": float(
                            np.abs(
                                counts[:, i] / totals[i] - counts[:, j] / totals[j]
                            ).sum()
                            / 2
                        ),
                    }
                )
    summaries, conditional, relationships = [], [], []
    for i, family in enumerate(names):
        mask = y == i
        xx, ww = x[mask], w[mask]
        for col in range(3, 7):
            vals = xx[:, col]
            valid = vals >= 0
            q = weighted_quantiles(vals[valid], ww[valid])
            summaries.append(
                {
                    "split": split,
                    "family": family,
                    "feature": nf.RAW_FEATURES[col],
                    "mean": float(np.average(vals[valid], weights=ww[valid])),
                    "median": q[0],
                    "p90": q[1],
                    "p99": q[2],
                    "invalid_weight": int(ww[~valid].sum()),
                }
            )
        logs = np.log1p(np.maximum(xx[:, 3:], 0))
        means = np.average(logs, axis=0, weights=ww)
        centered = logs - means
        cov = (centered * ww[:, None]).T @ centered / ww.sum()
        for a, b in [(0, 1), (2, 3), (0, 2), (1, 3)]:
            denom = np.sqrt(cov[a, a] * cov[b, b])
            relationships.append(
                {
                    "split": split,
                    "family": family,
                    "feature_a": nf.COUNTERS[a],
                    "feature_b": nf.COUNTERS[b],
                    "weighted_log1p_pearson": None
                    if denom == 0
                    else float(cov[a, b] / denom),
                    "undefined_status_policy": "Negative statuses excluded from scalar quantiles; zero-filled with separate status in model. Correlations descriptive after zero fill.",
                }
            )
        for label, column in [("protocol", 0), ("destination_port", 2)]:
            vals, mass = np.unique(xx[:, column], return_inverse=True)
            mass = np.bincount(mass, weights=ww)
            for value in vals[np.argsort(-mass, kind="stable")[:3]]:
                selected = xx[:, column] == value
                record = {
                    "split": split,
                    "family": family,
                    "condition": label,
                    "value": int(value),
                    "weighted_records": int(ww[selected].sum()),
                }
                for col in range(3, 7):
                    record[nf.RAW_FEATURES[col] + "_log1p_mean"] = float(
                        np.average(logs[selected, col - 3], weights=ww[selected])
                    )
                conditional.append(record)
    pd.DataFrame(rows).to_csv(
        directory / f"{split}_discrete_distributions.csv", index=False
    )
    pd.DataFrame(summaries).to_csv(
        directory / f"{split}_counter_distributions.csv", index=False
    )
    pd.DataFrame(relationships).to_csv(
        directory / f"{split}_relationships.csv", index=False
    )
    pd.DataFrame(conditional).to_csv(
        directory / f"{split}_conditioned_distributions.csv", index=False
    )
    return tv, summaries


def svg_heatmap(path, title, matrix, rows, columns, *, logarithmic=False):
    matrix = np.asarray(matrix, dtype=float)
    width, height = 1120, 100 + 32 * len(rows) + 190
    left, top, cell = 310, 60, min(95, 700 / max(len(columns), 1))
    values = np.log1p(matrix) if logarithmic else matrix
    maximum = max(float(values.max()), 1e-12)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}"><rect width="100%" height="100%" fill="#0b1220"/><g fill="#e5edfa" font-family="sans-serif" font-size="11">',
        f'<text x="20" y="25" font-size="17">{html.escape(title)}</text>',
    ]
    for r, name in enumerate(rows):
        parts.append(f'<text x="5" y="{top + 32 * r + 20}">{html.escape(name)}</text>')
        for c in range(len(columns)):
            v = values[r, c] / maximum
            color = f"rgb({int(20 + 40 * v)},{int(35 + 180 * v)},{int(60 + 175 * v)})"
            value = matrix[r, c]
            display = (
                f"{value / 1e6:.2f}M"
                if value >= 1e6
                else f"{value / 1000:.1f}k"
                if value >= 1000
                else f"{value:.0f}"
                if logarithmic
                else f"{value:.2f}"
            )
            parts.append(
                f'<rect x="{left + cell * c}" y="{top + 32 * r}" width="{cell - 1}" height="31" fill="{color}"/><text x="{left + cell * c + 2}" y="{top + 32 * r + 19}" fill="#fff">{display}</text>'
            )
    for c, name in enumerate(columns):
        parts.append(
            f'<text transform="translate({left + cell * c + 8},{top + 32 * len(rows) + 8}) rotate(55)">{html.escape(name)}</text>'
        )
    parts.append("</g></svg>")
    path.write_text("".join(parts))


def verify_binary(path, manifest_digest):
    metadata = json.loads(path.with_suffix(".metadata.json").read_text())
    if (
        sha256(path) != metadata["artifact_sha256"]
        or metadata["partition_manifest_sha256"] != manifest_digest
    ):
        raise ValueError("Frozen binary artifact/partition checksum mismatch")
    if (
        metadata["selected_threshold"] != NF_MODES["high_sensitivity"]
        or NF_MODES["standard"] != 0.5
    ):
        raise ValueError("Verified binary mode thresholds disagree")
    if metadata["feature_contract_version"] != nf.CONTRACT_VERSION or metadata[
        "encoded_feature_order"
    ] != list(nf.MODEL_FEATURES):
        raise ValueError("Binary contract mismatch")
    return joblib.load(path), metadata


def software_identity():
    return {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "sklearn": sklearn.__version__,
        "joblib": joblib.__version__,
        "implementation_sha256": {
            "attack_family.py": sha256(Path(__file__)),
            "study_attack_families.py": sha256(
                ROOT / "scripts/study_attack_families.py"
            ),
            "nf_cse.py": sha256(Path(nf.__file__)),
        },
    }


def run(root=DEFAULT_DATA, output=DEFAULT_OUTPUT, *, threads=4):
    root, output = Path(root).resolve(), Path(output).resolve()
    if (
        output.is_relative_to(ROOT / "data")
        or output.is_relative_to(ROOT / "models")
        or output.is_relative_to(root)
    ):
        raise ValueError("Research output cannot overwrite datasets or models")
    if not 1 <= threads <= 8:
        raise ValueError("Threads must be 1..8")
    output.mkdir(parents=True, exist_ok=False)
    (output / "figures").mkdir()
    # Persist criteria and budgets before reading any candidate validation results.
    dump(output / "experiment_plan.json", PLAN)
    start = time.perf_counter()
    with deny_reserved(root) as guard, threadpool_limits(limits=threads):
        manifest, digest = load_manifest(root)
        binary_path = ROOT / "models/network/nf_cse_binary_completed_flow.joblib"
        binary_hash = sha256(binary_path)
        bot_path = ROOT / "models/network/bot_iot_restricted_baseline.joblib"
        bot_hash = sha256(bot_path)
        binary, metadata = verify_binary(binary_path, digest)
        train = load_data(root, manifest, "train")
        validation = load_data(root, manifest, "validation", train["names"])
        names = train["names"]
        integrity = verify_disjoint(train, validation)
        dump(output / "class_mapping.json", {str(i): n for i, n in enumerate(names)})
        collisions, inventory, overlap, distribution, counters = {}, [], [], [], []
        for split, data in [("train", train), ("validation", validation)]:
            inv, pairs, collisions[split] = collision_analysis(data)
            inventory.extend({"split": split, **v} for v in inv)
            overlap.extend({"split": split, **v} for v in pairs)
            tv, stats = feature_analysis(data, split, output)
            distribution.extend(tv)
            counters.extend(stats)
            print(
                f"Analyzed {split} inventory, exact collisions and distributions",
                flush=True,
            )
        pd.DataFrame(inventory).to_csv(output / "class_inventory.csv", index=False)
        pd.DataFrame(overlap).to_csv(output / "feature_overlap.csv", index=False)
        pd.DataFrame(distribution).to_csv(
            output / "distribution_overlap.csv", index=False
        )
        dump(output / "collision_analysis.json", collisions)
        # No canonical vectors needed by estimators; release them before training.
        del train["vectors"], validation["vectors"]
        gc.collect()
        score_start = time.perf_counter()
        binary_scores = np.concatenate(
            [
                binary.score_encoded(validation["X"][i : i + 50000])
                for i in range(0, len(validation["y"]), 50000)
            ]
        )
        binary_seconds = time.perf_counter() - score_start
        direct, hierarchy, conditional, abstain, costs, rare = {}, {}, {}, {}, {}, []
        attack = validation["y"] != 0
        prediction_hashes = {}
        for kind in ("linear", "histogram"):
            for family_only in (False, True):
                key = ("family_" if family_only else "direct_") + kind
                print(f"Fitting {key} on frozen training partition", flush=True)
                model, fit_cost = fit_candidate(kind, train, family_only, threads)
                pred, score, prediction_cost = predict_candidate(
                    model, validation["X"], threads
                )
                costs[key] = {**fit_cost, **prediction_cost}
                prediction_hashes[key] = hashlib.sha256(
                    pred.tobytes() + score.tobytes()
                ).hexdigest()
                if not family_only:
                    result = metrics(validation["y"], pred, validation["w"], names)
                    direct[kind] = result
                    abstain[key] = abstention(
                        validation["y"], pred, score, validation["w"], names
                    )
                    matrices = [(key, result)]
                else:
                    # Attack-only taxonomy has no Benign, so compute without binary-derived metrics.
                    conditional[kind] = metrics(
                        validation["y"][attack] - 1,
                        pred[attack] - 1,
                        validation["w"][attack],
                        names[1:],
                    )
                    for field in ("benign_fpr", "attack_detection_recall"):
                        conditional[kind].pop(field)
                    for row in conditional[kind]["per_class"]:
                        row.pop("attack_detection_recall")
                        row["family_identification_recall"] = row["recall"]
                    hierarchy[kind] = {}
                    matrices = []
                    for mode, threshold in NF_MODES.items():
                        final = route(binary_scores, pred, threshold)
                        result = metrics(validation["y"], final, validation["w"], names)
                        result["binary_threshold"] = threshold
                        hierarchy[kind][mode] = result
                        abstain[key + "_" + mode] = abstention(
                            validation["y"],
                            final,
                            score,
                            validation["w"],
                            names,
                            eligible=binary_scores >= threshold,
                        )
                        matrices.append((key + "_" + mode, result))
                        for i, name in enumerate(names[1:], start=1):
                            mask = validation["y"] == i
                            detected = mask & (binary_scores >= threshold)
                            total = float(validation["w"][mask].sum())
                            correct = mask & (pred == i)
                            rare.append(
                                {
                                    "candidate": kind,
                                    "mode": mode,
                                    "family": name,
                                    "validation_records": int(total),
                                    "validation_groups": len(
                                        np.unique(validation["groups"][mask])
                                    ),
                                    "binary_detected": int(
                                        validation["w"][detected].sum()
                                    ),
                                    "conditional_family_correct": int(
                                        validation["w"][correct].sum()
                                    ),
                                    "end_to_end_family_correct": int(
                                        validation["w"][correct & detected].sum()
                                    ),
                                    "correct_among_detected": None
                                    if not np.any(detected)
                                    else float(
                                        validation["w"][correct & detected].sum()
                                        / validation["w"][detected].sum()
                                    ),
                                }
                            )
                for title, result in matrices:
                    svg_heatmap(
                        output / "figures" / (title + "_confusion.svg"),
                        title
                        + " weighted validation confusion (true rows, predicted columns; log1p color)",
                        result["confusion_matrix"],
                        names,
                        names,
                        logarithmic=True,
                    )
                del model
                gc.collect()
        dump(output / "direct_multiclass_metrics.json", direct)
        dump(output / "hierarchical_metrics.json", hierarchy)
        dump(output / "conditional_family_metrics.json", conditional)
        dump(
            output / "abstention_analysis.json",
            {
                "score_semantics": "Uncalibrated maximum class score; exploratory cutoffs, no selected deployment threshold. Hierarchical abstention rejects routed attacks only; binary Benign stays Benign.",
                "experiments": abstain,
            },
        )
        pd.DataFrame(rare).to_csv(
            output / "family_error_decomposition.csv", index=False
        )
        elapsed = time.perf_counter() - start
        resources = {
            "candidates": costs,
            "binary_validation_predict_seconds": binary_seconds,
            "wall_seconds_before_report": elapsed,
            "peak_process_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            / 1024,
            "threads": threads,
            "memory_scope": "Cumulative process high-water RSS including analysis/training; not incremental per-model memory",
        }
        dump(output / "resources.json", resources)
        for relative, expected in {**train["used"], **validation["used"]}.items():
            if sha256(root / relative) != expected:
                raise ValueError("Dataset changed during research")
        if sha256(binary_path) != binary_hash or sha256(bot_path) != bot_hash:
            raise ValueError("Production classifier changed")
        integrity.update(
            partition_manifest_sha256=digest,
            binary_sha256=binary_hash,
            bot_sha256=bot_hash,
            binary_metadata=metadata,
            operating_modes=NF_MODES,
            opened_processed_files=sorted(guard["opened"]),
            prediction_sha256=prediction_hashes,
            train_used_shards=train["used"],
            validation_used_shards=validation["used"],
            taxonomy=names,
            reserved_test_opened=False,
        )
        dump(output / "integrity.json", integrity)
        build_report(
            output,
            inventory,
            distribution,
            counters,
            collisions,
            direct,
            hierarchy,
            conditional,
            rare,
            abstain,
            resources,
        )
        artifact_hashes = {
            p.relative_to(output).as_posix(): sha256(p)
            for p in sorted(output.rglob("*"))
            if p.is_file()
        }
        dump(
            output / "artifact_manifest.json",
            {
                "status": "complete",
                "artifacts": artifact_hashes,
                "reproducibility": "Deterministic arrays/scores/config/metrics; wall times/RSS vary. No experimental estimator registered or serialized.",
                "software": software_identity(),
            },
        )
        print(
            f"Study complete: {output}; peak {resources['peak_process_rss_mib']:.1f} MiB",
            flush=True,
        )
    return resources


def table(headers, rows):
    return (
        "| "
        + " | ".join(headers)
        + " |\n| "
        + " | ".join("---" for _ in headers)
        + " |\n"
        + "\n".join("| " + " | ".join(map(str, row)) + " |" for row in rows)
    )


def build_report(
    out,
    inventory,
    overlap,
    counters,
    collisions,
    direct,
    hierarchy,
    conditional,
    rare,
    abstain,
    resources,
):
    names = direct["histogram"]["names"]
    train = {v["family"]: v for v in inventory if v["split"] == "train"}
    val = {v["family"]: v for v in inventory if v["split"] == "validation"}
    results = {"direct_" + k: v for k, v in direct.items()}
    results.update(
        {
            "hierarchical_" + k + "_" + mode: v
            for k, modes in hierarchy.items()
            for mode, v in modes.items()
        }
    )
    criteria = PLAN["criteria"]
    assessments = {}
    for key, result in results.items():
        reliable = [
            r
            for r in result["per_class"][1:]
            if r["recall"] >= criteria["supported_family_recall_min"]
            and val[r["family"]]["weighted_records"]
            >= criteria["reliable_validation_records_min"]
            and val[r["family"]]["distinct_feature_groups"]
            >= criteria["reliable_validation_groups_min"]
        ]
        aggregate = (
            result["benign_fpr"] <= criteria["benign_fpr_max"]
            and result["attack_detection_recall"]
            >= criteria["attack_detection_recall_min"]
        )
        assessments[key] = {
            "families_meeting_support_and_recall": [r["family"] for r in reliable],
            "aggregate_detection_gates": aggregate,
            "all_family_go": aggregate
            and result["macro_f1"] >= criteria["macro_f1_min"]
            and len(reliable) == len(names) - 1,
            "conditional_go": aggregate and len(reliable) >= (len(names) - 1) / 2,
        }
    resource_ok = (
        resources["peak_process_rss_mib"] <= criteria["peak_rss_mib_max"]
        and resources["wall_seconds_before_report"]
        <= criteria["total_wall_seconds_max"]
    )
    if resource_ok and any(v["all_family_go"] for v in assessments.values()):
        # Prefer no additional gate when both meet all predeclared criteria; never deploy here.
        decision = (
            "GO — Direct multiclass"
            if any(
                assessments[k]["all_family_go"]
                for k in assessments
                if k.startswith("direct")
            )
            else "GO — Hierarchical"
        )
    elif resource_ok and any(v["conditional_go"] for v in assessments.values()):
        decision = "CONDITIONAL GO"
    else:
        decision = "NO-GO"
    dump(
        out / "decision.json",
        {
            "recommendation": decision,
            "resource_gates_passed": resource_ok,
            "criteria": criteria,
            "assessments": assessments,
        },
    )
    inv_rows = [
        [
            n,
            train[n]["weighted_records"],
            val[n]["weighted_records"],
            f"{train[n]['percent_of_attack_records']:.4f}" if n != "Benign" else "n/a",
            f"{val[n]['percent_of_attack_records']:.4f}" if n != "Benign" else "n/a",
            train[n]["compact_rows"],
            val[n]["compact_rows"],
            train[n]["unique_feature_vectors"],
            val[n]["unique_feature_vectors"],
        ]
        for n in names
    ]
    compare = [
        [
            key,
            f"{v['macro_f1']:.4f}",
            f"{v['weighted_f1']:.4f}",
            f"{v['balanced_accuracy']:.4f}",
            f"{v['benign_fpr']:.4%}",
            f"{v['attack_detection_recall']:.4%}",
            len(assessments[key]["families_meeting_support_and_recall"]),
        ]
        for key, v in results.items()
    ]
    pd.DataFrame(
        [
            {
                "candidate": k,
                **{
                    f: v[f]
                    for f in (
                        "macro_f1",
                        "weighted_f1",
                        "balanced_accuracy",
                        "benign_fpr",
                        "attack_detection_recall",
                    )
                },
            }
            for k, v in results.items()
        ]
    ).to_csv(out / "comparison.csv", index=False)
    per_rows = []
    for key, result in results.items():
        per_rows.extend({"candidate": key, **row} for row in result["per_class"])
    pd.DataFrame(per_rows).to_csv(out / "per_family_metrics.csv", index=False)
    # Fully numerical, deterministic figures; no external renderer required.
    svg_heatmap(
        out / "figures/counter_medians.svg",
        "Weighted counter medians (log1p color; displayed original units)",
        [
            [
                next(
                    r["median"]
                    for r in counters
                    if r["split"] == "train" and r["family"] == n and r["feature"] == f
                )
                for f in nf.COUNTERS
            ]
            for n in names
        ],
        names,
        list(nf.COUNTERS),
        logarithmic=True,
    )
    svg_heatmap(
        out / "figures/family_recall.svg",
        "End-to-end family identification recall (validation)",
        [
            [
                next(r["recall"] for r in v["per_class"] if r["family"] == n)
                for v in results.values()
            ]
            for n in names
        ],
        names,
        list(results),
    )
    sample_overlap = sorted(
        [
            v
            for v in overlap
            if v["split"] == "train" and v["distribution"] == "protocol_port_pair"
        ],
        key=lambda v: v["total_variation"],
    )[:10]
    feature_text = table(
        ["Family A", "Family B", "Protocol/source/destination joint TV"],
        [
            [r["family_a"], r["family_b"], f"{r['total_variation']:.6f}"]
            for r in sample_overlap
        ],
    )
    collision_text = table(
        [
            "Split",
            "Unique vectors",
            "Ambiguous groups",
            "Min deterministic multiclass errors",
            "Multiclass ceiling",
            "Attack-family conflicts",
            "Benign/attack conflicts",
            "Attack-only ceiling",
        ],
        [
            [
                split,
                v["unique_vectors"],
                v["ambiguous_groups_any_label"],
                v["minimum_deterministic_errors"],
                f"{v['empirical_multiclass_collision_ceiling']:.6%}",
                v["attack_family_conflicting_groups"],
                v["benign_attack_conflicting_groups"],
                f"{v['attack_only_collision_ceiling']:.6%}",
            ]
            for split, v in collisions.items()
        ],
    )
    conditional_text = table(
        [
            "Family classifier",
            "Attack-only macro-F1",
            "Weighted-F1",
            "Balanced accuracy",
        ],
        [
            [
                k,
                f"{v['macro_f1']:.4f}",
                f"{v['weighted_f1']:.4f}",
                f"{v['balanced_accuracy']:.4f}",
            ]
            for k, v in conditional.items()
        ],
    )
    family_text = table(
        [
            "True family",
            "Direct linear recall",
            "Direct histogram precision / recall / F1",
            "Conditional histogram recall",
            "Hier standard recall",
            "Hier sensitive recall",
        ],
        [
            [
                n,
                f"{direct['linear']['per_class'][i]['recall']:.4f}",
                " / ".join(
                    f"{direct['histogram']['per_class'][i][f]:.4f}"
                    for f in ("precision", "recall", "f1")
                ),
                "n/a"
                if i == 0
                else f"{conditional['histogram']['per_class'][i - 1]['recall']:.4f}",
                f"{hierarchy['histogram']['standard']['per_class'][i]['recall']:.4f}",
                f"{hierarchy['histogram']['high_sensitivity']['per_class'][i]['recall']:.4f}",
            ]
            for i, n in enumerate(names)
        ],
    )
    rare_text = table(
        [
            "Family",
            "Mode",
            "Support / groups",
            "Detected by frozen binary",
            "Correct family without binary gate",
            "Correct end-to-end",
        ],
        [
            [
                r["family"],
                r["mode"],
                f"{r['validation_records']} / {r['validation_groups']}",
                r["binary_detected"],
                r["conditional_family_correct"],
                r["end_to_end_family_correct"],
            ]
            for r in rare
            if r["candidate"] == "histogram"
            and (
                r["family"]
                in {
                    "Infilteration",
                    "SQL Injection",
                    "Brute Force -Web",
                    "Brute Force -XSS",
                    "DDOS attack-HOIC",
                }
            )
        ],
    )
    abstain_text = table(
        [
            "Experiment",
            "Raw cutoff",
            "Coverage",
            "Selective accuracy",
            "Selective macro-F1",
            "Accepted error",
        ],
        [
            [
                k,
                r["raw_max_score_cutoff"],
                f"{r['coverage']:.4%}",
                f"{r['selective_accuracy']:.4f}"
                if r["selective_accuracy"] is not None
                else "undefined",
                f"{r['selective_macro_f1_fixed_taxonomy']:.4f}"
                if r["selective_macro_f1_fixed_taxonomy"] is not None
                else "undefined",
                f"{r['accepted_error_rate']:.4%}"
                if r["accepted_error_rate"] is not None
                else "undefined",
            ]
            for k, rows in abstain.items()
            for r in rows
            if "histogram" in k
        ],
    )
    costs_text = table(
        [
            "Fit",
            "Training seconds",
            "All-validation inference seconds",
            "Compact rows/s",
            "Process peak MiB",
        ],
        [
            [
                k,
                f"{v['fit_seconds']:.2f}",
                f"{v['predict_seconds']:.2f}",
                f"{v['compact_rows_per_second']:.0f}",
                f"{v['peak_process_rss_mib']:.1f}",
            ]
            for k, v in resources["candidates"].items()
        ],
    )
    text = f"""# NF-CSE attack-family feasibility — Phase 7A

## 1. Executive summary

**{decision}.** This is an exploratory offline study of the existing seven completed-flow features, with no production changes or deployment approval. All four predeclared fits and both frozen binary modes are reported. Weighted/macro metrics, benign false positives and family-specific errors determine feasibility; overall accuracy is not the ranking criterion.

The complete full-taxonomy GO requires macro-F1 ≥0.80, benign FPR ≤1%, overall attack detection recall ≥90%, and every attack family's identification recall ≥70% with ≥100 original validation records **and ≥100 distinct validation groups**. Resource gates: cumulative peak RSS ≤12 GiB and study wall time ≤30 minutes. Conditional GO requires detection/FPR/resource gates plus at least half the families meeting the support/recall gates. These engineering criteria were written to [experiment_plan.json](experiment_plan.json) before candidate validation scoring, not fitted to results. They are not claims of deployment adequacy.

[Decision checks](decision.json) list exactly which families pass for each candidate. **Rare-family reliability prevents an unqualified all-family claim.** No categories were merged, oversampled, relabeled or removed.

## 2. Dataset, labels and integrity

The sealed Phase 5B compact NPZ shards already store canonical features, original `Attack` strings, binary `Label`, group IDs and uint64 multiplicities. Labels are recovered directly from these verified shards, not guessed from ports or rejoined to raw data. Benign is index 0; all other names are lexically ordered from training and mapped identically in validation. The original spelling **Infilteration** is retained. Validation-only unseen labels would fail the run.

Every allowed shard checksum was verified before loading and after experiments. Each stored group ID was recomputed from its exact canonical vector, and every vector was checked against the frozen seed/schema partition rule. Full group-ID intersection was empty. [integrity.json](integrity.json) records train/validation hashes, opened-path ledger, manifest, frozen classifier identity and reproducible prediction hashes. Existing `deny_reserved` blocks test-shard opens, class-distribution metadata and processed-data writes. Only train/validation records were read; the common manifest's test objects are skipped by the existing streaming allowlist parser. No raw files, reserved test records or synthetic generator records enter this study.

{table(["Family", "Train originals", "Validation originals", "Train % attacks", "Val % attacks", "Train compact", "Val compact", "Train unique/groups", "Val unique/groups"], inv_rows)}

Original counts are sample weights; compact counts describe stored canonical-vector/family rows; unique counts refer to seven-feature vectors. For a given family, unique vectors equal distinct groups by definition. A group can support multiple families. [class_inventory.csv](class_inventory.csv) additionally reports ambiguity counts, own-label shares and multiplicity-weighted majority proportions within ambiguous groups. Multiplicities preserve the source record population but do not create independent episodes. Extremely rare families or families with fewer than 100 validation groups cannot satisfy the reliability gate even if observed recall is high.

## 3. Feature distinguishability

The seven raw inputs are exactly `PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS`. Existing canonical-to-13-field value/status encoding is reused unchanged. No IP, duration, capture/row identifier or label is a predictor. Protocol/status fields are categorical for boosting; ports remain numeric following the existing binary baseline. The linear transform reuses fixed protocol/status one-hot categories, port/65535 and log1p counters, with multiplicity-weighted scaling fitted only on the relevant training population.

Full weighted protocol/port distributions were compared, not sampled. The discrete CSVs retain top-10 source ports, destination ports and protocol/source/destination triples per family. [distribution_overlap.csv](distribution_overlap.csv) contains all pairwise total-variation distances for protocol, each port and joint triples (0 = same discrete distribution, 1 = disjoint). Nearest training joint distributions:

{feature_text}

Shared service signatures can make some families inseparable by ports alone; high-cardinality source ports and collection/generation artifacts can also make apparent separation misleading. These comparisons describe this corpus, not causal attack mechanisms. Full seven-feature collisions below provide stronger direct evidence of representation ambiguity.

Counter CSVs contain exact multiplicity-weighted median/p90/p99/means for every family/split. Negative unavailable statuses are excluded from scalar quantiles and counted; zeros remain legitimate values. Cross-feature CSVs report weighted log1p correlations for IN/OUT packets, IN/OUT bytes and directional bytes/packets. Conditioned CSVs report log1p counter means for each family's three most frequent protocols/destination ports. These examine joint relationships without adding new model features. Correlations after zero fill are explicitly descriptive and do not substitute for causal evidence. No outlier clipping occurred.

![Counter medians, log color](figures/counter_medians.svg)

## 4. Exact feature collisions

{collision_text}

For each exact canonical vector, the empirical deterministic multiclass ceiling is `sum(max weighted label mass) / sum(all mass)`. Attack-only ceilings restrict the plurality calculation to attack families; benign/attack and multiple-attack collisions are counted separately and may overlap. No majority voting is applied to training. [feature_overlap.csv](feature_overlap.csv) gives every pair's shared-vector count and label masses. [collision_analysis.json](collision_analysis.json) gives ambiguous population sizes, majority shares and unavoidable disagreement counts.

Specific representation limits in the measured populations are material:

- SlowHTTPTest and FTP-BruteForce share **all** their vectors: 8,479 shared training groups (63,437 SlowHTTPTest / 116,120 FTP records), and 2,818 validation groups (21,067 / 38,611). Both families have substantial weighted support; class scarcity alone cannot explain this indistinguishability. Their protocol/port signatures and seven-field supports overlap exactly. No deterministic function of these inputs can correctly assign both labels for an identical vector.
- SQL Injection shares all 24 training and seven validation vectors with DDOS attack-HOIC, with equal pairwise record masses. This combines representation ambiguity with extremely low SQL support. More copies of identical examples would not resolve it.
- Web and XSS share 1,263 records per label over 11 training vectors, and 410 records per label over two validation vectors. Apparent support is largely correlated multiplicity; the seven fields do not identify which family generated those shared observations.
- Infilteration shares 10,328 training groups with Benign (12,589 Infilteration / 106,923 benign originals) and 3,356 validation groups (3,998 / 29,257). This supplies direct evidence of benign/attack representation ambiguity alongside model misses. It does not prove every remaining error is irreducible.

These observations justify investigating additional independently sourced behavioral context and label provenance; they do not justify silently merging labels. The inventory, pairwise masses and joint distributions support these statements without using the test partition.

These are **empirical lookup ceilings on observed weighted vectors**, not universal generalization bounds, and cannot promise performance on disjoint unseen vectors. Identical vectors with conflicting labels cannot be resolved deterministically from these seven features; incomplete capture/label provenance limits attribution to true attack similarity versus source-label errors.

## 5. Direct multiclass baseline

A linear SGD log-loss baseline and histogram gradient boosting each predict Benign plus all 14 original attack families. No class balancing was used. Both receive original multiplicity sample weights. Linear: five fixed incremental epochs, alpha 1e-4, averaged SGD, deterministic within-batch shuffles. Histogram: 60 boosting iterations, 15 leaves, learning rate 0.1, L2=1, min_samples_leaf=20, early_stopping=False. No model or threshold search occurred. The fixed direct SGD baseline collapsed largely to Benign (attack detection recall about 0.23%); its macro-F1 0.0623 is a poor result for this unoptimized solver/budget, not proof that all linear formulations are infeasible. Attack-only linear macro-F1 was 0.1821. No extra validation-driven solver/epoch experiments were added after observing that outcome. SGD compact weighted gradients are not identical to repeated expanded updates; tree leaf constraints count compact rows. These limitations apply even though the intended objective retains original population weights.

{table(["Candidate", "Macro-F1", "Weighted-F1", "Balanced accuracy", "Benign FPR", "Attack detection recall", "Families passing support/recall"], compare)}

[direct_multiclass_metrics.json](direct_multiclass_metrics.json) and [per_family_metrics.csv](per_family_metrics.csv) contain all per-class precision, recall, F1 and full weighted confusion matrices. Rows are true labels, columns predicted labels in [class_mapping.json](class_mapping.json) order. Undefined precision is zero; fixed-taxonomy macro-F1 includes every class.

![Direct histogram confusion](figures/direct_histogram_confusion.svg)

## 6. Hierarchical baseline

Stage 1 is the unchanged frozen binary artifact. Both thresholds come from the verified registry configuration, with high_sensitivity cross-checked against frozen artifact metadata: `{NF_MODES}`. Standard is the existing fixed 0.5 operating point, not a new tuned threshold. Stage 2 trains only on attack-labeled training compact rows, with the same linear/histogram budgets and taxonomy as direct training. No binary refit or calibration.

For final predictions, binary Benign stays Benign; binary Attack routes to a family prediction. Stage-2 predictions on all validation rows were cached once to compare both modes. The report's stage-2 inference timing therefore includes all rows, a conservative bound rather than pretending it measured gated-only inference. Real gated execution would score only routed records; end-to-end validation predictions are identical to that routing. Binary inference separately took {resources["binary_validation_predict_seconds"]:.2f} seconds for the compact validation population. Stage-2 prediction + binary time is a reproducible conservative compute comparison, not request/HTTP latency.

Independent stage-2 evaluation uses true attack-labeled validation rows **without the binary gate**:

{conditional_text}

Conditional family performance is not end-to-end performance. The table above includes benign rows in every hierarchical final metric/confusion. Family identification recall is the weighted fraction of a true family assigned that exact final family; attack detection recall counts any non-Benign output even when its family is wrong.

{family_text}

![End-to-end recalls](figures/family_recall.svg)

## 7. Rare-family diagnosis

{rare_text}

The binary-detected count isolates first-stage misses; conditional-correct isolates family distinguishability when the binary gate is bypassed; end-to-end-correct requires both stages to succeed. [family_error_decomposition.csv](family_error_decomposition.csv) supplies this breakdown for every family, mode and stage-2 candidate. Compare these counts with collision/support evidence rather than assigning a single unsupported cause.

SQL Injection has only {val["SQL Injection"]["weighted_records"]} validation records in {val["SQL Injection"]["distinct_feature_groups"]} groups and {train["SQL Injection"]["weighted_records"]} training records. A one-record change shifts recall by {100 / val["SQL Injection"]["weighted_records"]:.2f} percentage points. Even a perfect observed outcome cannot establish reliable rare-family performance. Simple binomial confidence intervals would assume independence not justified by duplicate/grouped traffic; counts and distinct groups are provided instead of false precision. DDOS attack-HOIC also has fewer than 100 validation records. Web/XSS multiplicities and low group support require similar caution.

For Infilteration, the measured histogram stage-2 recall is 12,273/12,292 (99.85%) **conditional on true attack labels**. The standard gate detects 1,037 and yields 1,036 correct final families (8.43%); sensitivity detects 2,350 and yields 2,349 correct final families (19.11%). Sensitive end-to-end Infilteration precision falls to 14.89%, versus 95.40% under standard. Thus conditional success does not cure the binary detection/false-positive problem; excluding benign traffic changes the task materially. Direct histogram family recall is 1,148/12,292 (9.34%). A strong conditional classifier cannot recover flows already predicted Benign by the frozen gate. Conditional failures additionally expose second-stage difficulty. Collision ambiguity is representation evidence; rare/small-group supports are reliability evidence. This study cannot causally separate source-label issues, collection artifacts, missing behavioral features and limited independent episodes. No synthetic examples or validation oversampling were used.

## 8. Exploratory abstention

{abstain_text}

Cutoffs 0/0.5/0.7/0.9/0.95 were fixed before scoring. The score is the **uncalibrated maximum class output**, not a calibrated confidence probability. Coverage is accepted original mass / all original mass; selective accuracy and error use only accepted records. Selective macro-F1 uses the fixed taxonomy with undefined/absent classes zero, so it can change when entire families are rejected. It must be read alongside per-family rejection rates/support in [abstention_analysis.json](abstention_analysis.json), not used to hide difficult classes.

Hierarchical abstention applies only to binary-routed attacks; frozen Benign outputs remain accepted and can retain false negatives. Thus high overall coverage/selective accuracy can be dominated by benign traffic. Unknown/Uncertain is an experimental reject outcome, not an additional learned family. At raw cutoff 0.9, direct histogram coverage is 96.07% and accepted accuracy 99.29%, but selective macro-F1 falls to 0.5390: it rejects **all** SlowHTTPTest and FTP-BruteForce validation records, 433/436 Web, 422/424 XSS and 6/7 SQL Injection. High selective accuracy therefore hides substantial loss of attack-family coverage. In the sensitive hierarchy, only 3/12,292 Infilteration records are rejected at 0.9 because most misses remain accepted binary Benign outputs. Simple stage-2 score rejection cannot rescue them. These findings make abstention a potential explicit uncertainty interface for ambiguous families, not a reliable cure or a selected operating point. No final abstention cutoff was selected, no calibration was fitted, and no test access occurred.

## 9. Compute and memory

{costs_text}

Total analysis/fit/scoring wall time before report rendering: **{resources["wall_seconds_before_report"]:.2f} s**; cumulative peak process RSS **{resources["peak_process_rss_mib"]:.2f} MiB**; {resources["threads"]} CPU threads, Python 3.13. Measurements include compact loading, integrity/collision/distribution work; per-fit peaks are cumulative process high-water marks, not incremental estimator allocations. The binary model was reused rather than retrained; its historical training cost is not included in the new stage-2 fit times. Both new model types use identical fixed budgets in direct/attack-only fits, with naturally smaller attack-only training populations. No GPU or full-row expansion. Chunked probability inference bounds temporary class-score matrices. Resource values vary by machine/load. Four fits are all recorded; there were no undisclosed discarded experiments or validation-based hyperparameter retries.

## 10. Comparative assessment and decision

**{decision}.** Eight families clear the support/recall gates for each boosting architecture: Bot, DDOS attack-LOIC-UDP, DDoS attacks-LOIC-HTTP, DoS attacks-GoldenEye, DoS attacks-Hulk, DoS attacks-Slowloris, FTP-BruteForce and SSH-Bruteforce. None clears the full taxonomy macro-F1 0.80 gate. Web, XSS, HOIC and SQL have insufficient independent group/record support; SlowHTTPTest has zero family recall; Infilteration remains below the family recall gate. This is **NO-GO for a general reliable 15-class deployment now**, with conditional research feasibility for a supported subset. [decision.json](decision.json) evaluates predeclared gates for every candidate. Direct models may jointly distinguish benign and families; hierarchy preserves existing binary operating modes and isolates family learning, but its final recall is capped by binary detection. The standard gate minimizes benign false positives in this corpus; sensitivity trades more false positives for attack coverage. Macro-F1 and rare-family recalls expose weaknesses hidden by weighted scores.

Even if a subset clears the conditional gates, the 15-class taxonomy has insufficient rare-family evidence. Do not deploy/register these experiments or silently merge difficult classes. A useful follow-up would predeclare a supported-family/uncertain-output policy and evaluate it on newly acquired independent captures; additional session/temporal/exporter evidence may be needed to resolve ambiguous families. Any proposed merge must have a defensible semantic rationale before another fit, not merely improve metrics.

## 11. Validation limitations and next steps

The frozen validation partition is group-disjoint, not capture/session/host/time independent. It already informed binary model/threshold selection in earlier phases. This study evaluates four new fits and exploratory abstention on it: comparative findings carry selection/validation-reuse bias. No independent deployment claim follows. The prior binary final-evaluation report was inspected as requested, but its numbers were not used for budgets, taxonomy, thresholds or new candidate selection; no reserved records were opened.

No internal tuning split was needed because all configurations/budgets were fixed. Any future tuning must split training groups only and keep this validation role explicit. The original held-out test benchmark has an existing binary evaluation history; this phase neither reopens it nor resets that history. Collect a new independent evaluation corpus before making broad family-generalization claims.

The generator profiles remain binary and train-derived; they provide no independent family ground truth and were not used as evaluation inputs. Production models, thresholds, API, Streamlit, Simulation Lab, normalizer and processed partitions are unchanged. Experimental estimators are not serialized or registered; predictions/config/metrics/artifact hashes suffice to reproduce this research. Runtime/RSS fields are intentionally non-deterministic. See the root README for the executable, required inputs, output protection and test commands.
"""
    (out / "feasibility_report.md").write_text(text)
