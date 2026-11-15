"""Original-record-weighted binary metrics and deterministic validation thresholds."""

from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def validate_scores(y, score, weight):
    y, score, weight = (
        np.asarray(y),
        np.asarray(score, dtype=float),
        np.asarray(weight, dtype=float),
    )
    if y.ndim != 1 or score.shape != y.shape or weight.shape != y.shape or not len(y):
        raise ValueError("Expected aligned nonempty binary vectors")
    if (
        set(np.unique(y)) != {0, 1}
        or not np.isfinite(score).all()
        or np.any((score < 0) | (score > 1))
        or not np.isfinite(weight).all()
        or np.any(weight <= 0)
    ):
        raise ValueError(
            "Need both labels 0/1, finite probabilities and positive multiplicities"
        )
    return y, score, weight


def curves(y, score, weight):
    y, score, weight = validate_scores(y, score, weight)
    fpr, tpr, threshold = roc_curve(
        y, score, sample_weight=weight, drop_intermediate=False
    )
    threshold[~np.isfinite(threshold)] = np.nextafter(1.0, np.inf)
    precision, recall, pr_threshold = precision_recall_curve(
        y, score, sample_weight=weight
    )
    return {
        "fpr": fpr,
        "recall": tpr,
        "threshold": threshold,
        "precision": precision,
        "pr_recall": recall,
        "pr_threshold": pr_threshold,
    }


def select_threshold(curve, max_fpr=0.01):
    """>= boundary; ties in scores are indivisible. Recall, then lower FPR, then higher threshold."""
    candidates = np.flatnonzero(curve["fpr"] <= max_fpr)
    if not len(candidates):
        raise ValueError("No reject-all point in threshold curve")
    best = max(
        candidates,
        key=lambda i: (curve["recall"][i], -curve["fpr"][i], curve["threshold"][i]),
    )
    return float(curve["threshold"][best]), int(best)


def metrics(y, score, weight, threshold):
    y, score, weight = validate_scores(y, score, weight)
    prediction = (score >= threshold).astype(np.uint8)
    cm = confusion_matrix(y, prediction, labels=[0, 1], sample_weight=weight)
    tn, fp, fn, tp = map(float, cm.ravel())
    report = classification_report(
        y,
        prediction,
        labels=[0, 1],
        target_names=["Benign", "Attack"],
        sample_weight=weight,
        output_dict=True,
        zero_division=0,
    )
    return {
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y, prediction, sample_weight=weight)),
        "balanced_accuracy": float(
            balanced_accuracy_score(y, prediction, sample_weight=weight)
        ),
        "precision": float(
            precision_score(y, prediction, sample_weight=weight, zero_division=0)
        ),
        "recall": float(
            recall_score(y, prediction, sample_weight=weight, zero_division=0)
        ),
        "f1": float(f1_score(y, prediction, sample_weight=weight, zero_division=0)),
        "macro_f1": float(
            f1_score(
                y, prediction, sample_weight=weight, average="macro", zero_division=0
            )
        ),
        "roc_auc": float(roc_auc_score(y, score, sample_weight=weight)),
        "average_precision": float(
            average_precision_score(y, score, sample_weight=weight)
        ),
        "benign_fpr": fp / (tn + fp),
        "false_positives_per_10000_benign": 10000 * fp / (tn + fp),
        "attack_detection_rate": tp / (tp + fn),
        "false_negative_rate": fn / (tp + fn),
        "confusion_matrix": cm.astype(np.int64).tolist(),
        "confusion_order": ["Benign", "Attack"],
        "classification_report": report,
        "original_records": int(weight.sum()),
        "compact_records": len(y),
    }


def family_recall(y, score, weight, codes, names, groups, threshold):
    pred = score >= threshold
    result = []
    for code, name in enumerate(names):
        if name == "Benign":
            continue
        mask = codes == code
        if not np.all(y[mask] == 1):
            raise ValueError("Attack metadata disagrees with binary labels")
        n = int(weight[mask].sum())
        fn = int(weight[mask & ~pred].sum())
        result.append(
            {
                "attack_family": name,
                "validation_records": n,
                "distinct_feature_groups": len(np.unique(groups[mask])),
                "false_negatives": fn,
                "recall": (n - fn) / n if n else None,
            }
        )
    return sorted(result, key=lambda row: row["attack_family"])
