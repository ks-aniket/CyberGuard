"""One-shot final evaluation; no fit, threshold search or data modification."""

from __future__ import annotations

import html
import json
import os
import platform
import resource
import tempfile
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import brier_score_loss, log_loss
from threadpoolctl import threadpool_limits

from cyberguard.features import nf_cse as nf
from cyberguard.features.nf_cse_preparation import sha256
from cyberguard.training import nf_cse_metrics as ev
from cyberguard.training.train_nf_cse import (
    ManifestSubset,
    json_dump,
    probe_frame,
    svg_lines,
    validate_artifact,
)

THRESHOLDS = {"high_sensitivity": 0.03090052128234102, "lower_false_alarm": 0.5}
EXPECTED = {
    "rows": 1689195,
    "compact_records": 953681,
    "groups": 947108,
    "binary_counts": {"0": 1485639, "1": 203556},
}
WARNING = "FINAL TEST: one frozen evaluation only. Never use these results to tune or calibrate this model; repeated test-based development consumes the benchmark."
LIMITATIONS = "Offline completed bidirectional flows only. Feature-group separation does not establish capture/session/host/time independence. Service signatures, collection artifacts, conflicting vectors and exporter parity remain limitations. Scores are uncalibrated; benign predictions do not prove safety. No API/dashboard integration or live/packet-level performance is established."


class TestManifest(ManifestSubset):
    def allowed(self, path):
        if path[0] in {"identity", "status"}:
            return True
        if path[0] == "artifacts":
            return (
                len(path) == 1
                or path[1].startswith("test/")
                or path[1]
                in {
                    "metadata/feature_contract.json",
                    "metadata/preprocessing_manifest.json",
                }
            )
        return path[0] == "plan" and (
            len(path) == 1
            or (path[1] == "partitions" and (len(path) == 2 or path[2] == "test"))
        )


@contextmanager
def forbid_fitting(model):
    """Fail closed if inference unexpectedly attempts any fitting."""
    saved = []

    def fail(*args, **kwargs):
        raise RuntimeError("Fitting is forbidden during final evaluation")

    try:
        for obj in [model, model.estimator, model.normalizer]:
            for name in ("fit", "fit_transform", "partial_fit"):
                if hasattr(obj, name):
                    own = name in obj.__dict__
                    saved.append((obj, name, own, getattr(obj, name)))
                    setattr(obj, name, fail)
        yield
    finally:
        for obj, name, own, value in reversed(saved):
            if own:
                setattr(obj, name, value)
            else:
                delattr(obj, name)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def preflight(root, artifact, validation_path, expected=EXPECTED):
    """Common metadata first, then test checksums. No test arrays/predictions yet."""
    model, metadata = validate_artifact(artifact)
    require(
        isinstance(model.estimator, HistGradientBoostingClassifier)
        and model.linear_transform is None,
        "Expected frozen histogram model",
    )
    require(
        metadata["model_type"] == "hist_gradient_boosting"
        and metadata["class_mapping"] == {"0": "Benign", "1": "Attack"}
        and list(model.estimator.classes_) == [0, 1],
        "Class/algorithm mapping mismatch",
    )
    require(
        model.threshold == THRESHOLDS["high_sensitivity"], "Frozen threshold mismatch"
    )
    require(
        metadata["preprocessing_version"] == nf.PREPROCESSING_VERSION
        and metadata["encoded_feature_order"] == list(nf.MODEL_FEATURES)
        and metadata["feature_order"] == list(nf.RAW_FEATURES),
        "Preprocessing/order mismatch",
    )
    for key in ("preprocessing_version", "encoded_feature_order"):
        require(
            model.metadata_.get(key) == metadata[key], "Embedded preprocessing mismatch"
        )
    manifest_path = root / "metadata/split_manifest.json"
    digest = sha256(manifest_path)
    require(
        digest
        == (root / "metadata/split_manifest.sha256").read_text().strip()
        == metadata["partition_manifest_sha256"],
        "Partition manifest checksum mismatch",
    )
    with manifest_path.open() as stream:
        manifest = TestManifest(stream).value()
    identity = manifest["identity"]
    require(
        manifest["status"] == "complete"
        and identity["schema_version"] == nf.CONTRACT_VERSION
        and identity["preprocessing_version"] == nf.PREPROCESSING_VERSION
        and identity["source_sha256"] == metadata["source_dataset_sha256"],
        "Manifest identity mismatch",
    )
    require(
        identity["implementation_sha256"]["nf_cse.py"] == sha256(nf.__file__),
        "Sealed normalizer source mismatch",
    )
    files = {
        str(artifact.resolve()): sha256(artifact),
        str(artifact.with_suffix(".metadata.json").resolve()): sha256(
            artifact.with_suffix(".metadata.json")
        ),
        str(manifest_path.resolve()): digest,
        str((root / "metadata/split_manifest.sha256").resolve()): sha256(
            root / "metadata/split_manifest.sha256"
        ),
    }
    # Verify shared contract/preprocessing metadata before opening test shards.
    for name in (
        "metadata/feature_contract.json",
        "metadata/preprocessing_manifest.json",
    ):
        path = root / name
        require(
            sha256(path) == manifest["artifacts"][name]["sha256"],
            f"Checksum mismatch: {name}",
        )
        files[str(path.resolve())] = sha256(path)
    contract = json.loads((root / "metadata/feature_contract.json").read_text())
    require(
        contract == json.loads(json.dumps(nf.feature_contract())),
        "Frozen feature contract mismatch",
    )
    require(
        identity["feature_contract_sha256"]
        == sha256(root / "metadata/feature_contract.json"),
        "Contract identity mismatch",
    )
    preprocessing = json.loads(
        (root / "metadata/preprocessing_manifest.json").read_text()
    )
    require(
        preprocessing["version"] == nf.PREPROCESSING_VERSION
        and preprocessing["learned_parameters"] is None,
        "Unexpected preprocessing state",
    )
    plan = manifest["plan"]["partitions"]["test"]
    require(
        all(plan[k] == v for k, v in expected.items()),
        "Expected test population mismatch",
    )
    validation = json.loads(validation_path.read_text())
    require(
        validation["metadata"]["artifact_sha256"] == metadata["artifact_sha256"],
        "Frozen validation model mismatch",
    )
    for mode, key in (
        ("high_sensitivity", "selected"),
        ("lower_false_alarm", "fixed_0_5"),
    ):
        require(
            validation["models"]["hist_gradient_boosting"][key]["threshold"]
            == THRESHOLDS[mode],
            "Frozen validation threshold mismatch",
        )
    files[str(validation_path.resolve())] = sha256(validation_path)
    with forbid_fitting(model):
        p = model.predict_proba(probe_frame())
        require(
            p.shape == (2, 2) and np.allclose(p.sum(axis=1), 1),
            "Inference probe failed",
        )
        require(
            np.array_equal(
                model.predict(probe_frame()),
                (p[:, 1] >= model.threshold).astype(np.uint8),
            ),
            "Binary mapping failed",
        )
    shards = sorted(k for k in manifest["artifacts"] if k.startswith("test/"))
    require(
        set(shards)
        == {p.relative_to(root).as_posix() for p in (root / "test").iterdir()},
        "Test inventory mismatch",
    )
    for name in shards:
        path = root / name
        require(
            path.parent.resolve() == (root / "test").resolve()
            and path.suffix == ".npz",
            "Unsafe shard path",
        )
        spec = manifest["artifacts"][name]
        require(
            path.stat().st_size == spec["bytes"] and sha256(path) == spec["sha256"],
            f"Test checksum mismatch: {name}",
        )
        files[str(path.resolve())] = spec["sha256"]
    if expected == EXPECTED:
        require(len(shards) == 20, "Expected 20 test shards")
    return model, metadata, manifest, validation, files, shards


def load_test(root, manifest, shards):
    """Retain compact data only; preallocate arrays and encode one shard at a time."""
    plan = manifest["plan"]["partitions"]["test"]
    n = plan["compact_records"]
    X = np.empty((n, len(nf.MODEL_FEATURES)), dtype=np.float64)
    y = np.empty(n, dtype=np.uint8)
    weight = np.empty(n, dtype=np.uint64)
    groups = np.empty(n, dtype="S64")
    names = sorted(plan["Attack_counts"])
    codes = np.empty(n, dtype=np.uint16)
    offset = 0
    for name in shards:
        with np.load(root / name, allow_pickle=False) as shard:
            require(
                set(shard.files)
                == {"features", "Label", "Attack", "multiplicity", "group_id"},
                "Shard schema mismatch",
            )
            f, label, attack, w, g = (
                shard[k]
                for k in ("features", "Label", "Attack", "multiplicity", "group_id")
            )
            count = len(label)
            require(
                f.dtype == np.int64
                and f.shape == (count, 7)
                and label.dtype == np.uint8
                and w.dtype == np.uint64
                and g.dtype == np.dtype("S64")
                and all(a.shape == (count,) for a in (label, attack, w, g))
                and attack.dtype.kind == "U"
                and offset + count <= n,
                "Invalid shard shape/dtype",
            )
            require(
                np.isin(label, [0, 1]).all()
                and np.all(w > 0)
                and np.all(w <= 2**53)
                and np.all((attack == "Benign") == (label == 0))
                and set(attack).issubset(names),
                "Invalid labels/weights/families",
            )
            end = offset + count
            X[offset:end] = nf.model_features(
                pd.DataFrame(f, columns=nf.RAW_FEATURES)
            ).to_numpy(dtype=float)
            y[offset:end], weight[offset:end], groups[offset:end] = label, w, g
            codes[offset:end] = np.array(
                [names.index(a) for a in attack], dtype=np.uint16
            )
            offset = end
    require(offset == n and int(weight.sum()) == plan["rows"], "Test total mismatch")
    require(
        {str(k): int(weight[y == k].sum()) for k in (0, 1)} == plan["binary_counts"],
        "Test binary counts mismatch",
    )
    require(len(np.unique(groups)) == plan["groups"], "Test group count mismatch")
    require(
        {name: int(weight[codes == i].sum()) for i, name in enumerate(names)}
        == plan["Attack_counts"],
        "Test family counts mismatch",
    )
    require(
        {str(k): len(np.unique(groups[y == k])) for k in (0, 1)}
        == plan["binary_group_support"],
        "Binary group support mismatch",
    )
    return X, y, weight, groups, codes, names


def summarize(y, score, weight, groups, codes, names, validation):
    results, families, comparisons = {}, [], []
    for mode, threshold in THRESHOLDS.items():
        result = ev.metrics(y, score, weight, threshold)
        tn, fp, fn, tp = np.asarray(result["confusion_matrix"]).ravel().tolist()
        result.update(
            specificity=tn / (tn + fp),
            predicted_benign=tn + fn,
            predicted_attack=tp + fp,
        )
        results[mode] = result
        for row in ev.family_recall(y, score, weight, codes, names, groups, threshold):
            row["original_records"] = row.pop("validation_records")
            row.update(
                mode=mode,
                threshold=threshold,
                true_positives=row["original_records"] - row["false_negatives"],
            )
            families.append(row)
        key = "selected" if mode == "high_sensitivity" else "fixed_0_5"
        baseline = validation["models"]["hist_gradient_boosting"][key]
        for metric in (
            "recall",
            "benign_fpr",
            "precision",
            "f1",
            "roc_auc",
            "average_precision",
        ):
            comparisons.append(
                {
                    "mode": mode,
                    "threshold": threshold,
                    "metric": metric,
                    "validation": baseline[metric],
                    "test": result[metric],
                    "test_minus_validation": result[metric] - baseline[metric],
                }
            )
    quality = {
        "brier_score": float(brier_score_loss(y, score, sample_weight=weight)),
        "log_loss": float(
            log_loss(
                y,
                np.column_stack([1 - score, score]),
                sample_weight=weight,
                labels=[0, 1],
            )
        ),
        "interpretation": "Uncalibrated score quality diagnostics; Brier is not proof of calibration. Log loss uses sklearn float64 epsilon clipping. AP is weighted step-wise average precision, not trapezoidal PR-AUC.",
    }
    return results, families, comparisons, quality


def plot_lines(path, title, xlabel, ylabel, series, **kwargs):
    svg_lines(path, title, xlabel, ylabel, series, **kwargs)
    path.write_text(
        path.read_text().replace(
            "Weighted validation; display downsampled, metrics/threshold choice use all scores.",
            "Original-record-weighted final test; display downsampled. No threshold selection.",
        )
    )


def write_outputs(
    stage, results, families, comparisons, quality, y, score, weight, codes, names
):
    pd.DataFrame(
        [
            {k: v for k, v in r.items() if not isinstance(v, (dict, list))}
            | {"mode": mode}
            for mode, r in results.items()
        ]
    ).to_csv(stage / "threshold_comparison.csv", index=False)
    pd.DataFrame(families).to_csv(stage / "attack_family_recall.csv", index=False)
    pd.DataFrame(comparisons).to_csv(
        stage / "validation_test_comparison.csv", index=False
    )
    pd.DataFrame(
        [
            {
                "mode": mode,
                "actual": a,
                "predicted": p,
                "original_records": r["confusion_matrix"][i][j],
            }
            for mode, r in results.items()
            for i, a in enumerate(["Benign", "Attack"])
            for j, p in enumerate(["Benign", "Attack"])
        ]
    ).to_csv(stage / "confusion_matrices.csv", index=False)
    fig = stage / "figures"
    fig.mkdir()
    curve = ev.curves(y, score, weight)
    plot_lines(
        fig / "roc.svg",
        "Final test ROC",
        "Benign FPR",
        "Attack recall",
        [("Frozen model", curve["fpr"], curve["recall"])],
    )
    plot_lines(
        fig / "precision_recall.svg",
        "Final test precision-recall",
        "Attack recall",
        "Precision",
        [("Frozen model", curve["pr_recall"], curve["precision"])],
    )
    for mode, r in results.items():
        cm = r["confusion_matrix"]
        text = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="800" height="370"><rect width="100%" height="100%" fill="white"/><g font-family="sans-serif" font-size="18"><text x="30" y="35">{mode}: threshold {r["threshold"]:.17g}</text><text x="30" y="70">Original-record counts; rows actual, columns predicted</text><text x="260" y="110">Benign</text><text x="500" y="110">Attack</text>'
        ]
        for i, label in enumerate(["Benign", "Attack"]):
            text.append(f'<text x="30" y="{180 + i * 90}">{label}</text>')
            for j in (0, 1):
                text.append(
                    f'<rect x="{220 + j * 240}" y="{130 + i * 90}" width="225" height="80" fill="#dbeafe"/><text x="{250 + j * 240}" y="{180 + i * 90}">{cm[i][j]:,}</text>'
                )
        (fig / f"confusion_{mode}.svg").write_text("".join(text) + "</g></svg>")
    # Weighted empirical CDFs expose low-score overlap and discrete spikes without bin ambiguity.
    distribution = []
    for label, mask in [("Benign", y == 0), ("Attack", y == 1)] + [
        (name, codes == i) for i, name in enumerate(names) if name != "Benign"
    ]:
        values, weights = score[mask], weight[mask]
        order = np.argsort(values)
        x, cdf = values[order], np.cumsum(weights[order], dtype=float) / weights.sum()
        if label in {"Benign", "Attack"}:
            distribution.append((label, x, cdf))
        safe = "".join(c if c.isalnum() else "_" for c in label)
        if label not in {"Benign", "Attack"}:
            plot_lines(
                fig / f"score_{safe}.svg",
                f"Final test score CDF: {label}",
                "Uncalibrated attack score",
                "Weighted cumulative fraction",
                [(label, x, cdf)],
                vertical=THRESHOLDS["high_sensitivity"],
            )
    plot_lines(
        fig / "score_distributions.svg",
        "Final test score distributions (empirical CDF)",
        "Uncalibrated attack score",
        "Weighted cumulative fraction",
        distribution,
    )
    for mode, threshold in THRESHOLDS.items():
        selected = []
        for label, x, cdf in distribution:
            mask = (x >= max(0, threshold - 0.025)) & (x <= threshold + 0.025)
            selected.append((label, (x[mask] - max(0, threshold - 0.025)), cdf[mask]))
        plot_lines(
            fig / f"score_overlap_{mode}.svg",
            f"Score overlap around {threshold:.17g}; x origin {max(0, threshold - 0.025):.5g}",
            "Score above window origin",
            "Whole-class cumulative fraction",
            selected,
            xmax=0.05,
            vertical=threshold - max(0, threshold - 0.025),
        )
    family_table = pd.DataFrame(families)
    text = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="850"><rect width="100%" height="100%" fill="white"/><g font-family="sans-serif" font-size="14"><text x="20" y="25">Final test family recall: blue sensitivity, orange lower false alarm; scale 0 to 1</text>'
    ]
    for i, name in enumerate(sorted(family_table.attack_family.unique())):
        rows = family_table[family_table.attack_family == name]
        text.append(f'<text x="15" y="{65 + 52 * i}">{html.escape(name)}</text>')
        for j, mode in enumerate(THRESHOLDS):
            recall = float(rows[rows["mode"] == mode].iloc[0].recall)
            text.append(
                f'<rect x="265" y="{48 + 52 * i + 17 * j}" width="{600 * recall}" height="14" fill="{["#2563eb", "#ea580c"][j]}"/><text x="880" y="{61 + 52 * i + 17 * j}">{recall:.4f}</text>'
            )
    (fig / "family_recall.svg").write_text("".join(text) + "</g></svg>")
    # Exact threshold neighborhoods, plus weighted family score summaries.
    score_rows = []
    for name, mask in [("Benign", y == 0), ("Attack", y == 1)] + [
        (name, codes == i) for i, name in enumerate(names) if name != "Benign"
    ]:
        row = {
            "population": name,
            "original_records": int(weight[mask].sum()),
            "weighted_mean": float(np.average(score[mask], weights=weight[mask])),
        }
        for mode, t in THRESHOLDS.items():
            row[f"below_{mode}"] = int(weight[mask & (score < t)].sum())
            row[f"within_0_01_{mode}"] = int(
                weight[mask & (np.abs(score - t) <= 0.01)].sum()
            )
        score_rows.append(row)
    pd.DataFrame(score_rows).to_csv(stage / "score_summary.csv", index=False)
    json_dump(
        {"thresholds": results, "score_quality": quality, "score_summary": score_rows},
        stage / "test_metrics.json",
    )


def render_report(stage, results, families, comparisons, quality, resources):
    rows = [
        "# NF-CSE frozen final test evaluation",
        "",
        WARNING,
        "",
        LIMITATIONS,
        "",
        "## Verified population and method",
        "",
        f"{next(iter(results.values()))['original_records']:,} original records represented by {next(iter(results.values()))['compact_records']:,} compact records. Original multiplicities are the only metric weights; conflicting records and all original family names remain. No fitting, calibration, threshold search, class balancing, validation-shard access or raw-data access. Stored canonical vectors use the sealed model encoding directly; they are not re-normalized as raw negative-status values. Synthetic raw probes verify saved inference without fitting.",
        "",
        "## Frozen operating points",
        "",
        "| Mode | Threshold | Accuracy | Balanced accuracy | Precision | Recall | F1 | Specificity | Benign FPR | FP/10k | Predicted benign | Predicted attack |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for mode, r in results.items():
        rows.append(
            f"| {mode} | {r['threshold']:.17g} | "
            + " | ".join(
                f"{r[k]:.6f}"
                for k in (
                    "accuracy",
                    "balanced_accuracy",
                    "precision",
                    "recall",
                    "f1",
                    "specificity",
                    "benign_fpr",
                    "false_positives_per_10000_benign",
                )
            )
            + f" | {r['predicted_benign']} | {r['predicted_attack']} |"
        )
    for mode, r in results.items():
        rows.extend(
            [
                "",
                f"{mode} confusion (actual rows / predicted columns, Benign then Attack): `{r['confusion_matrix']}`; FNR {r['false_negative_rate']:.6f}.",
                "",
            ]
        )
    r = results["high_sensitivity"]
    rows.extend(
        [
            f"ROC-AUC **{r['roc_auc']:.8f}**; weighted average precision **{r['average_precision']:.8f}** (step-wise AP, not trapezoidal PR-AUC). Brier **{quality['brier_score']:.8f}**, log loss **{quality['log_loss']:.8f}** with float64 epsilon safeguards. These are uncalibrated-score diagnostics, not calibrated attack probabilities.",
            "",
            "## Validation versus final test",
            "",
            "Frozen validation metrics JSON is read only; no validation records are scored. Differences below are test minus validation (fractions, not percentage points).",
            "",
            "| Mode | Metric | Validation | Test | Difference |",
            "|---|---|---|---|---|",
        ]
    )
    rows.extend(
        f"| {r['mode']} | {r['metric']} | {r['validation']:.8f} | {r['test']:.8f} | {r['test_minus_validation']:+.8f} |"
        for r in comparisons
    )
    rows.extend(
        [
            "",
            "## Attack-family weaknesses",
            "",
            "| Family | Mode | Original support | Distinct groups | TP | FN | Recall |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    rows.extend(
        f"| {r['attack_family']} | {r['mode']} | {r['original_records']} | {r['distinct_feature_groups']} | {r['true_positives']} | {r['false_negatives']} | {r['recall']:.6f} |"
        for r in families
    )
    for item in families:
        if item["attack_family"] == "Infilteration":
            total_fn = int(np.asarray(results[item["mode"]]["confusion_matrix"])[1, 0])
            rows.extend(
                [
                    "",
                    f"Infilteration ({item['mode']}): {item['true_positives']:,}/{item['original_records']:,} detected; {item['false_negatives']:,} misses account for {item['false_negatives'] / max(1, total_fn):.2%} of all attack false negatives. This quantifies whether the validation weakness persists; no threshold was changed.",
                ]
            )
    rows.extend(
        [
            "",
            "Tiny SQL Injection and other rare-family supports cannot establish robust category detection; weighted repeated records are not independent episodes. Family group counts can overlap because conflicting vectors retain their metadata. This is a binary model, not multiclass attribution.",
            "",
            "## Score distributions and interpretation",
            "",
            "Weighted empirical CDFs show benign/attack overlap and each original family separately. score_summary.csv records weighted means, counts below each frozen threshold, and counts within ±0.01. Conflicting labels on identical vectors necessarily share scores. The Infilteration TP/FN table and score summary quantify persistence of its validation weakness without changing a threshold. Differences in rare-family row counts and repeated group support can shift measured recall across partitions. Neither these descriptive comparisons nor similar aggregate metrics establish independent capture generalization.",
            "",
            "![ROC](figures/roc.svg)",
            "![PR](figures/precision_recall.svg)",
            "![Scores](figures/score_distributions.svg)",
            "![Family recalls](figures/family_recall.svg)",
            "",
            "## Resources and reproducibility",
            "",
            f"Resources: `{json.dumps(resources, sort_keys=True)}`. Throughput counts compact rows (not independent flows); prediction timing excludes encoding and IO. Peak RSS is process-wide Linux high-water memory. CPU only, no expansion of weighted records. Integrity hashes, software versions, evaluation code/config and UTC timestamp are in evaluation_manifest.json.",
            "",
            "The persistent attempt ledger is created exclusively before any test access. Published output is atomic and never overwritten. If an attempt fails, preserve its ledger/staging evidence for manual investigation; there is no routine force/retry path. Inspect existing results read-only. Future improvements require new development data and an independently sourced holdout, not tuning against this final test. No model/service integration is included.",
        ]
    )
    (stage / "evaluation_report.md").write_text("\n".join(rows) + "\n")


def run(
    root,
    artifact,
    validation_path,
    output,
    *,
    allow=False,
    threads=4,
    batch_size=50000,
    expected=EXPECTED,
):
    if not allow:
        raise ValueError(
            "Explicit --allow-final-test required; use --inspect for existing results"
        )
    root, artifact, validation_path, output = (
        Path(p).resolve() for p in (root, artifact, validation_path, output)
    )
    require(
        1 <= threads <= (os.cpu_count() or 1) and batch_size > 0,
        "Invalid threads/batch size",
    )
    require(
        not output.exists(), "Final evaluation results already exist; use --inspect"
    )
    require(
        not output.is_relative_to(root)
        and not output.is_relative_to(artifact.parent)
        and not output.is_relative_to(Path(__file__).resolve().parents[3] / "data"),
        "Unsafe output location",
    )
    print(WARNING, flush=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    ledger = output.parent / "final_test_attempt.json"
    # Exclusive and persistent even on failure. No alternate-output CLI or force switch.
    with ledger.open("x") as stream:
        json.dump(
            {
                "started_utc": datetime.now(UTC).isoformat(),
                "output": str(output),
                "model": str(artifact),
                "policy": WARNING,
            },
            stream,
            indent=2,
        )
        stream.flush()
        os.fsync(stream.fileno())
    started = time.perf_counter()
    with threadpool_limits(limits=threads):
        model, metadata, manifest, validation, files, shards = preflight(
            root, artifact, validation_path, expected
        )
        X, y, weight, groups, codes, names = load_test(root, manifest, shards)
        score = np.empty(len(y), dtype=float)
        with forbid_fitting(model):
            scoring_start = time.perf_counter()
            for begin in range(0, len(y), batch_size):
                score[begin : begin + batch_size] = model.score_encoded(
                    X[begin : begin + batch_size]
                )
            scoring_seconds = time.perf_counter() - scoring_start
        del X
        results, families, comparisons, quality = summarize(
            y, score, weight, groups, codes, names, validation
        )
        stage = Path(tempfile.mkdtemp(prefix=".final-test-", dir=output.parent))
        # Retain staging on failure for manual diagnosis, never automatically rescore.
        write_outputs(
            stage,
            results,
            families,
            comparisons,
            quality,
            y,
            score,
            weight,
            codes,
            names,
        )
        for path, digest in files.items():
            require(sha256(path) == digest, f"Input changed during evaluation: {path}")
        resources = {
            "wall_seconds": time.perf_counter() - started,
            "prediction_seconds": scoring_seconds,
            "compact_records_per_second": len(y) / scoring_seconds,
            "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
            "serialized_model_bytes": artifact.stat().st_size,
            "threads": threads,
            "batch_size": batch_size,
            "timing_scope": "Integrity, loading, scoring, metrics, plots and rehashes; excludes final markdown/manifest publication.",
        }
        render_report(stage, results, families, comparisons, quality, resources)
        record = {
            "status": "complete",
            "evaluated_utc": datetime.now(UTC).isoformat(),
            "thresholds": THRESHOLDS,
            "integrity_checks": {
                key: "passed"
                for key in (
                    "model_checksum",
                    "embedded_metadata",
                    "class_mapping",
                    "contract",
                    "preprocessing_source",
                    "manifest_checksum",
                    "test_inventory_checksums",
                    "expected_population",
                    "frozen_thresholds",
                    "inference_without_fit",
                    "inputs_unchanged",
                )
            },
            "source_artifact_sha256": files,
            "dataset_identity": manifest["identity"],
            "test_population": manifest["plan"]["partitions"]["test"],
            "model_metadata": metadata,
            "resources": resources,
            "versions": {
                "python": platform.python_version(),
                "numpy": np.__version__,
                "pandas": pd.__version__,
                "sklearn": sklearn.__version__,
            },
            "evaluator_sha256": sha256(__file__),
            "metric_code_sha256": sha256(ev.__file__),
            "inference_code_sha256": sha256(
                Path(__file__).parents[1] / "inference/nf_cse_model.py"
            ),
            "outputs": {
                p.relative_to(stage).as_posix(): sha256(p)
                for p in stage.rglob("*")
                if p.is_file()
            },
            "warning": LIMITATIONS,
        }
        json_dump(record, stage / "evaluation_manifest.json")
        require(
            not output.exists(),
            "Output appeared during evaluation; refusing publication",
        )
        os.rename(stage, output)
    print(f"Final evaluation published: {output}", flush=True)
    return record


def inspect(output):
    output = Path(output)
    record = json.loads((output / "evaluation_manifest.json").read_text())
    for name, digest in record["outputs"].items():
        path = (output / name).resolve()
        require(
            path.is_relative_to(output.resolve()) and sha256(path) == digest,
            f"Result checksum mismatch: {name}",
        )
    return {
        "manifest": record,
        "metrics": json.loads((output / "test_metrics.json").read_text()),
    }
