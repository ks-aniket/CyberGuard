"""Read-only inference and bounded-memory evaluation of a fitted network model."""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)

from cyberguard.features.network import RAW_FEATURES, TARGETS
from cyberguard.inference.model_loader import inspect_model, sha256
from cyberguard.inference.network_detector import predict_frame
from cyberguard.training.train_network import DEFAULT_TRAIN

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MODEL = Path("models/network/bot_iot_restricted_baseline.joblib")
OFFICIAL_TEST = Path(
    "data/raw/bot_iot/test/UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv"
)
LIMITATIONS = (
    "Experimental offline predictions use only protocol and ports. "
    "Probabilities are uncalibrated model estimates, not confidence in real maliciousness. "
    "Theft and unknown attacks are unsupported. No live network detection is performed."
)


def load_model(path):
    from cyberguard.inference.model_loader import load_model as shared_load

    return shared_load(path, loader=joblib.load)


def same_path(a, b):
    a, b = Path(a), Path(b)
    return a.resolve() == b.resolve() or (a.exists() and b.exists() and a.samefile(b))


def positive_int(value):
    value = int(value)
    if value < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def protect_input(path, root, allow_official):
    if same_path(path, root / OFFICIAL_TEST):
        if not allow_official:
            raise ValueError(
                "Reserved official test input is protected. --allow-official-test is required; evaluating it consumes the reserved benchmark. Subsequent model changes informed by these results invalidate its untouched-final-test status."
            )
        print(
            "WARNING: official test benchmark is being consumed; future result-informed changes invalidate untouched final-test status.",
            file=sys.stderr,
        )
    if same_path(path, root / DEFAULT_TRAIN):
        print(
            "WARNING: original training CSV includes fitting and validation records. These results are not independent test performance.",
            file=sys.stderr,
        )


def protect_output(path, source, model_path, root):
    path = Path(path)
    resolved = path.resolve()
    raw = (root / "data/raw").resolve()
    if resolved == raw or raw in resolved.parents:
        raise ValueError("Outputs must not be placed inside data/raw")
    if same_path(path, source) or same_path(path, model_path):
        raise ValueError("Output must not overwrite the input CSV or model artifact")


def csv_chunks(path, size, *, labeled=False):
    """Strict row-width validation preserves every record, including empty fields."""
    with Path(path).open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.reader(stream, strict=True)
        header = next(reader, None)
        if not header:
            raise ValueError(
                "Empty CSV: a header and at least one data record are required"
            )
        if len(set(header)) != len(header) or any(not name for name in header):
            raise ValueError("CSV column names must be nonempty and unique")
        required = set(RAW_FEATURES) | ({"category"} if labeled else set())
        if missing := required - set(header):
            raise ValueError(f"Missing required CSV columns: {sorted(missing)}")
        records, count = [], 0
        for row in reader:
            if len(row) != len(header):
                raise ValueError(
                    f"Malformed CSV near line {reader.line_num}: expected {len(header)} fields, got {len(row)}"
                )
            records.append(row)
            count += 1
            if len(records) == size:
                yield pd.DataFrame(records, columns=header)
                records = []
        if records:
            yield pd.DataFrame(records, columns=header)
        if count == 0:
            raise ValueError("CSV has a header but no data records")


def metrics_from_matrix(matrix):
    """At most 16 count-weighted cells yield exact full-file sklearn metrics."""
    actual, predicted = np.nonzero(matrix)
    weights = matrix[actual, predicted]
    names = np.array(TARGETS)
    y, p = names[actual], names[predicted]
    total = int(matrix.sum())
    supports = matrix.sum(axis=1)
    absent = [label for label, n in zip(TARGETS, supports, strict=True) if n == 0]
    report = (
        classification_report(
            y,
            p,
            labels=list(TARGETS),
            sample_weight=weights,
            zero_division=0,
            output_dict=True,
        )
        if total
        else {}
    )
    if total:
        precision, recall, f1, _ = precision_recall_fscore_support(
            y, p, labels=list(TARGETS), sample_weight=weights, zero_division=0
        )
    else:
        precision = recall = f1 = np.zeros(len(TARGETS))
    per_class = {
        label: {
            "precision": float(precision[i]) if total else None,
            "recall": float(recall[i]) if supports[i] else None,
            "f1": float(f1[i]) if total else None,
            "support": int(supports[i]),
        }
        for i, label in enumerate(TARGETS)
    }
    return {
        "class_order": list(TARGETS),
        "evaluated_records": total,
        "class_distribution": dict(zip(TARGETS, map(int, supports), strict=True)),
        "absent_classes": absent,
        "accuracy": float(accuracy_score(y, p, sample_weight=weights))
        if total
        else None,
        "balanced_accuracy": float(np.mean(recall[supports > 0])) if total else None,
        "balanced_accuracy_definition": "Mean recall over actual classes with nonzero support; absent classes are listed explicitly.",
        "macro_f1": float(
            f1_score(
                y,
                p,
                labels=list(TARGETS),
                average="macro",
                sample_weight=weights,
                zero_division=0,
            )
        )
        if total
        else None,
        "macro_f1_definition": "Fixed four-class macro; undefined class F1 contributes zero under zero_division=0. Incomplete coverage is not a complete four-class benchmark.",
        "weighted_f1": float(
            f1_score(
                y,
                p,
                labels=list(TARGETS),
                average="weighted",
                sample_weight=weights,
                zero_division=0,
            )
        )
        if total
        else None,
        "per_class": per_class,
        "classification_report_sklearn": report,
        "confusion_matrix": matrix.tolist(),
        "benign_false_positives": int(matrix[0, 1:].sum()),
        "benign_false_positive_rate": float(matrix[0, 1:].sum() / supports[0])
        if supports[0]
        else None,
    }


def publish_file(staged, target, overwrite):
    if overwrite:
        os.replace(staged, target)
    else:
        # Hard link publication fails atomically if an output already exists.
        os.link(staged, target)
        Path(staged).unlink()


def run_csv(args, model, root):
    source, output = args.input.resolve(), args.output.resolve()
    protect_output(output, source, args.model, root)
    if output.exists() and not args.overwrite:
        raise ValueError(f"Output exists: {output}; use --overwrite explicitly")
    labeled = args.command == "evaluate"
    filenames = [
        "metrics.json",
        "classification_report.csv",
        "confusion_matrix.csv",
        "predictions.csv",
        "summary.md",
    ]
    if labeled:
        if output.exists() and not output.is_dir():
            raise ValueError("Evaluation --output must be a directory")
        for filename in filenames:
            protect_output(output / filename, source, args.model, root)
    elif output.is_dir():
        raise ValueError("Prediction --output must be a CSV file, not a directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    total, excluded, matrix = (
        0,
        Counter(),
        np.zeros((len(TARGETS), len(TARGETS)), dtype=np.int64),
    )
    inference_seconds = 0.0
    with tempfile.TemporaryDirectory(
        prefix=".cyberguard_eval_", dir=output.parent
    ) as temp:
        temp = Path(temp)
        staged = temp / "predictions.csv"
        for chunk in csv_chunks(source, args.chunk_size, labeled=labeled):
            start = time.perf_counter()
            result = predict_frame(model, chunk, probabilities=args.probabilities)
            inference_seconds += time.perf_counter() - start
            if labeled:
                if set(chunk) & {"evaluation_status", "evaluation_label"}:
                    raise ValueError(
                        "Input collides with reserved evaluation_status/evaluation_label columns"
                    )
                labels = chunk.category.str.strip()
                eligible = labels.isin(TARGETS)
                excluded.update(labels[~eligible])
                if eligible.any():
                    matrix += confusion_matrix(
                        labels[eligible],
                        result.loc[eligible, "prediction"],
                        labels=list(TARGETS),
                    )
                result["evaluation_label"] = labels
                result["evaluation_status"] = np.where(
                    eligible, "evaluated", "excluded_unsupported"
                )
            result.to_csv(staged, mode="a", index=False, header=(total == 0))
            total += len(chunk)
        if not labeled:
            publish_file(staged, output, args.overwrite)
            print(f"Predicted {total:,} rows -> {output}")
            return
        if excluded and not args.exclude_unsupported:
            raise ValueError(
                f"Unsupported labels and counts: {dict(excluded)!r}. Theft is unsupported malicious traffic, never Normal. Use --exclude-unsupported explicitly to omit these rows from four-class metrics; all rows remain in predictions.csv."
            )
        metrics = metrics_from_matrix(matrix)
        metrics.update(
            {
                "model_path": str(args.model.resolve()),
                "model_sha256": sha256(args.model),
                "dataset_path": str(source),
                "evaluation_timestamp": datetime.now(
                    ZoneInfo("Asia/Kolkata")
                ).isoformat(),
                "total_input_records": total,
                "excluded_records": sum(excluded.values()),
                "excluded_by_label": dict(excluded),
                "inference_seconds": inference_seconds,
                "prediction_throughput_records_per_second": total / inference_seconds
                if inference_seconds
                else None,
                "throughput_scope": "All input rows including excluded labels; predict/predict_proba plus DataFrame formatting, excluding CSV disk I/O and model load.",
                "limitations": LIMITATIONS,
            }
        )
        (temp / "metrics.json").write_text(
            json.dumps(metrics, indent=2, allow_nan=False) + "\n"
        )
        pd.DataFrame(metrics["per_class"]).T.rename_axis("class").to_csv(
            temp / "classification_report.csv"
        )
        pd.DataFrame(matrix, index=TARGETS, columns=TARGETS).rename_axis(
            "actual / predicted"
        ).to_csv(temp / "confusion_matrix.csv")

        def display(value):
            return "undefined" if value is None else f"{value:.6f}"

        lines = [
            "# CyberGuard manual offline evaluation",
            "",
            f"Model: `{metrics['model_path']}`; SHA-256 `{metrics['model_sha256']}`.",
            f"Dataset: `{source}`. Timestamp: {metrics['evaluation_timestamp']}.",
            "",
            f"Input: {total}; evaluated: {metrics['evaluated_records']}; excluded: {sum(excluded.values())}.",
            f"Excluded by label: `{dict(excluded)}`. Unsupported inputs remain in predictions.csv with an explicit exclusion status.",
            "",
            "| Class | Support | Precision | Recall | F1 |",
            "| --- | --- | --- | --- | --- |",
            *[
                f"| {label} | {v['support']} | {display(v['precision'])} | {display(v['recall'])} | {display(v['f1'])} |"
                for label, v in metrics["per_class"].items()
            ],
            "",
            *[
                f"- {name}: {display(metrics[name])}"
                for name in [
                    "accuracy",
                    "balanced_accuracy",
                    "macro_f1",
                    "weighted_f1",
                    "benign_false_positive_rate",
                    "prediction_throughput_records_per_second",
                ]
            ],
            "",
            f"Absent classes: {', '.join(metrics['absent_classes']) or 'none'}. Missing class recall and no-Normal benign FPR are undefined (JSON null).",
            metrics["balanced_accuracy_definition"],
            metrics["macro_f1_definition"],
            metrics["throughput_scope"],
            "",
            "Confusion matrix order (actual rows / predicted columns): "
            + ", ".join(TARGETS)
            + ". See confusion_matrix.csv.",
            "",
            LIMITATIONS,
            "Manual/synthetic examples are software demonstrations, not independent generalization evidence. Evaluation never refits preprocessing, trains, tunes, or selects a model.",
        ]
        if same_path(source, root / DEFAULT_TRAIN):
            lines += [
                "",
                "WARNING: original training file contains fitting/validation records; this is not independent test performance.",
            ]
        if same_path(source, root / OFFICIAL_TEST):
            lines += [
                "",
                "WARNING: this evaluation consumes the reserved official test benchmark. Future result-informed changes invalidate its untouched final-test status.",
            ]
        (temp / "summary.md").write_text("\n".join(lines) + "\n")
        if not output.exists():
            temp.rename(output)
        else:
            for filename in filenames:
                os.replace(temp / filename, output / filename)
        print(
            f"Evaluated {metrics['evaluated_records']:,}; excluded {sum(excluded.values()):,}; macro-F1 {display(metrics['macro_f1'])}; benign FPR {display(metrics['benign_false_positive_rate'])}"
        )
        print("Class support: " + str(metrics["class_distribution"]))
        print(f"Reports -> {output}")


def interactive(model):
    print("CyberGuard Network Model Tester\nSupported classes: " + ", ".join(TARGETS))
    print(LIMITATIONS)
    try:
        while True:
            proto = input("Protocol [tcp/udp/icmp/ipv6-icmp/arp; q to exit]: ")
            if proto.strip().lower() in ("q", "quit", "exit"):
                return
            sport = input("Source port: ")
            dport = input("Destination port: ")
            try:
                frame = pd.DataFrame([{"proto": proto, "sport": sport, "dport": dport}])
                result = predict_frame(
                    model,
                    frame,
                    probabilities=callable(getattr(model, "predict_proba", None)),
                )
                print("Class: " + str(result.prediction.iloc[0]))
                for label in TARGETS:
                    if f"probability_{label}" in result:
                        print(
                            f"  {label}: {result[f'probability_{label}'].iloc[0]:.6f}"
                        )
                print(
                    "Probabilities are uncalibrated model estimates, not calibrated confidence."
                )
            except (ValueError, TypeError, OverflowError) as exc:
                print(f"Input rejected: {exc}. Please try again.")
                continue
            if input("Test another record? [Y/n]: ").strip().lower() in (
                "n",
                "no",
                "q",
                "quit",
                "exit",
            ):
                return
    except (EOFError, KeyboardInterrupt):
        print("\nExited.")


def parser(root=ROOT):
    result = argparse.ArgumentParser(
        description="Inspect and use the fitted CyberGuard offline network baseline. "
        + LIMITATIONS
    )
    subs = result.add_subparsers(dest="command", required=True)
    for name in ["interactive", "predict", "evaluate", "info"]:
        sub = subs.add_parser(name)
        sub.add_argument(
            "--model",
            type=Path,
            default=root / DEFAULT_MODEL,
            help="Trusted fitted joblib artifact; never refitted",
        )
        if name in ("predict", "evaluate"):
            sub.add_argument("--input", type=Path, required=True)
            sub.add_argument(
                "--output",
                type=Path,
                required=True,
                help="CSV file for predict; report directory for evaluate",
            )
            sub.add_argument("--chunk-size", type=positive_int, default=10000)
            sub.add_argument(
                "--probabilities",
                action="store_true",
                help="Add uncalibrated probability_<class> columns",
            )
            sub.add_argument(
                "--overwrite",
                action="store_true",
                help="Explicitly replace existing requested outputs",
            )
            sub.add_argument(
                "--allow-official-test",
                action="store_true",
                help="Acknowledge consuming the reserved official test benchmark",
            )
        if name == "evaluate":
            sub.add_argument(
                "--exclude-unsupported",
                action="store_true",
                help="Exclude unsupported labels from metrics; report their counts and preserve predictions",
            )
    return result


def main(argv=None, *, root=ROOT):
    args = parser(root).parse_args(argv)
    try:
        if args.command in ("predict", "evaluate"):
            protect_input(args.input, root, args.allow_official_test)
        model = load_model(
            args.model
        )  # once per invocation, including interactive loops
        if args.command == "info":
            print(json.dumps(inspect_model(model, args.model, root), indent=2))
        elif args.command == "interactive":
            interactive(model)
        else:
            print(LIMITATIONS, file=sys.stderr)
            run_csv(args, model, root)
        return 0
    except (ValueError, TypeError, OSError, csv.Error, OverflowError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
