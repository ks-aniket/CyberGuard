"""Load historical report artifacts only; never open a model or raw dataset."""

import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class ReportError(ValueError):
    pass


@dataclass(frozen=True)
class ValidationReport:
    evaluation: dict
    per_class: pd.DataFrame
    confusion: pd.DataFrame
    model_sha256: str

    @property
    def total(self):
        return int(self.confusion.to_numpy().sum())


def load_validation(root=PROJECT_ROOT):
    directory = root / "reports/model_evaluation"
    try:
        metrics = json.loads(
            (directory / "bot_iot_validation_metrics.json").read_text()
        )
        with (directory / "bot_iot_validation_confusion.csv").open(
            newline=""
        ) as stream:
            rows = list(csv.reader(stream, strict=True))
        evaluation = metrics["evaluation"]
        labels = evaluation["class_order"]
        if (
            not isinstance(labels, list)
            or len(labels) != 4
            or set(labels)
            != {
                "Normal",
                "DoS",
                "DDoS",
                "Reconnaissance",
            }
        ):
            raise ValueError("classes")
        if (
            len(rows) != 5
            or rows[0] != ["actual / predicted", *labels]
            or any(len(r) != 5 for r in rows[1:])
            or [r[0] for r in rows[1:]] != labels
        ):
            raise ValueError("matrix labels")
        counts = [[int(v) for v in row[1:]] for row in rows[1:]]
        if (
            any(v < 0 for row in counts for v in row)
            or counts != evaluation["confusion_matrix"]
        ):
            raise ValueError("matrix counts")
        per_class = pd.DataFrame(
            [evaluation["per_class"][label] for label in labels], index=labels
        )
        for name in ("macro_f1", "balanced_accuracy", "benign_false_positive_rate"):
            v = evaluation[name]
            if type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1:
                raise ValueError("metrics")
        for index, row in enumerate(counts):
            if sum(row) != per_class.iloc[index]["support"] or sum(row) <= 0:
                raise ValueError("support")
            for name in ("precision", "recall", "f1-score"):
                v = per_class.iloc[index][name]
                if not math.isfinite(v) or not 0 <= v <= 1:
                    raise ValueError("per-class metrics")
        normal = labels.index("Normal")
        benign_support = sum(counts[normal])
        false_positives = benign_support - counts[normal][normal]
        if (
            evaluation["benign_support"] != benign_support
            or evaluation["benign_false_positives"] != false_positives
            or not math.isclose(
                evaluation["benign_false_positive_rate"],
                false_positives / benign_support,
            )
        ):
            raise ValueError("benign denominator")
        return ValidationReport(
            evaluation,
            per_class,
            pd.DataFrame(counts, index=labels, columns=labels),
            metrics["model_sha256"],
        )
    except FileNotFoundError:
        raise ReportError(
            "Historical validation artifacts are missing. Restore the existing metrics JSON and confusion CSV under reports/model_evaluation; inference is not required."
        ) from None
    except (OSError, ValueError, TypeError, KeyError, IndexError, csv.Error):
        raise ReportError(
            "Historical validation artifacts are unreadable or inconsistent. Check the saved JSON and confusion CSV; metrics have not been regenerated."
        ) from None


@dataclass(frozen=True)
class FinalReport:
    metrics: dict
    families: pd.DataFrame
    figures: dict[str, str]
    model_sha256: str


def load_nf_final(root=PROJECT_ROOT, *, expected_version=None):
    """Read and verify only a fixed allowlist of published evaluation artifacts."""
    import hashlib

    directory = root / "reports/model_evaluation/nf_cse_binary/final_test"
    try:
        manifest = json.loads((directory / "evaluation_manifest.json").read_text())
        if manifest["status"] != "complete":
            raise ValueError("Incomplete report")
        digest = manifest["model_metadata"]["artifact_sha256"]
        if expected_version is not None and expected_version != "sha256:" + digest:
            raise ValueError("Report model mismatch")

        def checked(name):
            path = directory / name
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != manifest["outputs"][name]:
                raise ValueError("Report checksum mismatch")
            return data

        metrics = json.loads(checked("test_metrics.json"))["thresholds"]
        import io

        families = pd.read_csv(io.BytesIO(checked("attack_family_recall.csv")))
        required_family_columns = {
            "attack_family",
            "mode",
            "recall",
            "original_records",
        }
        if not required_family_columns.issubset(families.columns):
            raise ValueError("Incomplete family metadata")
        for mode in ("high_sensitivity", "lower_false_alarm"):
            value = metrics[mode]
            if value["threshold"] != manifest["thresholds"][mode] or value[
                "confusion_order"
            ] != ["Benign", "Attack"]:
                raise ValueError("Metric contract mismatch")
            for metric in (
                "recall",
                "benign_fpr",
                "precision",
                "f1",
                "roc_auc",
                "average_precision",
            ):
                if not math.isfinite(value[metric]) or not 0 <= value[metric] <= 1:
                    raise ValueError("Invalid metric")
        figures = {}
        for name in ("roc", "precision_recall", "family_recall"):
            relative = "figures/" + name + ".svg"
            if relative in manifest["outputs"] and (directory / relative).exists():
                figures[name] = checked(relative).decode("utf-8")
        return FinalReport(metrics, families, figures, digest)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        raise ReportError(
            "Frozen NF-CSE performance artifacts are missing, inconsistent or do not match the selected model. Restore the published report; no metrics have been regenerated."
        ) from None
