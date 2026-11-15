"""Allowlisted startup registry and isolated adapters; no dataset access or fitting."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from cyberguard.core.model_schemas import (
    BoTPredictionRequest,
    NFCompletedFlowRecord,
    NFPredictionRequest,
)
from cyberguard.core.schemas import NetworkRecord
from cyberguard.features import nf_cse as nf
from cyberguard.inference.model_loader import load_network_detector, sha256
from cyberguard.inference.network_detector import WARNING as BOT_WARNING
from cyberguard.inference.nf_cse_model import NFCSEBinaryModel

logger = logging.getLogger(__name__)
BOT_ID = "bot_iot_restricted_baseline"
NF_ID = "nf_cse_binary_completed_flow"
# Explicitly versioned presentation configuration, checked against frozen evaluation.
MODE_CONFIG_VERSION = "nf-cse-frozen-operating-modes-v1"
NF_MODES = {"standard": 0.5, "high_sensitivity": 0.03090052128234102}
NF_LIMITATIONS = [
    "Completed bidirectional NetFlow-v1 statistics required; not packet, partial-flow or live detection.",
    "Scores are uncalibrated; a prediction does not establish attack occurrence or safety.",
    "Offline feature-group-disjoint evaluation does not establish independent capture/session/host/time generalization.",
    "Exporter orientation, accounting and timeout parity are unverified; Infilteration recall is poor and rare-family supports are limited.",
    "The sensitivity threshold exceeded the validation 1% benign FPR constraint on final test.",
]
METRICS = (
    "accuracy",
    "balanced_accuracy",
    "precision",
    "recall",
    "f1",
    "macro_f1",
    "benign_fpr",
    "roc_auc",
    "average_precision",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def metric_subset(metrics):
    return {k: metrics[k] for k in METRICS if k in metrics}


class BoTAdapter:
    request_type = BoTPredictionRequest

    def __init__(self, detector):
        self.detector = detector

    def predict(self, records, mode):
        require(mode == "default", "Unsupported operating mode")
        return [
            (r.prediction, r.probabilities, None)
            for r in self.detector.predict_batch(records)
        ]


class NFAdapter:
    request_type = NFPredictionRequest

    def __init__(self, model):
        self.model = model
        self.lock = Lock()

    def predict(self, records, mode):
        require(mode in NF_MODES, "Unsupported operating mode")
        frame = pd.DataFrame(records).loc[:, nf.RAW_FEATURES]
        with self.lock:
            probabilities = np.asarray(self.model.predict_proba(frame), dtype=float)
        require(
            probabilities.shape == (len(records), 2)
            and np.isfinite(probabilities).all()
            and np.all((probabilities >= 0) & (probabilities <= 1))
            and np.allclose(probabilities.sum(axis=1), 1),
            "Invalid model scores",
        )
        return [
            (
                "Attack" if p[1] >= NF_MODES[mode] else "Benign",
                {"Benign": float(p[0]), "Attack": float(p[1])},
                float(p[1]),
            )
            for p in probabilities
        ]


def load_nf(path, evaluation_dir):
    """Verify trusted local artifact and frozen metadata; never open dataset paths."""
    metadata = json.loads(path.with_suffix(".metadata.json").read_text())
    require(
        sha256(path) == metadata["artifact_sha256"], "NF artifact checksum mismatch"
    )
    manifest = json.loads((evaluation_dir / "evaluation_manifest.json").read_text())
    require(
        manifest["status"] == "complete" and manifest["model_metadata"] == metadata,
        "NF final evaluation/model metadata mismatch",
    )
    require(
        manifest["thresholds"]
        == {
            "high_sensitivity": NF_MODES["high_sensitivity"],
            "lower_false_alarm": NF_MODES["standard"],
        },
        "Frozen evaluation threshold mismatch",
    )
    identity = manifest["dataset_identity"]
    require(
        identity["source_sha256"] == metadata["source_dataset_sha256"]
        and manifest["inference_code_sha256"]
        == sha256(Path(__file__).with_name("nf_cse_model.py"))
        and identity["schema_version"] == nf.CONTRACT_VERSION
        and identity["preprocessing_version"] == nf.PREPROCESSING_VERSION
        and identity["implementation_sha256"]["nf_cse.py"] == sha256(nf.__file__),
        "NF preprocessing compatibility mismatch",
    )
    contract = nf.feature_contract()
    require(
        metadata["feature_contract_version"] == nf.CONTRACT_VERSION
        and metadata["preprocessing_version"] == nf.PREPROCESSING_VERSION
        and metadata["feature_order"] == list(nf.RAW_FEATURES)
        and metadata["encoded_feature_order"] == list(nf.MODEL_FEATURES)
        and metadata["class_mapping"] == {"0": "Benign", "1": "Attack"}
        and metadata["selected_threshold"] == NF_MODES["high_sensitivity"]
        and metadata["model_type"] == "hist_gradient_boosting"
        and metadata["model_id"] == NF_ID,
        "NF contract/class/threshold mismatch",
    )
    metrics_path = evaluation_dir / "test_metrics.json"
    require(
        sha256(metrics_path) == manifest["outputs"]["test_metrics.json"],
        "NF performance checksum mismatch",
    )
    test = json.loads(metrics_path.read_text())["thresholds"]
    for mode, key in (
        ("standard", "lower_false_alarm"),
        ("high_sensitivity", "high_sensitivity"),
    ):
        require(
            test[key]["threshold"] == NF_MODES[mode], "Test metric threshold mismatch"
        )
    # All metadata gates precede deserialization. joblib is trusted-local only.
    model = joblib.load(path)
    require(
        isinstance(model, NFCSEBinaryModel)
        and isinstance(model.estimator, HistGradientBoostingClassifier)
        and isinstance(model.normalizer, nf.NFCSECompletedFlowFeatures)
        and model.linear_transform is None,
        "NF artifact type mismatch",
    )
    for key in (
        "model_id",
        "model_type",
        "feature_contract_version",
        "preprocessing_version",
        "feature_order",
        "encoded_feature_order",
        "class_mapping",
        "selected_threshold",
        "source_dataset_sha256",
        "partition_manifest_sha256",
    ):
        require(
            model.metadata_.get(key) == metadata[key], "NF embedded metadata mismatch"
        )
    require(
        list(model.feature_names_in_) == list(nf.RAW_FEATURES)
        and list(model.classes_) == [0, 1]
        and list(model.estimator.classes_) == [0, 1]
        and model.threshold == NF_MODES["high_sensitivity"],
        "NF runtime contract mismatch",
    )
    adapter = NFAdapter(model)
    adapter.predict(
        [dict(zip(nf.RAW_FEATURES, [6, 49152, 443, 1200, 2400, 8, 12], strict=True))],
        "standard",
    )
    performance = {
        "validation": {
            "scope": "Historical selection-set results, not independent deployment evidence",
            "high_sensitivity": metric_subset(metadata["validation_metrics"]),
        },
        "final_test": {
            "scope": "Offline feature-group-disjoint final test; consumed benchmark, no reevaluation",
            **{
                mode: metric_subset(test[key])
                for mode, key in (
                    ("standard", "lower_false_alarm"),
                    ("high_sensitivity", "high_sensitivity"),
                )
            },
        },
    }
    return adapter, metadata["artifact_sha256"], contract, performance


class RegisteredModel:
    def __init__(
        self,
        model_id,
        display_name,
        description,
        task,
        artifact_path,
        record_type,
        contract_version,
        classes,
        modes,
        default_mode,
        limitations,
    ):
        self.model_id = model_id
        self.artifact_path = artifact_path  # private, never serialized
        self.record_type = record_type
        self.adapter = None
        self.public = {
            "id": model_id,
            "display_name": display_name,
            "description": description,
            "model_version": None,
            "task": task,
            "classes": classes,
            "required_features": list(record_type.model_fields),
            "input_contract_version": contract_version,
            "input_contract": {"raw_feature_order": list(record_type.model_fields)},
            "input_schema": record_type.model_json_schema(),
            "api_input_policy": "Every required field must be supplied. NF-CSE API rejects null/malformed values before the unchanged frozen pipeline; its offline normalizer also supports statuses. BoT retains its legacy scalar/null and status semantics.",
            "available_operating_modes": [
                {"id": name, "threshold": value} for name, value in modes.items()
            ],
            "default_operating_mode": default_mode,
            "operating_modes_version": MODE_CONFIG_VERSION
            if model_id == NF_ID
            else "bot-iot-default-v1",
            "limitations": limitations,
            "readiness": "unavailable",
            "performance_metadata": None,
        }
        self.modes = modes

    def metadata(self):
        # Return detached public data, never arbitrary artifact dictionaries/paths.
        return json.loads(json.dumps(self.public))

    def initialize(self, factory):
        try:
            adapter, version, contract, performance = factory()
            self.adapter = adapter
            self.public.update(
                model_version=f"sha256:{version}",
                input_contract=contract,
                performance_metadata=performance,
                readiness="ready",
            )
        except Exception as exc:  # noqa: BLE001 -- isolate optional model failures
            logger.error(
                "registered_model_unavailable model=%s error_type=%s",
                self.model_id,
                type(exc).__name__,
            )
            self.adapter = None

    def predict(self, records, mode):
        require(mode in self.modes, "Unsupported operating mode")
        # Defense in depth for direct adapter callers. Validate all before inference.
        validated = [
            self.record_type.model_validate(record).model_dump() for record in records
        ]
        require(bool(validated), "Empty batch")
        results = self.adapter.predict(validated, mode)
        require(len(results) == len(validated), "Prediction count mismatch")
        timestamp = datetime.now(UTC)
        return [
            {
                "model_id": self.model_id,
                "model_version": self.public["model_version"],
                "task": self.public["task"],
                "predicted_class": label,
                "positive_class_score": positive,
                "class_scores": scores,
                "operating_mode": mode,
                "applied_threshold": self.modes[mode],
                "input_contract_version": self.public["input_contract_version"],
                "inference_timestamp": timestamp,
                "limitations": self.public["limitations"],
            }
            for label, scores, positive in results
        ]


class ModelRegistry:
    def __init__(self, settings, project_root):
        self.entries = {
            BOT_ID: RegisteredModel(
                BOT_ID,
                "BoT-IoT restricted baseline",
                "Experimental protocol/port four-class classifier",
                "multiclass",
                settings.network_model_path,
                NetworkRecord,
                "bot-iot-header-v1",
                ["Normal", "DoS", "DDoS", "Reconnaissance"],
                {"default": None},
                "default",
                [
                    BOT_WARNING,
                    "Only 79 benign validation rows; offline group-disjoint validation is not independent-session generalization.",
                ],
            ),
            NF_ID: RegisteredModel(
                NF_ID,
                "NF-CSE completed-flow binary",
                "Binary classifier for finalized bidirectional NetFlow-v1 exports",
                "binary",
                settings.nf_cse_model_path,
                NFCompletedFlowRecord,
                nf.CONTRACT_VERSION,
                ["Benign", "Attack"],
                NF_MODES,
                "standard",
                NF_LIMITATIONS,
            ),
        }
        self.root = Path(project_root)
        self.settings = settings

    def load(self):
        self.entries[BOT_ID].initialize(self._load_bot)
        self.entries[NF_ID].initialize(
            lambda: load_nf(
                self.settings.nf_cse_model_path, self.settings.nf_cse_evaluation_dir
            )
        )

    def _load_bot(self):
        detector = load_network_detector(self.settings.network_model_path, self.root)
        version = detector.metadata()["artifact_sha256"]
        contract = {
            "schema_version": "bot-iot-header-v1",
            "raw_feature_order": ["proto", "sport", "dport"],
            "observation_contract": "Protocol and port fields only; no packet capture or live detection",
        }
        performance = None
        path = self.root / "reports/model_evaluation/bot_iot_validation_metrics.json"
        if path.exists():
            data = json.loads(path.read_text())
            if data.get("model_sha256") == version:
                require(
                    data["preprocessing_version"] == "bot-iot-header-v1",
                    "BoT preprocessing contract mismatch",
                )
                performance = {
                    "validation": {
                        "scope": "Historical offline group-disjoint validation; only 79 Normal records",
                        **{
                            k: data["evaluation"][k]
                            for k in (
                                "accuracy",
                                "macro_f1",
                                "weighted_f1",
                                "balanced_accuracy",
                                "classification_report",
                                "benign_false_positive_rate",
                                "benign_support",
                            )
                            if k in data["evaluation"]
                        },
                    }
                }
        return BoTAdapter(detector), version, contract, performance

    def close(self):
        for entry in self.entries.values():
            entry.adapter = None
            entry.public["readiness"] = "unavailable"
