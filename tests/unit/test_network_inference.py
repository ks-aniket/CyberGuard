"""Framework-independent model loading, compatibility and inference contracts."""

import json

import joblib
import numpy as np
import pytest

from cyberguard.core.config import DEFAULT_MODEL, PROJECT_ROOT, Settings
from cyberguard.inference.model_loader import (
    load_network_detector,
    sha256,
)
from cyberguard.inference.network_detector import InferenceError


def test_load_once_probe_and_unchanged_artifact(api_model_path, tmp_path, monkeypatch):
    import cyberguard.inference.model_loader as loader

    original = loader.joblib.load
    calls = []

    def tracked(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(loader.joblib, "load", tracked)
    before = sha256(api_model_path)
    detector = load_network_detector(api_model_path, tmp_path)
    assert len(calls) == 1
    assert detector._model.predict_calls == 1  # one startup compatibility batch
    result = detector.predict_one({"proto": "tcp", "sport": "3", "dport": "80"})
    assert result.prediction == "DDoS"
    assert result.probabilities == {
        "Normal": 0,
        "DoS": 0,
        "DDoS": 1,
        "Reconnaissance": 0,
    }
    assert len(calls) == 1
    assert sha256(api_model_path) == before
    assert not any(
        "/" in str(v)
        for v in detector.metadata().values()
        if isinstance(v, str) and v != detector.metadata()["model_type"]
    )


def test_missing_and_invalid_artifacts_fail_clearly(tmp_path):
    for path in [
        tmp_path / "missing.joblib",
        tmp_path / "corrupt.joblib",
        tmp_path / "not_model.joblib",
    ]:
        if path.name == "corrupt.joblib":
            path.write_text("corrupt")
        if path.name == "not_model.joblib":
            joblib.dump({"no": "predict"}, path)
        with pytest.raises(RuntimeError, match="Unable to initialize network model"):
            load_network_detector(path, tmp_path)


@pytest.mark.parametrize(
    "mutation", ["features", "classes", "unfitted", "bad_probabilities"]
)
def test_incompatible_artifact_rejected_at_startup(tmp_path, synthetic_model, mutation):
    if mutation == "features":
        synthetic_model.feature_names_in_ = np.array(["saddr", "sport", "dport"])
    if mutation == "classes":
        synthetic_model.classes_ = np.array(["Normal", "Theft"])
    if mutation == "unfitted":
        synthetic_model.fail = True
    if mutation == "bad_probabilities":
        synthetic_model.classes_ = np.array(["Normal", "DoS", "DDoS", "Theft"])
    path = tmp_path / "bad.joblib"
    joblib.dump(synthetic_model, path)
    with pytest.raises(RuntimeError):
        load_network_detector(path, tmp_path)


def test_batch_order_probability_alignment_and_no_refit(api_model_path, tmp_path):
    model = load_network_detector(api_model_path, tmp_path)
    result = model.predict_batch(
        [{"proto": "udp", "sport": str(i), "dport": "0x50"} for i in [4, 1, 2, 3]]
    )
    assert [r.prediction for r in result] == ["Reconnaissance", "Normal", "DoS", "DDoS"]
    assert result[0].probabilities["Reconnaissance"] == 1
    assert model._model.batch_lengths == [2, 4]
    assert len(model.supported_classes()) == 4
    with pytest.raises(ValueError, match="empty"):
        model.predict_batch([])
    model._model.fail = True
    with pytest.raises(InferenceError):
        model.predict_one({"proto": "tcp", "sport": 1, "dport": 80})


def test_optional_probabilities_and_unavailable_metadata(tmp_path, synthetic_model):
    synthetic_model.predict_proba = None
    path = tmp_path / "no_proba.joblib"
    joblib.dump(synthetic_model, path)
    detector = load_network_detector(path, tmp_path)
    assert (
        detector.predict_one(
            {"proto": "tcp", "sport": "1", "dport": "80"}
        ).probabilities
        is None
    )
    assert detector.metadata()["preprocessing_contract_version"] is None
    metadata = detector.metadata()
    metadata["required_features"].append("saddr")
    assert "saddr" not in detector.metadata()["required_features"]


def test_contract_metadata_requires_matching_model_hash(api_model_path, tmp_path):
    metadata = tmp_path / "reports/model_evaluation/bot_iot_validation_metrics.json"
    metadata.parent.mkdir(parents=True)
    metadata.write_text(
        json.dumps({"model_sha256": "wrong", "preprocessing_version": "bogus"})
    )
    assert (
        load_network_detector(api_model_path, tmp_path).metadata()[
            "preprocessing_contract_version"
        ]
        is None
    )
    metadata.write_text(
        json.dumps(
            {
                "model_sha256": sha256(api_model_path),
                "preprocessing_version": "fixture-v1",
            }
        )
    )
    assert (
        load_network_detector(api_model_path, tmp_path).metadata()[
            "preprocessing_contract_version"
        ]
        == "fixture-v1"
    )


def test_default_and_relative_config_paths_ignore_working_directory(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    assert Settings.from_env().network_model_path == DEFAULT_MODEL
    monkeypatch.setenv("CYBERGUARD_NETWORK_MODEL_PATH", "models/other.joblib")
    assert (
        Settings.from_env().network_model_path == PROJECT_ROOT / "models/other.joblib"
    )
    monkeypatch.setenv("CYBERGUARD_NETWORK_MODEL_PATH", str(tmp_path / "model.joblib"))
    assert Settings.from_env().network_model_path == tmp_path / "model.joblib"


@pytest.mark.parametrize(
    "variable,value",
    [
        ("CYBERGUARD_API_PORT", "0"),
        ("CYBERGUARD_API_PORT", "65536"),
        ("CYBERGUARD_API_PORT", "abc"),
        ("CYBERGUARD_MAX_BATCH_SIZE", "0"),
        ("CYBERGUARD_LOG_LEVEL", "invalid"),
        ("CYBERGUARD_API_HOST", " "),
    ],
)
def test_invalid_environment_fails(variable, value, monkeypatch):
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match=variable):
        Settings.from_env()
