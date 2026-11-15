"""Synthetic inference-only artifacts; no dataset access, training or test scoring."""

import json
from pathlib import Path

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import HistGradientBoostingClassifier

from cyberguard.api.main import create_app
from cyberguard.core.config import PROJECT_ROOT, Settings
from cyberguard.features import nf_cse as nf
from cyberguard.inference.model_loader import sha256
from cyberguard.inference.model_registry import BOT_ID, NF_ID, NF_MODES, NFAdapter
from cyberguard.inference.nf_cse_model import NFCSEBinaryModel

BOT = {"proto": "tcp", "sport": "3", "dport": "80"}
FLOW = dict(zip(nf.RAW_FEATURES, [6, 49152, 443, 500, 2400, 8, 12], strict=True))


class SyntheticNFEstimator(HistGradientBoostingClassifier):
    def __init__(self):
        super().__init__()
        self.classes_ = np.array([0, 1])
        self.fail = False
        self.calls = 0

    def fit(self, *args, **kwargs):
        raise AssertionError("No fitting permitted")

    def predict_proba(self, X):
        self.calls += 1
        if self.fail:
            raise ValueError("sensitive feature /private/secret.joblib")
        values = np.asarray(X)[:, 3]
        scores = np.array(
            [
                {
                    30: np.nextafter(NF_MODES["high_sensitivity"], 0),
                    31: NF_MODES["high_sensitivity"],
                    499: np.nextafter(0.5, 0),
                    500: 0.5,
                }.get(v, 0.9)
                for v in values
            ]
        )
        return np.column_stack([1 - scores, scores])


@pytest.fixture
def registry_settings(tmp_path, api_model_path, monkeypatch):
    modelpath = tmp_path / "nf.joblib"
    metadata = {
        "model_id": NF_ID,
        "model_type": "hist_gradient_boosting",
        "feature_contract_version": nf.CONTRACT_VERSION,
        "preprocessing_version": nf.PREPROCESSING_VERSION,
        "feature_order": list(nf.RAW_FEATURES),
        "encoded_feature_order": list(nf.MODEL_FEATURES),
        "class_mapping": {"0": "Benign", "1": "Attack"},
        "selected_threshold": NF_MODES["high_sensitivity"],
        "source_dataset_sha256": "fixture-source",
        "partition_manifest_sha256": "fixture-manifest",
        "validation_metrics": {"recall": 0.5},
    }
    model = NFCSEBinaryModel(
        SyntheticNFEstimator(),
        threshold=metadata["selected_threshold"],
        metadata=metadata.copy(),
    )
    joblib.dump(model, modelpath)
    metadata["artifact_sha256"] = sha256(modelpath)
    modelpath.with_suffix(".metadata.json").write_text(json.dumps(metadata))
    evaluation = tmp_path / "evaluation"
    evaluation.mkdir()
    (evaluation / "test_metrics.json").write_text(
        json.dumps(
            {
                "thresholds": {
                    "high_sensitivity": {
                        "threshold": NF_MODES["high_sensitivity"],
                        "recall": 0.5,
                    },
                    "lower_false_alarm": {"threshold": 0.5, "recall": 0.25},
                }
            }
        )
    )
    manifest = {
        "status": "complete",
        "model_metadata": metadata,
        "thresholds": {
            "high_sensitivity": NF_MODES["high_sensitivity"],
            "lower_false_alarm": 0.5,
        },
        "dataset_identity": {
            "source_sha256": "fixture-source",
            "schema_version": nf.CONTRACT_VERSION,
            "preprocessing_version": nf.PREPROCESSING_VERSION,
            "implementation_sha256": {"nf_cse.py": sha256(nf.__file__)},
        },
        "inference_code_sha256": sha256(
            PROJECT_ROOT / "src/cyberguard/inference/nf_cse_model.py"
        ),
        "outputs": {"test_metrics.json": sha256(evaluation / "test_metrics.json")},
    }
    (evaluation / "evaluation_manifest.json").write_text(json.dumps(manifest))
    original = Path.open

    def no_datasets(self, *args, **kwargs):
        assert not self.resolve().is_relative_to(PROJECT_ROOT / "data"), (
            "No real dataset access in API tests"
        )
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", no_datasets)

    def no_fit(*args, **kwargs):
        raise AssertionError("No preprocessing refit")

    monkeypatch.setattr(nf.NFCSECompletedFlowFeatures, "fit", no_fit)
    return Settings(
        network_model_path=api_model_path,
        nf_cse_model_path=modelpath,
        nf_cse_evaluation_dir=evaluation,
        max_batch_size=2,
        max_model_request_bytes=4096,
    )


@pytest.fixture
def client(registry_settings):
    with TestClient(create_app(registry_settings)) as client:
        yield client


def test_discovery_readiness_schemas_and_no_paths(client, registry_settings):
    response = client.get("/api/v1/models")
    assert response.status_code == 200
    models = {m["id"]: m for m in response.json()["models"]}
    assert set(models) == {BOT_ID, NF_ID}
    assert all(m["readiness"] == "ready" for m in models.values())
    assert str(registry_settings.nf_cse_model_path.parent) not in response.text
    nf_info = models[NF_ID]
    assert nf_info["classes"] == ["Benign", "Attack"]
    assert nf_info["required_features"] == list(nf.RAW_FEATURES)
    assert nf_info["input_schema"]["required"] == list(nf.RAW_FEATURES)
    assert nf_info["default_operating_mode"] == "standard"
    assert nf_info["available_operating_modes"] == [
        {"id": k, "threshold": v} for k, v in NF_MODES.items()
    ]
    for model in (BOT_ID, NF_ID):
        assert client.get(f"/api/v1/models/{model}/ready").status_code == 200
        assert client.get(f"/api/v1/models/{model}").json() == models[model]
    schema = client.get("/openapi.json").json()
    for name in ("BoTModelBatchRequest", "NFModelBatchRequest"):
        assert (
            schema["components"]["schemas"][name]["properties"]["records"]["maxItems"]
            == 2
        )
    assert client.get("/health/ready").status_code == 200


@pytest.mark.parametrize(
    "path,method,body",
    [
        ("/api/v1/models/nope", "get", None),
        ("/api/v1/models/nope/ready", "get", None),
        ("/api/v1/models/nope/predict", "post", {"record": FLOW}),
        ("/api/v1/models/nope/predict/batch", "post", {"records": [FLOW]}),
    ],
)
def test_unknown_model_is_structured_404(client, path, method, body):
    response = client.get(path) if method == "get" else client.post(path, json=body)
    assert (
        response.status_code == 404
        and response.json()["error"]["code"] == "unknown_model"
    )


def test_bot_preserves_legacy_scores_classes_and_schema(client):
    old = client.post("/api/v1/predict", json=BOT).json()
    response = client.post(f"/api/v1/models/{BOT_ID}/predict", json={"record": BOT})
    assert response.status_code == 200
    got = response.json()
    assert got["predicted_class"] == old["prediction"] == "DDoS"
    assert got["class_scores"] == old["probabilities"]
    assert list(got["class_scores"]) == ["Normal", "DoS", "DDoS", "Reconnaissance"]
    assert got["applied_threshold"] is None and got["operating_mode"] == "default"
    assert set(old) == {"prediction", "probabilities", "model", "warning"}
    assert client.get("/api/v1/model/info").json()["required_features"] == [
        "proto",
        "sport",
        "dport",
    ]
    for record in (
        BOT,
        {"proto": None, "sport": None, "dport": None},
        {"proto": "unknown", "sport": "bad", "dport": "70000"},
    ):
        assert (
            client.post(
                f"/api/v1/models/{BOT_ID}/predict", json={"record": record}
            ).status_code
            == 200
        )


@pytest.mark.parametrize(
    "value,mode,label",
    [
        (500, "standard", "Attack"),
        (499, "standard", "Benign"),
        (31, "high_sensitivity", "Attack"),
        (30, "high_sensitivity", "Benign"),
        (31, "standard", "Benign"),
    ],
)
def test_nf_frozen_decision_boundaries(client, value, mode, label):
    response = client.post(
        f"/api/v1/models/{NF_ID}/predict",
        json={"record": FLOW | {"IN_BYTES": value}, "operating_mode": mode},
    )
    assert response.status_code == 200
    got = response.json()
    assert got["predicted_class"] == label
    assert got["applied_threshold"] == NF_MODES[mode]
    assert got["positive_class_score"] == got["class_scores"]["Attack"]
    assert list(got["class_scores"]) == ["Benign", "Attack"]
    assert got["model_id"] == NF_ID and got["task"] == "binary"
    assert got["input_contract_version"] == nf.CONTRACT_VERSION
    assert "uncalibrated" in got["score_semantics"].lower()
    assert got["inference_timestamp"].endswith("Z")
    assert (
        client.app.state.registry.entries[NF_ID].adapter.model.threshold
        == NF_MODES["high_sensitivity"]
    )


def test_nf_default_standard_and_ordered_batch(client):
    single = client.post(
        f"/api/v1/models/{NF_ID}/predict", json={"record": FLOW | {"IN_BYTES": 31}}
    ).json()
    assert (
        single["operating_mode"] == "standard" and single["predicted_class"] == "Benign"
    )
    response = client.post(
        f"/api/v1/models/{NF_ID}/predict/batch",
        json={"records": [FLOW | {"IN_BYTES": 499}, FLOW]},
    )
    assert response.status_code == 200
    assert [p["predicted_class"] for p in response.json()["predictions"]] == [
        "Benign",
        "Attack",
    ]
    assert response.json()["count"] == 2
    response = client.post(
        f"/api/v1/models/{BOT_ID}/predict/batch",
        json={"records": [BOT, BOT | {"sport": "1"}]},
    )
    assert [p["predicted_class"] for p in response.json()["predictions"]] == [
        "DDoS",
        "Normal",
    ]


@pytest.mark.parametrize(
    "feature,value",
    [
        ("PROTOCOL", "garbage"),
        ("PROTOCOL", 256),
        ("PROTOCOL", None),
        ("L4_SRC_PORT", 65536),
        ("L4_DST_PORT", "bad"),
        ("L4_DST_PORT", None),
        ("IN_BYTES", -1),
        ("OUT_BYTES", "inf"),
        ("IN_PKTS", 1.2),
        ("OUT_PKTS", True),
        ("IN_BYTES", 2**53),
        ("IN_BYTES", ""),
        ("IN_BYTES", "NA"),
    ],
)
def test_invalid_nf_values_rejected_before_inference(client, feature, value):
    estimator = client.app.state.registry.entries[NF_ID].adapter.model.estimator
    before = estimator.calls
    response = client.post(
        f"/api/v1/models/{NF_ID}/predict", json={"record": FLOW | {feature: value}}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert estimator.calls == before


@pytest.mark.parametrize(
    "payload",
    [
        {"record": BOT},
        {"record": {k: v for k, v in FLOW.items() if k != "IN_BYTES"}},
        {"record": FLOW | {"Label": 1}},
        {"record": FLOW, "operating_mode": "magic"},
        {"record": FLOW, "threshold": 0.2},
        {"records": [FLOW]},
    ],
)
def test_nf_wrong_contract_and_modes(client, payload):
    assert (
        client.post(f"/api/v1/models/{NF_ID}/predict", json=payload).status_code == 422
    )
    assert (
        client.post(
            f"/api/v1/models/{BOT_ID}/predict", json={"record": FLOW}
        ).status_code
        == 422
    )


@pytest.mark.parametrize(
    "records", [[], [FLOW] * 3, [FLOW, FLOW | {"OUT_BYTES": -1}], [FLOW, BOT]]
)
def test_batch_all_or_nothing_validation(client, records):
    estimator = client.app.state.registry.entries[NF_ID].adapter.model.estimator
    before = estimator.calls
    assert (
        client.post(
            f"/api/v1/models/{NF_ID}/predict/batch", json={"records": records}
        ).status_code
        == 422
    )
    assert estimator.calls == before


def test_request_byte_limit_including_chunked_input(client):
    body = json.dumps({"record": FLOW | {"PROTOCOL": "x" * 5000}})
    for content in (body, iter([body[:2000].encode(), body[2000:].encode()])):
        response = client.post(
            f"/api/v1/models/{NF_ID}/predict",
            content=content,
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "request_too_large"


@pytest.mark.parametrize("missing", ["bot", "nf"])
def test_partial_availability(registry_settings, missing):
    path = (
        registry_settings.network_model_path
        if missing == "bot"
        else registry_settings.nf_cse_model_path
    )
    path.unlink()
    with TestClient(create_app(registry_settings)) as client:
        bad, good = (BOT_ID, NF_ID) if missing == "bot" else (NF_ID, BOT_ID)
        assert client.get("/health").status_code == 200
        assert client.get("/health/ready").status_code == (
            503 if missing == "bot" else 200
        )
        assert client.get(f"/api/v1/models/{bad}").json()["readiness"] == "unavailable"
        assert client.get(f"/api/v1/models/{bad}/ready").status_code == 503
        assert client.get(f"/api/v1/models/{good}/ready").status_code == 200
        response = client.post(
            f"/api/v1/models/{good}/predict",
            json={"record": FLOW if good == NF_ID else BOT},
        )
        assert response.status_code == 200
        assert (
            client.post(
                f"/api/v1/models/{bad}/predict",
                json={"record": FLOW if bad == NF_ID else BOT},
            ).status_code
            == 503
        )


@pytest.mark.parametrize(
    "corruption",
    [
        "bytes",
        "missing_metadata",
        "contract",
        "classes",
        "threshold",
        "manifest",
        "performance",
    ],
)
def test_nf_artifact_incompatibility_is_isolated(registry_settings, corruption):
    path = registry_settings.nf_cse_model_path
    metadata_path = path.with_suffix(".metadata.json")
    if corruption == "bytes":
        with path.open("ab") as f:
            f.write(b"bad")
    elif corruption == "missing_metadata":
        metadata_path.unlink()
    elif corruption in ("contract", "classes", "threshold"):
        metadata = json.loads(metadata_path.read_text())
        key, value = {
            "contract": ("feature_contract_version", "wrong"),
            "classes": ("class_mapping", {"0": "Attack", "1": "Benign"}),
            "threshold": ("selected_threshold", 0.2),
        }[corruption]
        metadata[key] = value
        metadata_path.write_text(json.dumps(metadata))
    elif corruption == "manifest":
        (
            registry_settings.nf_cse_evaluation_dir / "evaluation_manifest.json"
        ).write_text("{}")
    else:
        (registry_settings.nf_cse_evaluation_dir / "test_metrics.json").write_text("{}")
    with TestClient(create_app(registry_settings)) as client:
        assert client.get(f"/api/v1/models/{NF_ID}/ready").status_code == 503
        assert client.get("/health/ready").status_code == 200


def test_one_deserialization_per_model_reuse_and_no_mutation(
    registry_settings, monkeypatch
):
    original = joblib.load
    calls = []

    def load(path):
        calls.append(Path(path))
        return original(path)

    monkeypatch.setattr(joblib, "load", load)
    paths = [
        registry_settings.network_model_path,
        registry_settings.nf_cse_model_path,
        registry_settings.nf_cse_model_path.with_suffix(".metadata.json"),
    ]
    before = [sha256(p) for p in paths]
    app = create_app(registry_settings)
    with TestClient(app) as client:
        assert calls == paths[:2]
        for _ in range(3):
            assert (
                client.post(
                    f"/api/v1/models/{NF_ID}/predict", json={"record": FLOW}
                ).status_code
                == 200
            )
            assert client.post("/api/v1/predict", json=BOT).status_code == 200
        assert calls == paths[:2]
        nf_model = app.state.registry.entries[NF_ID].adapter.model
        nf_model.estimator.fail = True
        response = client.post(f"/api/v1/models/{NF_ID}/predict", json={"record": FLOW})
        assert response.status_code == 500
        assert "sensitive" not in response.text and "/private/" not in response.text
    assert [sha256(p) for p in paths] == before
    assert app.state.detector is None
    assert all(m.adapter is None for m in app.state.registry.entries.values())


def test_adapter_rejects_malformed_scores():
    class BadModel:
        def predict_proba(self, frame):
            return np.array([[float("nan"), 0.8]])

    with pytest.raises(ValueError, match="scores"):
        NFAdapter(BadModel()).predict([FLOW], "standard")


def test_nf_normalization_matches_saved_pipeline(client):
    record = FLOW | {
        "PROTOCOL": " TCP ",
        "L4_SRC_PORT": "0xc000",
        "IN_BYTES": "5e2",
        "OUT_PKTS": 0,
    }
    got = client.post(f"/api/v1/models/{NF_ID}/predict", json={"record": record}).json()
    model = client.app.state.registry.entries[NF_ID].adapter.model
    import pandas as pd

    expected = model.predict_proba(pd.DataFrame([record]))[0, 1]
    assert got["positive_class_score"] == expected
    for values in (
        {"PROTOCOL": "icmp", "L4_SRC_PORT": "-", "L4_DST_PORT": -1},
        {"PROTOCOL": 250},
    ):
        assert (
            client.post(
                f"/api/v1/models/{NF_ID}/predict", json={"record": FLOW | values}
            ).status_code
            == 200
        )


@pytest.mark.parametrize(
    "corruption", ["features", "classes", "runtime_threshold", "normalizer"]
)
def test_runtime_contract_rejected_even_when_artifact_checksums_match(
    registry_settings, corruption
):
    path = registry_settings.nf_cse_model_path
    model = joblib.load(path)
    if corruption == "features":
        model.feature_names_in_ = np.array(["wrong"] * 7)
    elif corruption == "classes":
        model.estimator.classes_ = np.array([1, 0])
    elif corruption == "runtime_threshold":
        model.threshold = 0.2
    else:
        model.normalizer = None
    joblib.dump(model, path)
    metadata_path = path.with_suffix(".metadata.json")
    metadata = json.loads(metadata_path.read_text())
    metadata["artifact_sha256"] = sha256(path)
    metadata_path.write_text(json.dumps(metadata))
    manifest_path = registry_settings.nf_cse_evaluation_dir / "evaluation_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["model_metadata"] = metadata
    manifest_path.write_text(json.dumps(manifest))
    with TestClient(create_app(registry_settings)) as client:
        assert client.get(f"/api/v1/models/{NF_ID}/ready").status_code == 503
        assert client.get("/health/ready").status_code == 200


def test_new_environment_settings(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERGUARD_NF_CSE_MODEL_PATH", str(tmp_path / "trusted.joblib"))
    monkeypatch.setenv("CYBERGUARD_NF_CSE_EVALUATION_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("CYBERGUARD_MAX_MODEL_REQUEST_BYTES", "2048")
    settings = Settings.from_env()
    assert settings.nf_cse_model_path == tmp_path / "trusted.joblib"
    assert settings.nf_cse_evaluation_dir == tmp_path / "reports"
    assert settings.max_model_request_bytes == 2048
    for value in ("0", "-1", "bad"):
        monkeypatch.setenv("CYBERGUARD_MAX_MODEL_REQUEST_BYTES", value)
        with pytest.raises(ValueError, match="CYBERGUARD_MAX_MODEL_REQUEST_BYTES"):
            Settings.from_env()
