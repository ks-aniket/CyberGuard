"""HTTP integration using synthetic local artifacts, without datasets or fitting."""

import pytest
from fastapi.testclient import TestClient

from cyberguard.api.main import create_app
from cyberguard.core.config import Settings
from cyberguard.inference.model_loader import sha256


@pytest.fixture
def application(api_model_path):
    return create_app(Settings(network_model_path=api_model_path, max_batch_size=2))


@pytest.fixture
def client(application):
    with TestClient(application) as client:
        yield client


def test_startup_readiness_health_and_shutdown_without_request_inference(application):
    assert application.state.detector is None
    with TestClient(application) as client:
        model = application.state.detector._model
        calls = model.predict_calls
        assert client.get("/health").json() == {
            "status": "ok",
            "service": "cyberguard-api",
        }
        assert client.get("/health/ready").json() == {
            "status": "ready",
            "model_loaded": True,
        }
        assert model.predict_calls == calls
    assert application.state.detector is None


def test_missing_model_fails_startup(tmp_path):
    application = create_app(Settings(network_model_path=tmp_path / "missing.joblib"))
    with (
        pytest.raises(RuntimeError, match="Unable to initialize"),
        TestClient(application),
    ):
        pass


def test_model_info_and_swagger_do_not_leak_local_paths(client, api_model_path):
    response = client.get("/api/v1/model/info")
    assert response.status_code == 200
    info = response.json()
    assert info["required_features"] == ["proto", "sport", "dport"]
    assert info["supported_classes"] == ["Normal", "DoS", "DDoS", "Reconnaissance"]
    assert info["model"] == "fixture_network"
    assert info["artifact_sha256"] == sha256(api_model_path)
    assert info["preprocessing_contract_version"] is None
    assert str(api_model_path) not in response.text
    assert "model_path" not in info
    assert client.get("/docs").status_code == 200
    schema = client.get("/openapi.json").json()
    batch = schema["components"]["schemas"]["BatchPredictionRequest"]["properties"][
        "records"
    ]
    assert batch["minItems"] == 1 and batch["maxItems"] == 2


def test_single_and_batch_predictions_are_real_and_ordered(client):
    response = client.post(
        "/api/v1/predict", json={"proto": "tcp", "sport": "3", "dport": "80"}
    )
    assert response.status_code == 200
    result = response.json()
    assert result["prediction"] == "DDoS"
    assert result["probabilities"] == {
        "Normal": 0,
        "DoS": 0,
        "DDoS": 1,
        "Reconnaissance": 0,
    }
    assert "uncalibrated" in result["warning"]
    response = client.post(
        "/api/v1/predict/batch",
        json={
            "records": [
                {"proto": "udp", "sport": "4", "dport": "53"},
                {"proto": 6, "sport": 1, "dport": 80},
            ]
        },
    )
    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert [r["prediction"] for r in response.json()["predictions"]] == [
        "Reconnaissance",
        "Normal",
    ]
    assert client.app.state.detector._model.batch_lengths == [2, 1, 2]


@pytest.mark.parametrize(
    "record",
    [
        {"proto": " TCP ", "sport": "0x50", "dport": "080"},
        {"proto": 6, "sport": 0, "dport": 65535},
        {"proto": "icmp", "sport": "0x0303", "dport": "-1"},
        {"proto": "arp", "sport": -1, "dport": "-"},
        {"proto": None, "sport": None, "dport": None},
        {"proto": "unknown", "sport": "not-a-number", "dport": "70000"},
    ],
)
def test_supported_contract_tokens_are_not_structural_errors(client, record):
    assert client.post("/api/v1/predict", json=record).status_code == 200


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"proto": "tcp", "sport": "1"},
        {"proto": "tcp", "sport": "1", "dport": "80", "saddr": "secret"},
        {"proto": True, "sport": 1, "dport": 80},
        {"proto": "tcp", "sport": True, "dport": 80},
        {"proto": "tcp", "sport": 80.0, "dport": 80},
        {"proto": [], "sport": 1, "dport": 80},
        {"proto": "tcp", "sport": {}, "dport": 80},
        [],
        None,
        {
            "proto": "tcp",
            "sport": 1,
            "dport": 80,
            "model_path": "/private/secret.joblib",
        },
    ],
)
def test_bad_schemas_return_consistent_errors(client, record):
    response = client.post("/api/v1/predict", json=record)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert "/private/secret.joblib" not in response.text
    for detail in response.json()["error"].get("details", []):
        assert set(detail) == {"location", "type", "message"}


@pytest.mark.parametrize(
    "payload",
    [
        {"records": []},
        {"records": [{"proto": "tcp", "sport": 1, "dport": 80}] * 3},
        {"records": [{"proto": "tcp", "sport": 1}]},
        {"records": [], "extra": "no"},
    ],
)
def test_empty_oversized_and_invalid_batches(client, payload):
    before = client.app.state.detector._model.predict_calls
    response = client.post("/api/v1/predict/batch", json=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert client.app.state.detector._model.predict_calls == before


def test_invalid_json_and_not_found(client):
    response = client.post(
        "/api/v1/predict", content="{bad", headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert client.get("/not-a-route").json()["error"]["code"] == "http_error"


def test_model_unavailable_and_inference_failure_are_non_success(client, caplog):
    detector = client.app.state.detector
    detector._model.fail = True
    response = client.post(
        "/api/v1/predict", json={"proto": "tcp", "sport": 1, "dport": 80}
    )
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "inference_failed", "message": "Network prediction failed"}
    }
    assert "sensitive feature" not in response.text + caplog.text
    assert "/private/model.joblib" not in response.text + caplog.text
    client.app.state.detector = None
    for path in ["/health/ready", "/api/v1/model/info"]:
        response = client.get(path)
        assert (
            response.status_code == 503
            and response.json()["error"]["code"] == "model_unavailable"
        )
    response = client.post(
        "/api/v1/predict", json={"proto": "tcp", "sport": 1, "dport": 80}
    )
    assert response.status_code == 503
    assert client.get("/health").status_code == 200


def test_one_load_across_requests_no_refit_no_model_changes(
    api_model_path, monkeypatch, caplog
):
    import cyberguard.inference.model_loader as loader

    original = loader.joblib.load
    loads = []

    def load(path):
        loads.append(path)
        return original(path)

    monkeypatch.setattr(loader.joblib, "load", load)
    before = sha256(api_model_path)
    application = create_app(Settings(network_model_path=api_model_path))
    assert not loads
    with TestClient(application) as client:
        assert len(loads) == 1
        original_detector = application.state.detector
        for _ in range(3):
            assert (
                client.post(
                    "/api/v1/predict",
                    json={"proto": "tcp", "sport": "1", "dport": "80"},
                ).status_code
                == 200
            )
        assert len(loads) == 1
        assert application.state.detector is original_detector
        assert "prediction_request count=3 batch_size=1" in caplog.text
    assert sha256(api_model_path) == before
    assert (
        "application_startup" in caplog.text and "application_shutdown" in caplog.text
    )
