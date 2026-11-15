"""Small HTTP/report fixtures test the UI boundary, never detection quality."""

import ast
import csv
import io
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from cyberguard.core.schemas import PredictionResponse
from cyberguard.dashboard import batch
from cyberguard.dashboard.api_client import APIClient, APIError, Connection
from cyberguard.dashboard.components import charts
from cyberguard.dashboard.report_loader import ReportError, load_validation

ROOT = Path(__file__).resolve().parents[2]
LABELS = ["Normal", "DoS", "DDoS", "Reconnaissance"]
RECORD = {"proto": "tcp", "sport": "0x50", "dport": None}
INFO = {
    "model": "fixture",
    "model_type": "fixture-type",
    "required_features": ["proto", "sport", "dport"],
    "supported_classes": LABELS,
    "probabilities_available": True,
    "artifact_sha256": "a" * 64,
    "preprocessing_contract_version": "fixture-v1",
    "warning": "Experimental software fixture, not a security evaluation.",
}


def prediction(label="Normal", probabilities=True):
    return {
        "prediction": label,
        "model": "fixture",
        "warning": INFO["warning"],
        "probabilities": {c: float(c == label) for c in LABELS}
        if probabilities
        else None,
    }


class FakeHTTP:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, request, timeout):
        self.calls.append((request.full_url, request.data, timeout))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return io.BytesIO(
            value if isinstance(value, bytes) else json.dumps(value).encode()
        )


def connection_responses(limit=2):
    return [
        {"status": "ok", "service": "cyberguard-api"},
        {"status": "ready", "model_loaded": True},
        INFO,
        {
            "paths": {
                "/api/v1/predict/batch": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Batch"}
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {"Batch": {"properties": {"records": {"maxItems": limit}}}}
            },
        },
    ]


def test_connection_metadata_and_actual_openapi_limit(monkeypatch):
    monkeypatch.setenv("CYBERGUARD_API_URL", "http://example.test:8123/")
    http = FakeHTTP(connection_responses(7))
    result = APIClient(opener=http).check_connection()
    assert result.ready and result.live and result.batch_limit == 7
    assert result.info.model == "fixture"
    assert result.info.required_features == ["proto", "sport", "dport"]
    assert len(http.calls) == 4
    assert all(
        c[0].startswith("http://example.test:8123/") and c[2] == 10 for c in http.calls
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "file:///etc/passwd",
        "http://name:secret@localhost",
        "http://localhost?x=y",
        "http://localhost:bad",
        "http://localhost#fragment",
    ],
)
def test_bad_configuration(url):
    with pytest.raises(APIError, match="base URL"):
        APIClient(url)


@pytest.mark.parametrize(
    "failure, message",
    [
        (TimeoutError("private"), "timed out"),
        (URLError(TimeoutError("private")), "timed out"),
        (URLError("private filesystem path"), "Cannot connect"),
        (HTTPError("secret", 422, "private", {}, None), "rejected"),
        (HTTPError("secret", 503, "private", {}, None), "unavailable"),
        (HTTPError("secret", 500, "private", {}, None), "HTTP 500"),
    ],
)
def test_http_failures_sanitized(failure, message):
    client = APIClient(opener=FakeHTTP([failure]))
    with pytest.raises(APIError, match=message) as error:
        client.predict(RECORD)
    assert "private" not in str(error.value) and "secret" not in str(error.value)


def test_disconnected_and_not_ready():
    state = APIClient(opener=FakeHTTP([URLError("offline")])).check_connection()
    assert not state.live and not state.ready and "Cannot connect" in state.error
    state = APIClient(
        opener=FakeHTTP(
            connection_responses()[:1] + [HTTPError("x", 503, "private", {}, None)]
        )
    ).check_connection()
    assert state.live and not state.ready


@pytest.mark.parametrize(
    "mutation", ["info", "features", "limit", "openapi", "ready", "reference"]
)
def test_invalid_metadata_contract(mutation):
    responses = connection_responses()
    if mutation == "info":
        responses[2] = {"model": "only"}
    elif mutation == "features":
        responses[2] = {**INFO, "required_features": ["src_ip"]}
    elif mutation == "limit":
        responses = connection_responses(0)
    elif mutation == "ready":
        responses[1] = {"status": "ready", "model_loaded": False}
    elif mutation == "reference":
        responses[3]["paths"]["/api/v1/predict/batch"]["post"]["requestBody"][
            "content"
        ]["application/json"]["schema"]["$ref"] = None
    else:
        responses[3] = {}
    result = APIClient(opener=FakeHTTP(responses)).check_connection()
    assert not result.ready and result.error


def test_response_memory_bound_preserves_clear_error():
    with pytest.raises(APIError, match="safety limit"):
        APIClient(opener=FakeHTTP([b" " * (4 * 1024 * 1024 + 1)])).predict(RECORD)


def test_single_parsing_preserves_tokens_and_optional_probabilities():
    http = FakeHTTP([prediction(), prediction(probabilities=False)])
    client = APIClient(opener=http)
    assert client.predict(RECORD).prediction == "Normal"
    assert client.predict(RECORD).probabilities is None
    assert json.loads(http.calls[0][1]) == RECORD


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"\xff",
        {},
        {**prediction(), "prediction": "Theft"},
        {
            **prediction(),
            "probabilities": {
                "Normal": float("nan"),
                "DoS": 0,
                "DDoS": 0,
                "Reconnaissance": 0,
            },
        },
        {**prediction(), "probabilities": {"Normal": 0.5}},
        {**prediction(), "model": ""},
    ],
)
def test_reject_invalid_predictions(body):
    with pytest.raises(APIError):
        APIClient(opener=FakeHTTP([body])).predict(RECORD)


def test_invalid_input_never_sent():
    http = FakeHTTP([])
    with pytest.raises(APIError, match="Invalid record"):
        APIClient(opener=http).predict({**RECORD, "sport": True})
    assert not http.calls


def test_ordered_chunking_progress_and_bound():
    labels = ["Reconnaissance", "Normal", "DoS", "DDoS", "Normal"]
    http = FakeHTTP(
        [
            {
                "predictions": [prediction(c) for c in labels[start : start + 2]],
                "count": len(labels[start : start + 2]),
            }
            for start in range(0, 5, 2)
        ]
    )
    progress = []
    result = APIClient(opener=http).predict_chunks(
        [RECORD] * 5,
        batch_limit=2,
        expected_model="fixture",
        progress=lambda done, total: progress.append((done, total)),
    )
    assert [p.prediction for p in result] == labels
    assert [len(json.loads(call[1])["records"]) for call in http.calls] == [2, 2, 1]
    assert progress == [(2, 5), (4, 5), (5, 5)]


def test_chunk_failure_does_not_return_partial_or_retry():
    http = FakeHTTP(
        [
            {"predictions": [prediction()], "count": 1},
            HTTPError("x", 500, "private", {}, None),
        ]
    )
    with pytest.raises(APIError):
        APIClient(opener=http).predict_chunks(
            [RECORD] * 3, batch_limit=1, expected_model="fixture"
        )
    assert len(http.calls) == 2


@pytest.mark.parametrize(
    "body",
    [
        {"predictions": [], "count": 1},
        {"predictions": [prediction()], "count": 2},
        {"predictions": [{**prediction(), "model": "different"}], "count": 1},
    ],
)
def test_incomplete_or_changed_model_batch(body):
    with pytest.raises(APIError):
        APIClient(opener=FakeHTTP([body])).predict_chunks(
            [RECORD], batch_limit=1, expected_model="fixture"
        )


def test_csv_preserves_rows_strings_and_extras():
    frame = batch.parse_csv(
        b'proto,sport,dport,note\nTCP,00080,0x50,"hello,world"\nudp,,-1,other\n'
    )
    assert list(frame["sport"]) == ["00080", ""]
    assert list(frame["note"]) == ["hello,world", "other"]
    assert len(frame) == 2


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"proto,sport,dport\n",
        b"protocol,sport,dport\nx,1,2\n",
        b"proto,sport,sport\nx,1,2",
        b"proto,sport,dport,\nx,1,2,3",
        b"proto,sport,dport\nx,1",
        b'proto,sport,dport\nx,"unclosed,2',
        b"proto,sport,dport\n\n",
        b"proto,sport,dport\nx,\x00,2",
        b"proto,sport,dport\nx,\xff,2",
        b"proto,sport,dport,prediction\nx,1,2,x",
    ],
)
def test_reject_empty_malformed_invalid_schema(data):
    with pytest.raises(batch.UploadError):
        batch.parse_csv(data)


def test_upload_size_and_record_bounds(monkeypatch):
    monkeypatch.setattr(batch, "MAX_UPLOAD_BYTES", 10)
    with pytest.raises(batch.UploadError, match="5 MiB"):
        batch.parse_csv(batch.DEMO_CSV)
    monkeypatch.setattr(batch, "MAX_UPLOAD_BYTES", 10000)
    monkeypatch.setattr(batch, "MAX_RECORDS", 2)
    with pytest.raises(batch.UploadError, match="20,000"):
        batch.parse_csv(batch.DEMO_CSV)


def test_complete_output_and_csv_formula_protection():
    frame = pd.DataFrame(
        {
            "proto": ["tcp"] * 6,
            "sport": ["-1", "=CMD()", " +SUM(1)", "@cmd", "\tvalue", "normal"],
            "dport": ["0x50"] * 6,
            "=header": ["raw"] * 6,
        }
    )
    results = [PredictionResponse.model_validate(prediction())] * 6
    output = batch.results_frame(frame, results)
    exported = list(csv.reader(io.StringIO(batch.safe_csv(output).decode())))
    assert exported[0][3] == "'=header"
    assert [r[1] for r in exported[1:]] == [
        "'-1",
        "'=CMD()",
        "' +SUM(1)",
        "'@cmd",
        "'\tvalue",
        "normal",
    ]
    assert frame.iloc[0]["sport"] == output.iloc[0]["sport"] == "-1"
    assert list(output["probability_Normal"]) == [1.0] * 6
    with pytest.raises(batch.UploadError, match="Incomplete"):
        batch.results_frame(frame, results[:1])


@pytest.fixture
def saved_report(tmp_path):
    directory = tmp_path / "reports/model_evaluation"
    directory.mkdir(parents=True)
    matrix = [[1, 0, 0, 0], [0, 2, 0, 0], [0, 0, 3, 0], [0, 0, 0, 4]]
    metrics = {
        "model_sha256": "a" * 64,
        "evaluation": {
            "class_order": LABELS,
            "macro_f1": 1,
            "balanced_accuracy": 1,
            "benign_false_positive_rate": 0,
            "benign_support": 1,
            "benign_false_positives": 0,
            "confusion_matrix": matrix,
            "per_class": {
                label: {
                    "precision": 1,
                    "recall": 1,
                    "f1-score": 1,
                    "support": index + 1,
                }
                for index, label in enumerate(LABELS)
            },
        },
    }
    (directory / "bot_iot_validation_metrics.json").write_text(json.dumps(metrics))
    with (directory / "bot_iot_validation_confusion.csv").open(
        "w", newline=""
    ) as stream:
        writer = csv.writer(stream)
        writer.writerow(["actual / predicted", *LABELS])
        writer.writerows([label, *row] for label, row in zip(LABELS, matrix))
    return tmp_path


def test_report_counts_axes_and_normalization(saved_report):
    report = load_validation(saved_report)
    assert report.total == 10
    assert list(report.confusion.index) == LABELS == list(report.confusion.columns)
    assert report.per_class.loc["Normal", "support"] == 1
    figure = charts.confusion(report)
    assert figure.layout.xaxis.title.text == "Predicted class"
    assert figure.layout.yaxis.title.text == "Actual class"
    assert list(figure.data[0].z[2]) == [0, 0, 3, 0]
    assert charts.confusion(report, True).data[0].text[2][2] == "100.0%"
    assert charts.support(report).layout.xaxis.type == "log"
    assert list(charts.support(report).layout.yaxis.categoryarray) == LABELS
    assert len(charts.class_performance(report).data) == 3


def test_missing_report_and_inconsistent_confusion(saved_report, tmp_path):
    path = saved_report / "reports/model_evaluation/bot_iot_validation_confusion.csv"
    path.write_text(path.read_text().replace("Normal,1,0", "Normal,2,0"))
    with pytest.raises(ReportError, match="inconsistent"):
        load_validation(saved_report)
    path.unlink()
    with pytest.raises(ReportError, match="missing"):
        load_validation(tmp_path)


def test_malformed_class_order_is_report_error(saved_report):
    path = saved_report / "reports/model_evaluation/bot_iot_validation_metrics.json"
    data = json.loads(path.read_text())
    data["evaluation"]["class_order"] = dict.fromkeys(LABELS)
    path.write_text(json.dumps(data))
    with pytest.raises(ReportError, match="inconsistent"):
        load_validation(saved_report)


def test_dashboard_has_no_model_loader_or_dataset_access():
    for path in (ROOT / "src/cyberguard/dashboard").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert not any(
                name.startswith(
                    (
                        "joblib",
                        "pickle",
                        "sklearn",
                        "cyberguard.inference",
                        "cyberguard.features",
                        "cyberguard.training",
                        "cyberguard.testing",
                    )
                )
                for name in names
            )
        assert "data/raw" not in path.read_text()
        assert "joblib.load" not in path.read_text()


def test_reports_only_access_whitelisted_artifacts(saved_report, monkeypatch):
    original = Path.open
    opened = []

    def guarded(path, *args, **kwargs):
        assert path.parent == saved_report / "reports/model_evaluation"
        assert path.name in {
            "bot_iot_validation_metrics.json",
            "bot_iot_validation_confusion.csv",
        }
        opened.append(path.name)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    assert load_validation(saved_report).total == 10
    assert len(opened) == 2


def test_app_offline_and_explicit_refresh_only(monkeypatch):
    calls = []

    def offline(self):
        calls.append(1)
        return Connection(error="Cannot connect to the API.")

    monkeypatch.setattr(APIClient, "check_connection", offline)
    # Avoid AppTest's legacy pages/ rediscovery between runs of callable pages.
    # The same entrypoint contents execute; real file launch is also browser-tested.
    app = AppTest.from_string(
        (ROOT / "src/cyberguard/dashboard/app.py").read_text()
    ).run(timeout=10)
    assert not app.exception
    assert any("Unavailable" in m.value for m in app.metric)
    app.run()
    assert len(calls) == 1
    app.button[0].click().run()
    assert len(calls) == 2 and not app.exception


@pytest.mark.parametrize("page_name", ["test_lab", "batch_testing"])
def test_successful_prediction_ui_and_download(page_name, monkeypatch):
    from cyberguard.core.schemas import ModelInfoResponse

    monkeypatch.setattr(
        APIClient,
        "check_connection",
        lambda self: Connection(ModelInfoResponse.model_validate(INFO), 2, live=True),
    )
    monkeypatch.setattr(
        APIClient,
        "predict",
        lambda self, record: PredictionResponse.model_validate(prediction("DoS")),
    )
    seen = []

    def chunk(self, records, **kwargs):
        seen.extend(records)
        return [PredictionResponse.model_validate(prediction("DoS")) for _ in records]

    monkeypatch.setattr(APIClient, "predict_chunks", chunk)
    script = f"""
from cyberguard.dashboard.pages import {page_name}
from cyberguard.dashboard.api_client import APIClient
client = APIClient()
{page_name}.render(client, client.check_connection(), None, None)
"""
    app = AppTest.from_string(script).run()
    if page_name == "batch_testing":
        app.button[0].click().run()
    button = next(
        b for b in app.button if b.label in ("Analyze traffic", "Classify CSV")
    )
    button.click().run()
    assert not app.exception
    if page_name == "test_lab":
        assert any(
            "<strong>DoS</strong>" in element.proto.body for element in app.get("html")
        )
        assert len(app.get("plotly_chart")) == 1
    else:
        assert len(seen) == 4
        assert len(app.get("download_button")) == 1
        assert len(app.session_state["batch_result"]) == 4
        assert len(app.table) == 2
        assert list(app.table[1].value.columns) == [
            "proto",
            "sport",
            "dport",
            "prediction",
        ]


@pytest.mark.parametrize(
    "page_name", ["test_lab", "batch_testing", "model_performance", "about"]
)
def test_pages_remain_usable_without_backend(page_name, monkeypatch):
    # Render functions directly so native multipage navigation is not mocked.
    script = f"""
from cyberguard.dashboard.pages import {page_name}
from cyberguard.dashboard.api_client import Connection
from cyberguard.dashboard.report_loader import load_validation
{page_name}.render(None, Connection(error="Offline"), load_validation(), None)
"""
    app = AppTest.from_string(script).run(timeout=10)
    assert not app.exception
    for button in app.button:
        if button.label == "Analyze traffic":
            assert button.disabled
    if page_name == "batch_testing":
        app.button[0].click().run()
        assert not app.exception
        assert next(b for b in app.button if b.label == "Classify CSV").disabled
    if page_name == "model_performance":
        assert len(app.get("plotly_chart")) == 3
        assert any(m.value == "582,821" for m in app.metric)
