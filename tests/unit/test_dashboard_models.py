"""Registry-driven dashboard software tests with mocked HTTP and synthetic records."""

import hashlib
import io
import json
from pathlib import Path
from urllib.error import HTTPError

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from cyberguard.dashboard.api_client import APIClient, APIError, Connection
from cyberguard.dashboard.batch import UploadError, parse_csv, results_frame, safe_csv
from cyberguard.dashboard.contracts import (
    ModelMetadata,
    ModelPrediction,
    validate_record,
)
from cyberguard.dashboard.model_ui import choose_mode, choose_model, template_csv
from cyberguard.dashboard.report_loader import FinalReport, ReportError, load_nf_final

ROOT = Path(__file__).parents[2]
FEATURES = [
    "PROTOCOL",
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
]
FLOW = dict(
    zip(FEATURES, ["tcp", "49152", "443", "1200", "2400", "8", "12"], strict=True)
)


def metadata(binary=False):
    features = FEATURES if binary else ["proto", "sport", "dport"]
    return ModelMetadata.model_validate(
        {
            "id": "flow_fixture" if binary else "headers_fixture",
            "display_name": "Flow fixture" if binary else "Header fixture",
            "description": "Synthetic contract, not an evaluation",
            "model_version": "sha256:" + "a" * 64,
            "task": "binary" if binary else "multiclass",
            "classes": ["Benign", "Attack"]
            if binary
            else ["Normal", "DoS", "DDoS", "Reconnaissance"],
            "required_features": features,
            "input_contract_version": "nf-cse-netflow-v1-completed-flow-v1"
            if binary
            else "bot-iot-header-v1",
            "input_contract": {
                "protocol_aliases": {"tcp": 6, "udp": 17, "icmp": 1},
                "fields": [
                    {
                        "name": f,
                        "description": f,
                        "minimum": 0,
                        "maximum": 255
                        if i == 0
                        else 65535
                        if i in (1, 2)
                        else 2**53 - 1,
                    }
                    for i, f in enumerate(features)
                ],
            },
            "input_schema": {
                "required": features,
                "properties": {
                    f: {
                        "title": f,
                        "anyOf": [
                            {"type": "string"},
                            {"type": "integer"},
                            {"type": "number"},
                        ]
                        if binary
                        else [
                            {"type": "string"},
                            {"type": "integer"},
                            {"type": "null"},
                        ],
                    }
                    for f in features
                },
            },
            "available_operating_modes": [
                {"id": "standard", "threshold": 0.5},
                {"id": "high_sensitivity", "threshold": 0.03090052128234102},
            ]
            if binary
            else [{"id": "default", "threshold": None}],
            "default_operating_mode": "standard" if binary else "default",
            "limitations": ["Synthetic fixture; uncalibrated scores"],
            "readiness": "ready",
        }
    )


def prediction(model, mode=None, label=None):
    return ModelPrediction(
        model_id=model.id,
        model_version=model.model_version,
        task=model.task,
        predicted_class=label or model.classes[0],
        positive_class_score=0.1 if model.task == "binary" else None,
        class_scores={c: (0.1 if i else 0.9) for i, c in enumerate(model.classes)}
        if model.task == "binary"
        else {c: float(i == 0) for i, c in enumerate(model.classes)},
        score_semantics="Uncalibrated scores",
        operating_mode=mode or model.default_operating_mode,
        applied_threshold=model.threshold(mode or model.default_operating_mode),
        input_contract_version=model.input_contract_version,
        inference_timestamp="2026-11-15T00:00:00Z",
        limitations=model.limitations,
    )


class HTTP:
    def __init__(self, values):
        self.values = values
        self.calls = []

    def __call__(self, request, timeout):
        self.calls.append((request.full_url, request.data, timeout))
        value = self.values.pop(0)
        if isinstance(value, Exception):
            raise value
        return io.BytesIO(json.dumps(value).encode())


def specification(models):
    return {
        "paths": {
            "/api/v1/models/{model_id}/predict/batch": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "anyOf": [
                                        {
                                            "$ref": "#/components/schemas/"
                                            + m.id
                                            + "Batch"
                                        }
                                        for m in models
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {
            "schemas": {
                m.id + "Batch": {
                    "properties": {
                        "records": {
                            "maxItems": 2,
                            "items": {"required": m.required_features},
                        }
                    }
                }
                for m in models
            }
        },
    }


def test_dynamic_discovery_detail_readiness_and_limits():
    models = [metadata(), metadata(True)]
    http = HTTP(
        [
            {"status": "ok", "service": "cyberguard-api"},
            {"models": [m.model_dump() for m in models]},
            specification(models),
            models[1].model_dump(),
            {"model_id": models[1].id, "status": "ready", "model_loaded": True},
        ]
    )
    client = APIClient(opener=http)
    connection = client.check_models()
    assert [m.id for m in connection.models] == [m.id for m in models]
    connection = client.select_model(connection, models[1].id)
    assert (
        connection.ready
        and connection.mode == "standard"
        and connection.batch_limit == 2
    )
    assert http.calls[-2][0].endswith("/api/v1/models/flow_fixture")
    assert http.calls[-1][0].endswith("/flow_fixture/ready")
    assert all(c[2] == 10 for c in http.calls)


def test_selected_unavailable_preserves_metadata_and_other_models():
    model = metadata(True).model_copy(update={"readiness": "unavailable"})
    client = APIClient(opener=HTTP([model.model_dump()]))
    connection = client.select_model(
        Connection(models=(metadata(), model), batch_limits={model.id: 2}, live=True),
        model.id,
    )
    assert not connection.ready and connection.selected.id == model.id
    assert len(connection.models) == 2 and connection.live


@pytest.mark.parametrize(
    "bad", [{}, {"models": [{"id": "bad"}]}, {"models": [metadata().model_dump()] * 2}]
)
def test_invalid_registry(bad):
    with pytest.raises(APIError, match="registry"):
        APIClient(opener=HTTP([bad])).list_models()


def test_single_batch_tokens_and_mode_only_no_frontend_classification():
    model = metadata(True)
    p = prediction(
        model, "high_sensitivity", "Benign"
    )  # score is above threshold: UI must not reclassify.
    http = HTTP([p.model_dump(), {"predictions": [p.model_dump()], "count": 1}])
    client = APIClient(opener=http)
    assert client.predict_model(model, FLOW, "high_sensitivity").prediction == "Benign"
    assert (
        client.predict_model_batch(model, [FLOW], "high_sensitivity")[0].prediction
        == "Benign"
    )
    assert json.loads(http.calls[0][1]) == {
        "record": FLOW,
        "operating_mode": "high_sensitivity",
    }
    assert "threshold" not in json.loads(http.calls[0][1])


@pytest.mark.parametrize(
    "field,value",
    [
        ("IN_BYTES", ""),
        ("OUT_PKTS", None),
        ("IN_BYTES", "1.2"),
        ("IN_PKTS", "inf"),
        ("PROTOCOL", "bad"),
        ("PROTOCOL", "256"),
        ("L4_SRC_PORT", "65536"),
        ("OUT_BYTES", True),
        ("IN_PKTS", "9007199254740992"),
    ],
)
def test_input_errors_before_network(field, value):
    model = metadata(True)
    http = HTTP([])
    with pytest.raises(APIError):
        APIClient(opener=http).predict_model(model, FLOW | {field: value}, "standard")
    assert not http.calls


@pytest.mark.parametrize(
    "change",
    [
        {"model_id": "wrong"},
        {"model_version": "changed"},
        {"operating_mode": "high_sensitivity"},
        {"applied_threshold": 0.2},
        {"predicted_class": "Normal"},
        {"class_scores": {"Benign": float("nan"), "Attack": 0.1}},
        {"positive_class_score": None},
    ],
)
def test_incompatible_prediction_is_not_displayed(change):
    model = metadata(True)
    with pytest.raises(APIError, match="selected model"):
        APIClient(opener=HTTP([prediction(model).model_dump() | change])).predict_model(
            model, FLOW, "standard"
        )


def test_model_batch_validation_is_atomic_and_error_sanitized():
    model = metadata(True)
    http = HTTP([])
    client = APIClient(opener=http)
    with pytest.raises(APIError):
        client.predict_model_chunks(
            model, [FLOW, FLOW | {"IN_BYTES": "bad"}], "standard", batch_limit=1
        )
    assert not http.calls
    p = prediction(model).model_dump()
    http = HTTP(
        [
            {"count": 1, "predictions": [p]},
            HTTPError("private", 500, "secret", {}, None),
        ]
    )
    with pytest.raises(APIError, match="HTTP 500") as exc:
        APIClient(opener=http).predict_model_chunks(
            model, [FLOW] * 3, "standard", batch_limit=1
        )
    assert len(http.calls) == 2 and "secret" not in str(exc.value)


def test_header_only_templates_csv_validation_and_export():
    for model in (metadata(), metadata(True)):
        data = template_csv(model)
        assert data.decode().strip() == ",".join(model.required_features)
        with pytest.raises(UploadError, match="no data"):
            parse_csv(data, model=model)
    model = metadata(True)
    csv = (
        ",".join(FEATURES + ["note"])
        + "\n"
        + ",".join(list(FLOW.values()) + ["=CMD()"])
        + "\n"
    ).encode()
    frame = parse_csv(csv, model=model)
    assert frame.iloc[0].IN_BYTES == "1200"
    output = results_frame(frame, [prediction(model)], model=model)
    assert (
        output.iloc[0].operating_mode == "standard"
        and output.iloc[0].score_Attack == 0.1
    )
    assert "'=CMD()" in safe_csv(output).decode()
    with pytest.raises(UploadError):
        parse_csv(b"proto,sport,dport\ntcp,1,2", model=model)
    with pytest.raises(UploadError, match="record 1"):
        parse_csv(csv.replace(b"1200", b""), model=model)
    assert (
        validate_record(model, FLOW | {"L4_SRC_PORT": "0xc000", "IN_BYTES": "1.2e3"})[
            "IN_BYTES"
        ]
        == "1.2e3"
    )


def test_switch_clears_results_upload_and_preserves_per_model_preferences():
    state = {
        "selected_model_id": "old",
        "single_result": "old",
        "batch_result": "old",
        "demo_csv": True,
        "batch_input_hash": "x",
        "form_preferences": {"old": {"a": "kept"}},
        "mode_preferences": {"old": "standard"},
    }
    choose_model(state, "new")
    assert not {"single_result", "batch_result", "demo_csv", "batch_input_hash"} & set(
        state
    )
    assert state["upload_epoch"] == 1 and state["form_preferences"]["old"] == {
        "a": "kept"
    }
    state["single_result"] = "old-mode"
    choose_mode(state, "new", "high_sensitivity")
    assert (
        "single_result" not in state and state["mode_preferences"]["old"] == "standard"
    )
    choose_model(state, "new")
    assert state["upload_epoch"] == 1


def test_selector_persists_no_repeated_metadata_requests_and_clears_stale_results(
    monkeypatch,
):
    models = [metadata(), metadata(True)]
    calls = []
    monkeypatch.setattr(
        APIClient,
        "check_models",
        lambda self: Connection(
            models=tuple(models), batch_limits={m.id: 2 for m in models}, live=True
        ),
    )

    def info(self, key):
        calls.append(key)
        return next(m for m in models if m.id == key)

    monkeypatch.setattr(APIClient, "model_info", info)
    monkeypatch.setattr(APIClient, "model_ready", lambda self, key: True)
    app = AppTest.from_string(
        (ROOT / "src/cyberguard/dashboard/app.py").read_text()
    ).run(timeout=15)
    assert not app.exception and calls == ["headers_fixture"]
    app.session_state["single_result"] = "stale"
    app.selectbox(key="model_selector").select("flow_fixture").run()
    assert (
        not app.exception and app.session_state["selected_model_id"] == "flow_fixture"
    )
    assert "single_result" not in app.session_state
    app.selectbox(key="mode_selector:flow_fixture").select("high_sensitivity").run()
    app.run()
    assert calls == ["headers_fixture", "flow_fixture"]
    assert app.session_state["connection"].mode == "high_sensitivity"
    app.selectbox(key="model_selector").select("headers_fixture").run()
    assert not any(w.label == "Operating mode" for w in app.selectbox)
    app.selectbox(key="model_selector").select("flow_fixture").run()
    assert app.session_state["connection"].mode == "high_sensitivity"


def test_nf_dynamic_form_requires_counters_predicts_and_remembers_values(monkeypatch):
    model = metadata(True)
    seen = []

    def predict(self, m, record, mode):
        seen.append(record)
        return prediction(m, mode)

    monkeypatch.setattr(APIClient, "predict_model", predict)
    import cyberguard.dashboard.model_ui as ui

    monkeypatch.setattr(ui, "available", lambda c: True)
    script = """
from cyberguard.dashboard.api_client import APIClient, Connection
from cyberguard.dashboard.contracts import ModelMetadata
from cyberguard.dashboard.model_ui import interactive
import streamlit as st
model=ModelMetadata.model_validate(st.session_state.model_data)
interactive(APIClient(),Connection(selected=model,mode='standard',batch_limit=2,live=True))
"""
    app = AppTest.from_string(script)
    app.session_state["model_data"] = model.model_dump()
    app.run()
    assert len(app.text_input) == 7
    next(b for b in app.button if b.label == "Analyze traffic").click().run()
    assert app.error and not seen
    for widget, value in zip(app.text_input, FLOW.values(), strict=True):
        widget.input(value)
    next(b for b in app.button if b.label == "Analyze traffic").click().run()
    assert not app.exception and seen == [FLOW]
    assert any("Raw attack score" in m.label for m in app.metric)
    assert any("<strong>Benign</strong>" in h.proto.body for h in app.get("html"))
    assert app.session_state["form_preferences"][model.id]["IN_BYTES"] == "1200"


def test_nf_performance_renders_actual_fixture_metrics_and_limitations():
    model = metadata(True)
    metrics = {
        "threshold": 0.5,
        "recall": 0.25,
        "benign_fpr": 0.02,
        "precision": 0.75,
        "f1": 0.375,
        "roc_auc": 0.8,
        "average_precision": 0.7,
        "confusion_matrix": [[98, 2], [3, 1]],
        "confusion_order": ["Benign", "Attack"],
    }
    families = pd.DataFrame(
        [
            {
                "attack_family": "Infilteration",
                "mode": mode,
                "recall": recall,
                "original_records": 5,
            }
            for mode, recall in [("high_sensitivity", 0.2), ("lower_false_alarm", 0.1)]
        ]
        + [
            {
                "attack_family": "SQL Injection",
                "mode": "lower_false_alarm",
                "recall": 0,
                "original_records": 5,
            }
        ]
    )
    report = FinalReport({"lower_false_alarm": metrics}, families, {}, "a" * 64)
    script = """
import streamlit as st
from cyberguard.dashboard.pages.final_performance import render
from cyberguard.dashboard.api_client import Connection
render(Connection(selected=st.session_state.model,mode='standard'),st.session_state.report,None)
"""
    app = AppTest.from_string(script)
    app.session_state["model"] = model
    app.session_state["report"] = report
    app.run()
    assert not app.exception
    assert any(
        m.label == "Attack recall" and m.value == "25.00000%" for m in app.metric
    )
    assert any(
        "20.00%" in h.proto.body and "10.00%" in h.proto.body for h in app.get("html")
    )
    assert any("SQL Injection" in w.value for w in app.warning)


def test_nf_report_reader_checks_hashes_without_any_model_or_dataset_access(
    tmp_path, monkeypatch
):
    directory = tmp_path / "reports/model_evaluation/nf_cse_binary/final_test"
    directory.mkdir(parents=True)
    value = {
        "threshold": 0.5,
        "confusion_order": ["Benign", "Attack"],
        **dict.fromkeys(
            ["recall", "benign_fpr", "precision", "f1", "roc_auc", "average_precision"],
            0.5,
        ),
    }
    (directory / "test_metrics.json").write_text(
        json.dumps(
            {
                "thresholds": {
                    "lower_false_alarm": value,
                    "high_sensitivity": value | {"threshold": 0.03},
                }
            }
        )
    )
    (directory / "attack_family_recall.csv").write_text(
        "attack_family,mode,recall,original_records\nFixture,high_sensitivity,0.5,5\n"
    )
    manifest = {
        "status": "complete",
        "model_metadata": {"artifact_sha256": "a" * 64},
        "thresholds": {"lower_false_alarm": 0.5, "high_sensitivity": 0.03},
        "outputs": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in directory.iterdir()
        },
    }
    (directory / "evaluation_manifest.json").write_text(json.dumps(manifest))
    original = Path.open

    def guard(path, *args, **kwargs):
        assert path.parent == directory
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guard)
    assert (
        load_nf_final(tmp_path, expected_version="sha256:" + "a" * 64).metrics[
            "lower_false_alarm"
        ]["recall"]
        == 0.5
    )
    with pytest.raises(ReportError):
        load_nf_final(tmp_path, expected_version="sha256:" + "b" * 64)
    (directory / "test_metrics.json").write_text("{}")
    with pytest.raises(ReportError):
        load_nf_final(tmp_path)


@pytest.mark.parametrize("binary", [False, True])
def test_model_aware_batch_page_download_and_request_order(binary, monkeypatch):
    model = metadata(binary)
    values = FLOW if binary else {"proto": "tcp", "sport": "00080", "dport": "0x50"}
    data = (
        ",".join(model.required_features) + "\n" + ",".join(values.values()) + "\n"
    ).encode()
    import cyberguard.dashboard.model_ui as ui

    monkeypatch.setattr(
        ui.st, "file_uploader", lambda *args, **kwargs: io.BytesIO(data)
    )
    seen = []

    def chunks(self, m, records, mode, **kwargs):
        seen.extend(records)
        return [prediction(m, mode) for _ in records]

    monkeypatch.setattr(APIClient, "predict_model_chunks", chunks)
    script = """
import streamlit as st
from cyberguard.dashboard.model_ui import batch_testing
from cyberguard.dashboard.api_client import APIClient,Connection
batch_testing(APIClient(),Connection(selected=st.session_state.model,mode=st.session_state.model.default_operating_mode,batch_limit=2,live=True))
"""
    app = AppTest.from_string(script)
    app.session_state["model"] = model
    app.run()
    next(b for b in app.button if b.label == "Classify CSV").click().run()
    assert not app.exception and seen == [values]
    assert (
        len(app.get("download_button")) == 2
    )  # Header template plus complete prediction export.
    assert app.session_state["batch_result"].iloc[0]["model"] == model.id
    assert (
        app.session_state["batch_result"].iloc[0]["operating_mode"]
        == model.default_operating_mode
    )


def test_model_aware_bot_custom_null_and_tokens_preserved(monkeypatch):
    model = metadata()
    seen = []

    def predict(self, m, record, mode):
        seen.append(record)
        return prediction(m, mode)

    monkeypatch.setattr(APIClient, "predict_model", predict)
    script = """
import streamlit as st
from cyberguard.dashboard.model_ui import interactive
from cyberguard.dashboard.api_client import APIClient,Connection
interactive(APIClient(),Connection(selected=st.session_state.model,mode='default',batch_limit=2,live=True))
"""
    app = AppTest.from_string(script)
    app.session_state["model"] = model
    app.run()
    app.selectbox[0].select("Custom").run()
    next(t for t in app.text_input if t.label == "Custom protocol").input("58")
    next(t for t in app.text_input if t.label == "Source port").input("0x50")
    next(t for t in app.text_input if t.label == "Destination port").input("-1")
    next(c for c in app.checkbox if c.label == "Protocol: JSON null").check().run()
    next(b for b in app.button if b.label == "Analyze traffic").click().run()
    assert not app.exception and seen == [
        {"proto": None, "sport": "0x50", "dport": "-1"}
    ]


def test_empty_registry_is_graceful_and_disables_prediction_workspaces(monkeypatch):
    monkeypatch.setattr(
        APIClient,
        "check_models",
        lambda self: Connection(models=(), batch_limits={}, live=True),
    )
    app = AppTest.from_string(
        (ROOT / "src/cyberguard/dashboard/app.py").read_text()
    ).run(timeout=15)
    assert not app.exception
    assert any("no registered models" in v.value for v in app.info)
    assert not any(s.label == "Selected model" for s in app.selectbox)


def test_integral_port_sentinel_forms_match_api_contract():
    model = metadata(True)
    for value in ("-1", "-1.0", "-1e0", -1):
        assert (
            validate_record(model, FLOW | {"L4_SRC_PORT": value})["L4_SRC_PORT"]
            == value
        )


def test_failed_refresh_keeps_selected_id_and_never_substitutes_bot_evidence(
    monkeypatch,
):
    model = metadata(True)
    offline = [False]
    monkeypatch.setattr(
        APIClient,
        "check_models",
        lambda self: (
            Connection(error="Offline")
            if offline[0]
            else Connection(models=(model,), batch_limits={model.id: 2}, live=True)
        ),
    )

    def info(self, key):
        if offline[0]:
            raise APIError("Offline")
        return model

    monkeypatch.setattr(APIClient, "model_info", info)
    monkeypatch.setattr(APIClient, "model_ready", lambda self, key: True)
    app = AppTest.from_string(
        (ROOT / "src/cyberguard/dashboard/app.py").read_text()
    ).run(timeout=15)
    assert app.session_state["selected_model_id"] == model.id
    offline[0] = True
    import cyberguard.dashboard.report_loader as loader

    def no_other_report(*args, **kwargs):
        raise AssertionError("Do not load BoT evidence for a selected NF model")

    monkeypatch.setattr(loader, "load_validation", no_other_report)
    next(b for b in app.button if b.label == "Refresh connection").click().run()
    assert not app.exception
    assert app.session_state["selected_model_id"] == model.id
    assert app.session_state["connection"].selected is None
    assert not any(m.label == "Macro-F1" for m in app.metric)
