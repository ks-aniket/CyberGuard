"""Frontend-only software fixtures: mocked HTTP, no models/profiles/datasets."""

import io
import json
from copy import deepcopy
from pathlib import Path
from urllib.error import HTTPError, URLError

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from cyberguard.dashboard import simulation_charts as charts
from cyberguard.dashboard.api_client import APIClient, APIError
from cyberguard.dashboard.contracts import ModelMetadata
from cyberguard.dashboard.simulation_contracts import (
    NF_SIM_MODEL,
    Metrics,
    Snapshot,
    validate_config,
)
from cyberguard.dashboard.simulation_ui import (
    LabState,
    actions,
    activity_frame,
    event_frame,
    form_payload,
    milliseconds,
)

IDENTIFIER = "a" * 32
OTHER = "b" * 32
FEATURES = [
    "PROTOCOL",
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
]
CONFIG = {
    "model_id": NF_SIM_MODEL,
    "mode": "synthetic",
    "seed": 42,
    "generation_rate": 100,
    "max_duration": 60,
    "max_records": 1000,
    "batch_size": 32,
    "queue_capacity": 256,
    "event_capacity": 1000,
    "history_capacity": 120,
    "benign_ratio": 0.9,
    "attack_ratio": 0.1,
    "operating_mode": "standard",
}


def model():
    return ModelMetadata.model_validate(
        {
            "id": NF_SIM_MODEL,
            "display_name": "NF-CSE completed-flow binary",
            "description": "Fixture",
            "model_version": "fixture-v1",
            "task": "binary",
            "classes": ["Benign", "Attack"],
            "required_features": FEATURES,
            "input_contract_version": "nf-cse-netflow-v1-completed-flow-v1",
            "input_contract": {},
            "input_schema": {"required": FEATURES},
            "available_operating_modes": [
                {"id": "standard", "threshold": 0.45},
                {"id": "high_sensitivity", "threshold": 0.02},
            ],
            "default_operating_mode": "standard",
            "limitations": ["Fixture"],
            "readiness": "ready",
        }
    )


def schema():
    limits = {
        "seed": (0, 2**63 - 1, 42),
        "generation_rate": (1, 500, 100),
        "max_duration": (0, 3600, 60),
        "max_records": (1, 1000000, 6000),
        "batch_size": (1, 128, 32),
        "queue_capacity": (1, 4096, 256),
        "event_capacity": (1, 2000, 500),
        "history_capacity": (1, 600, 120),
    }
    props = {
        k: {
            "type": "number" if k in {"generation_rate", "max_duration"} else "integer",
            "minimum": minimum,
            "maximum": maximum,
            "default": default,
        }
        for k, (minimum, maximum, default) in limits.items()
    }
    props["max_duration"].pop("minimum")
    props["max_duration"]["exclusiveMinimum"] = 0
    props.update(
        model_id={"type": "string", "default": NF_SIM_MODEL},
        mode={
            "type": "string",
            "enum": ["empirical", "synthetic"],
            "default": "empirical",
        },
        operating_mode={
            "type": "string",
            "enum": ["standard", "high_sensitivity"],
            "default": "standard",
        },
        benign_ratio={"type": "number", "minimum": 0, "maximum": 1},
        attack_ratio={"type": "number", "minimum": 0, "maximum": 1},
    )
    return {"properties": props, "type": "object"}


def snapshot(state="created", identifier=IDENTIFIER, finished=False):
    return {
        "id": identifier,
        "state": state,
        "config": dict(CONFIG),
        "stop_requested": False,
        "finished": finished,
        "termination_reason": "max_records" if finished else None,
        "error": None,
        "elapsed_seconds": 10.0 if finished else 1.0,
        "warning": "Training-derived profiles",
    }


def metrics(n=10, state="running", finished=False, identifier=IDENTIFIER, elapsed=1.0):
    return {
        "id": identifier,
        "state": state,
        "finished": finished,
        "generated": n,
        "classified": n,
        "discarded": 0,
        "benign_profile": n,
        "attack_profile": 0,
        "predicted_benign": n,
        "predicted_attack": 0,
        "source_agreement": n,
        "source_agreement_fraction": 1.0 if n else None,
        "queue_depth": 0,
        "queue_capacity": 256,
        "queue_high_water": 1,
        "inflight": 0,
        "queue_full": 0,
        "queue_backpressure_seconds": 0.0,
        "elapsed_seconds": float(elapsed),
        "requested_generation_rate": 100.0,
        "actual_generation_rate": float(n / elapsed),
        "actual_inference_rate": float(n / elapsed),
        "worker_errors": 0,
        "latency_seconds": {
            name: {
                "mean_lifetime": 0.01 if n else None,
                "p95_recent": 0.02 if n else None,
                "recent_samples": min(n, 2000),
            }
            for name in ("queue_wait", "batch_processing", "end_to_end")
        },
        "history": [
            {"elapsed_seconds": 0.0, "generated": 0, "classified": 0, "queue_depth": 0},
            {
                "elapsed_seconds": float(elapsed),
                "generated": n,
                "classified": n,
                "queue_depth": 0,
            },
        ],
        "error": None,
        "warning": "Not test accuracy",
    }


def event(sequence):
    return {
        "sequence": sequence,
        "simulation_time": sequence / 100,
        "source_profile": "benign",
        "record": dict(zip(FEATURES, [6, 49152, 443, 1200, 2400, 8, 12], strict=True)),
        "model_id": NF_SIM_MODEL,
        "prediction": {
            "predicted_class": "Benign",
            "attack_score": 0.01,
            "operating_mode": "standard",
            "applied_threshold": 0.45,
            "model_version": "fixture-v1",
        },
        "latency_seconds": {
            "queue_wait": 0.01,
            "batch_processing": 0.01,
            "end_to_end": 0.02,
        },
    }


def page(events, after=-1, identifier=IDENTIFIER, gap=False):
    return {
        "id": identifier,
        "events": events,
        "next_cursor": events[-1]["sequence"] if events else after,
        "oldest_available": 0 if not events else events[0]["sequence"],
        "cursor_gap": gap,
        "state": "running",
        "finished": False,
        "warning": "Fixture",
    }


class HTTP:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, request, timeout):
        self.calls.append((request.full_url, request.method, request.data, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return io.BytesIO(json.dumps(response).encode())


class MockClient:
    def __init__(self):
        self.state = "created"
        self.n = 0
        self.calls = []
        self.fail = None
        self.gap = False
        self.oldest = 0

    def model_info(self, _id):
        return model()

    def model_ready(self, _id):
        return True

    def simulation_schema(self):
        return schema()

    def list_simulations(self):
        return [] if self.n == -1 else [self.get_simulation(IDENTIFIER)]

    def create_simulation(self, payload):
        self.calls.append(("create", payload))
        return snapshot()

    def get_simulation(self, _id):
        if self.fail:
            raise self.fail
        return snapshot(
            self.state, finished=self.state in {"completed", "stopped", "failed"}
        )

    def simulation_metrics(self, _id):
        return metrics(
            self.n,
            self.state,
            self.state in {"completed", "stopped", "failed"},
            elapsed=max(1, self.n / 100),
        )

    def simulation_events(self, _id, after=-1, limit=500):
        self.calls.append(("events", after))
        return page(
            [
                event(i)
                for i in range(
                    max(after + 1, self.oldest),
                    min(self.n, max(after + 1, self.oldest) + limit),
                )
            ],
            after=after,
            gap=self.gap,
        )

    def start_simulation(self, _id):
        self.calls.append(("start", _id))
        self.state = "running"
        self.n = 10
        return self.get_simulation(_id)

    def pause_simulation(self, _id):
        self.state = "paused"
        return self.get_simulation(_id)

    def resume_simulation(self, _id):
        self.state = "running"
        return self.get_simulation(_id)

    def stop_simulation(self, _id):
        self.state = "stopped"
        return self.get_simulation(_id)

    def delete_simulation(self, _id):
        self.n = -1
        return {"id": _id, "deleted": True}


def test_client_all_simulation_methods_exact_paths_methods_and_timeout():
    response = snapshot()
    http = HTTP(
        [
            {"simulations": [response]},
            response,
            response,
            response,
            response,
            response,
            response,
            {"id": IDENTIFIER, "deleted": True},
            metrics(),
            page([event(0)]),
        ]
    )
    client = APIClient(opener=http)
    assert client.list_simulations()[0]["id"] == IDENTIFIER
    assert client.create_simulation(CONFIG)["id"] == IDENTIFIER
    assert client.get_simulation(IDENTIFIER)["id"] == IDENTIFIER
    for operation in ("start", "pause", "resume", "stop"):
        getattr(client, operation + "_simulation")(IDENTIFIER)
    client.delete_simulation(IDENTIFIER)
    client.simulation_metrics(IDENTIFIER)
    client.simulation_events(IDENTIFIER, after=-1, limit=500)
    assert [call[1] for call in http.calls] == [
        "GET",
        "POST",
        "GET",
        "POST",
        "POST",
        "POST",
        "POST",
        "DELETE",
        "GET",
        "GET",
    ]
    assert all(call[3] == 10 for call in http.calls)
    assert json.loads(http.calls[1][2]) == CONFIG
    assert http.calls[-1][0].endswith("/events?after=-1&limit=500")


def test_schema_uses_actual_openapi_and_validates_resources():
    spec = {
        "paths": {
            "/api/v1/simulations": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/SimulationConfig"
                                }
                            }
                        }
                    }
                }
            }
        },
        "components": {"schemas": {"SimulationConfig": schema()}},
    }
    assert APIClient(opener=HTTP([spec])).simulation_schema() == schema()
    spec["components"]["schemas"]["SimulationConfig"]["properties"]["max_records"].pop(
        "maximum"
    )
    with pytest.raises(APIError):
        APIClient(opener=HTTP([spec])).simulation_schema()


@pytest.mark.parametrize(
    "body,kind",
    [
        ({}, Snapshot),
        (snapshot() | {"id": OTHER}, Snapshot),
        (metrics() | {"classified": 999}, Metrics),
        (metrics() | {"actual_inference_rate": float("nan")}, Metrics),
    ],
)
def test_response_shape_validation_and_cross_run_rejection(body, kind):
    with pytest.raises(APIError):
        APIClient()._simulation_response(body, kind, IDENTIFIER)


@pytest.mark.parametrize(
    "status,phrase",
    [
        (404, "no longer exists"),
        (409, "state changed"),
        (429, "capacity"),
        (503, "unavailable"),
        (422, "configuration"),
    ],
)
def test_http_failures_are_sanitized_and_status_retained(status, phrase):
    http = HTTP([HTTPError("private", status, "/secret/raw trace", {}, None)])
    with pytest.raises(APIError, match=phrase) as exc:
        APIClient(opener=http).get_simulation(IDENTIFIER)
    assert exc.value.status == status and "secret" not in str(exc.value)


@pytest.mark.parametrize("error", [URLError("private"), TimeoutError("secret")])
def test_connection_timeout_no_raw_traceback(error):
    with pytest.raises(APIError) as exc:
        APIClient(opener=HTTP([error])).get_simulation(IDENTIFIER)
    assert "secret" not in str(exc.value) and "private" not in str(exc.value)


@pytest.mark.parametrize("after,limit", [(-2, 10), (0, 1001), (True, 100)])
def test_invalid_cursor_before_http(after, limit):
    http = HTTP([])
    with pytest.raises(APIError):
        APIClient(opener=http).simulation_events(IDENTIFIER, after=after, limit=limit)
    assert not http.calls


def test_cursor_contract_rejects_duplicates_old_events_and_id_mismatch():
    for result in (
        page([event(2), event(1)]),
        page([event(0), event(0)]),
        page([event(0)]),
        page([], after=5, identifier=OTHER),
    ):
        with pytest.raises(APIError):
            APIClient(opener=HTTP([result])).simulation_events(IDENTIFIER, after=0)


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation_rate", 501),
        ("max_duration", 0),
        ("max_records", 1000001),
        ("queue_capacity", 4097),
        ("batch_size", 129),
        ("seed", True),
        ("mode", "gan"),
    ],
)
def test_configuration_validated_against_schema(field, value):
    with pytest.raises(ValueError):
        validate_config(CONFIG | {field: value}, schema(), model())


def test_form_seed_optional_large_integer_and_batch_limit():
    body = CONFIG.copy()
    body.pop("seed")
    assert "seed" not in form_payload(body | {"seed_text": ""}, schema(), model(), 1000)
    assert (
        form_payload(body | {"seed_text": str(2**63 - 1)}, schema(), model(), 1000)[
            "seed"
        ]
        == 2**63 - 1
    )
    for text in ("-1", "1.5", "1e2", "9999999999999999999999"):
        with pytest.raises(ValueError):
            form_payload(body | {"seed_text": text}, schema(), model(), 1000)
    with pytest.raises(ValueError):
        form_payload(body, schema(), model(), 2)


def test_duplicate_create_guard_selection_and_switch_cache_reset():
    state = LabState()
    client = MockClient()
    state.create(client, CONFIG)
    with pytest.raises(APIError):
        state.create(client, CONFIG)
    assert len([c for c in client.calls if c[0] == "create"]) == 1
    state.events = [event(0)]
    state.cursor = 0
    state.samples.append({"x": 1})
    state.selected_event = 0
    state.select(OTHER, snapshot(identifier=OTHER))
    assert (
        state.cursor == -1
        and not state.events
        and not state.samples
        and state.selected_event is None
    )
    state.events = [event(1)]
    state.select(OTHER)
    assert state.events  # Same-run reruns do not clear results.


def test_uncertain_create_never_auto_retries():
    state = LabState()

    class Broken(MockClient):
        def create_simulation(self, payload):
            raise APIError("Timeout after possible create")

    with pytest.raises(APIError):
        state.create(Broken(), CONFIG)
    assert state.creation_uncertain and not state.creation_armed
    with pytest.raises(APIError):
        state.create(MockClient(), CONFIG)


def test_valid_lifecycle_actions_and_stop_draining():
    assert actions(snapshot()) == ("start", "stop")
    assert actions(snapshot("running")) == ("pause", "stop")
    assert actions(snapshot("paused")) == ("resume", "stop")
    assert actions(snapshot("completed", finished=True)) == ("delete",)
    assert actions(snapshot("running") | {"stop_requested": True}) == ()
    state = LabState()
    state.select(IDENTIFIER, snapshot())
    client = MockClient()
    state.command(client, "start")
    assert state.snapshot["state"] == "running"
    with pytest.raises(APIError):
        state.command(client, "start")
    state.command(client, "pause")
    state.command(client, "resume")
    state.command(client, "stop")
    assert state.snapshot["finished"]


def test_incremental_pages_deduplication_order_bounded_memory_and_terminal_stop():
    state = LabState()
    client = MockClient()
    client.state = "running"
    client.n = 1600
    state.select(IDENTIFIER, snapshot("running"))
    state.poll(client)
    assert state.cursor == 999 and len(state.events) == 1000
    state.poll(client)
    assert (
        state.cursor == 1599
        and len(state.events) == 1000
        and state.events[0]["sequence"] == 600
    )
    state.poll(client)
    assert len(state.events) == 1000
    assert [e["sequence"] for e in state.events] == list(range(600, 1600))
    assert ("events", 999) in client.calls
    for i in range(150):
        client.n += 1
        state.poll(client)
    assert len(state.samples) == 120 and len(state.events) == 1000
    client.state = "completed"
    state.poll(client)
    assert not state.needs_poll() and not state.complete_export()


def test_gap_missing_id_and_cached_results_preserved():
    state = LabState()
    client = MockClient()
    client.n = 1200
    client.state = "running"
    client.oldest = 1000
    client.gap = True
    state.select(IDENTIFIER, snapshot("running"))
    state.poll(client)
    assert state.gap and state.events[0]["sequence"] == 1000
    previous = deepcopy(state.events)
    client.fail = APIError("Backend restarted", status=404)
    state.poll(client)
    assert (
        state.blocked
        and state.missing
        and not state.needs_poll()
        and state.events == previous
    )
    state.select(OTHER, snapshot(identifier=OTHER))
    assert not state.events and not state.missing


def test_activity_data_observed_intervals_and_empty_history():
    history = [
        {"elapsed_seconds": 5, "generated": 100, "classified": 80},
        {"elapsed_seconds": 7, "generated": 130, "classified": 120},
        {"elapsed_seconds": 10, "generated": 160, "classified": 150},
    ]
    frame = activity_frame(history)
    assert frame["Generated / s"].tolist() == [15, 10]
    assert frame["Classified / s"].tolist() == [20, 10]
    assert frame.interval_seconds.tolist() == [2, 3]
    assert activity_frame([]).empty and activity_frame(history[:1]).empty
    assert milliseconds(None) == "—" and milliseconds(0.05) == "50.0 ms"


def test_exports_actual_data_not_full_run_claims():
    state = LabState()
    client = MockClient()
    client.state = "completed"
    client.n = 20
    state.select(IDENTIFIER, snapshot("completed", finished=True))
    state.poll(client)
    assert state.complete_export()
    frame = pd.read_csv(io.BytesIO(state.event_export()))
    assert len(frame) == 20 and frame.sequence.tolist() == list(range(20))
    assert set(FEATURES) <= set(frame)
    state.events = state.events[5:]
    assert not state.complete_export()
    assert event_frame([]).empty


def test_figures_use_actual_series_and_separate_performance_axes():
    frame = pd.DataFrame(
        {
            "elapsed_seconds": [1, 2],
            "generated": [1, 3],
            "predicted_benign": [1, 2],
            "predicted_attack": [0, 1],
            "queue_depth": [0, 1],
            "actual_inference_rate": [1, 2],
        }
    )
    figure = charts.series(
        frame,
        [
            ("predicted_benign", "Predicted benign"),
            ("predicted_attack", "Predicted attack"),
        ],
        "Cumulative",
    )
    assert list(figure.data[0].y) == [1, 2] and list(figure.data[1].y) == [0, 1]
    performance = charts.performance(frame)
    assert performance.data[1].yaxis == "y2"
    assert list(charts.profile_prediction(metrics()).data[0].x) == [10, 10]


APP = """
import streamlit as st
from cyberguard.dashboard.pages.simulation_lab import render
from cyberguard.dashboard.api_client import Connection
render(st.session_state.fake_client,Connection(batch_limits={"nf_cse_binary_completed_flow":1000},live=True))
"""


def app_fixture():
    app = AppTest.from_string(APP)
    app.session_state["fake_client"] = MockClient()
    app.run(timeout=20)
    return app


def button(app, label):
    return next(b for b in app.button if b.label == label)


def test_streamlit_create_start_lifecycle_no_duplicate_on_reruns_and_downloads():
    app = app_fixture()
    assert not app.exception
    button(app, "Create simulation").click().run(timeout=20)
    assert not app.exception
    client = app.session_state["fake_client"]
    assert len([c for c in client.calls if c[0] == "create"]) == 1
    app.run(timeout=20)
    assert len([c for c in client.calls if c[0] == "create"]) == 1
    assert app.session_state["simulation_lab"].selected == IDENTIFIER
    button(app, "Start simulation").click().run(timeout=20)
    assert (
        not app.exception
        and app.session_state["simulation_lab"].snapshot["state"] == "running"
    )
    button(app, "Pause simulation").click().run(timeout=20)
    assert app.session_state["simulation_lab"].snapshot["state"] == "paused"
    button(app, "Resume simulation").click().run(timeout=20)
    button(app, "Stop simulation").click().run(timeout=20)
    assert not app.exception
    assert app.session_state["simulation_lab"].snapshot["finished"]
    assert len(app.get("download_button")) == 3
    assert button(app, "Delete simulation").disabled
    next(
        c for c in app.checkbox if c.label == "Confirm deletion of retained results"
    ).check().run(timeout=20)
    assert not button(app, "Delete simulation").disabled
    button(app, "Delete simulation").click().run(timeout=20)
    assert not app.exception and app.session_state["simulation_lab"].selected is None


def test_streamlit_invalid_configuration_stays_local_and_api_failure_is_readable():
    app = app_fixture()
    next(t for t in app.text_input if t.label == "Random seed (optional)").input(
        "not a seed"
    )
    button(app, "Create simulation").click().run(timeout=20)
    assert app.error and not app.exception
    assert not [c for c in app.session_state["fake_client"].calls if c[0] == "create"]
    state = app.session_state["simulation_lab"]
    state.select(IDENTIFIER, snapshot("running"))
    app.session_state["fake_client"].fail = APIError("Cannot connect to the API")
    app.session_state["sim_selection_epoch"] = 1
    app.run(timeout=20)
    assert not app.exception and state.blocked


def test_navigation_definition_preserves_existing_pages_and_no_backend_imports():
    root = Path(__file__).resolve().parents[2]
    source = (root / "src/cyberguard/dashboard/app.py").read_text()
    assert 'title="Simulation Lab"' in source
    for title in (
        "Overview",
        "Interactive Testing",
        "Batch Testing",
        "Model Performance",
        "About CyberGuard",
    ):
        assert f'title="{title}"' in source
    for filename in (
        "simulation_ui.py",
        "simulation_contracts.py",
        "simulation_charts.py",
        "pages/simulation_lab.py",
    ):
        text = (root / "src/cyberguard/dashboard" / filename).read_text()
        assert "from cyberguard.simulation" not in text
        assert "from cyberguard.inference" not in text
        assert "joblib.load" not in text


def test_streamlit_event_selection_recovers_when_old_event_is_evicted():
    app = app_fixture()
    button(app, "Create simulation").click().run(timeout=20)
    button(app, "Start simulation").click().run(timeout=20)
    cache = app.session_state["simulation_lab"]
    cache.selected_event = 0
    app.session_state["sim_event_choice:" + IDENTIFIER] = 0
    app.session_state["fake_client"].n = 1600
    app.run(timeout=20)
    app.run(timeout=20)
    assert not app.exception
    assert cache.selected_event >= 600


def test_streamlit_model_unavailable_does_not_offer_another_simulation_model():
    app = AppTest.from_string(APP)

    class Unavailable(MockClient):
        def model_info(self, _id):
            return model().model_copy(update={"readiness": "unavailable"})

    app.session_state["fake_client"] = Unavailable()
    app.run(timeout=20)
    assert not app.exception and button(app, "Create simulation").disabled
    assert any("NF-CSE is unavailable" in warning.value for warning in app.warning)
    assert len([s for s in app.selectbox if s.label == "Simulation model"]) == 1


def test_streamlit_backend_restart_preserves_cached_results_and_requires_new_id():
    app = app_fixture()
    button(app, "Create simulation").click().run(timeout=20)
    button(app, "Start simulation").click().run(timeout=20)
    button(app, "Stop simulation").click().run(timeout=20)
    cache = app.session_state["simulation_lab"]
    old = deepcopy(cache.events)
    app.session_state["fake_client"].n = -1
    button(app, "Refresh Lab").click().run(timeout=20)
    assert not app.exception and cache.missing and cache.blocked
    assert cache.events == old and cache.selected == IDENTIFIER
    assert not any(b.label == "Start simulation" for b in app.button)


@pytest.mark.parametrize("identifier", ["invalid selection", None, "", 123, "a" * 31])
def test_invalid_selected_id_is_sanitized_before_http(identifier):
    http = HTTP([])
    client = APIClient(opener=http)
    with pytest.raises(APIError, match="Invalid simulation selection"):
        client.get_simulation(identifier)
    assert not http.calls


def test_stale_selection_poll_preserves_results_and_stops_without_traceback():
    cache = LabState()
    cache.select(IDENTIFIER, snapshot("running"))
    client = MockClient()
    client.state = "running"
    client.n = 10
    cache.poll(client)
    previous = deepcopy(cache.events)
    cache.selected = "stale display label"
    cache.poll(APIClient(opener=HTTP([])))
    assert cache.blocked and cache.events == previous
    assert "Invalid simulation selection" in cache.error
