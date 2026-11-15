"""No datasets/models: real generator/registry plumbing with tiny in-memory fixtures."""

import time
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from cyberguard.api.dependencies import APIError
from cyberguard.api.main import create_app
from cyberguard.core.config import Settings
from cyberguard.core.model_schemas import NFCompletedFlowRecord
from cyberguard.features import nf_cse as nf
from cyberguard.inference.model_registry import (
    NF_ID,
    NF_MODES,
    ModelRegistry,
    NFAdapter,
    RegisteredModel,
)
from cyberguard.simulation.engine import SimulationController, advance_deadline
from cyberguard.simulation.engine_schemas import SimulationConfig
from cyberguard.simulation.generator import TrafficGenerator
from cyberguard.simulation.schemas import GeneratorConfig


class Predictor:
    def __init__(self):
        self.delay = 0
        self.fail = False
        self.calls = []

    def predict_proba(self, frame):
        self.calls.append(len(frame))
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise ValueError("private /secret/model trace")
        score = np.where(frame.IN_BYTES.to_numpy() > 100, 0.9, 0.01)
        return np.column_stack((1 - score, score))


def model_fixture():
    model = RegisteredModel(
        NF_ID,
        "fixture",
        "fixture",
        "binary",
        Path("fixture.joblib"),
        NFCompletedFlowRecord,
        nf.CONTRACT_VERSION,
        ["Benign", "Attack"],
        NF_MODES,
        "standard",
        [],
    )
    predictor = Predictor()
    model.adapter = NFAdapter(predictor)
    model.public.update(readiness="ready", model_version="fixture-v1")
    return model, predictor


def factory(config):
    profiles = SimpleNamespace(
        vectors=np.array(
            [[6, 1000, 80, 100, 100, 1, 1], [17, 2000, 53, 1000, 2000, 10, 20]],
            dtype=np.int64,
        ),
        weights=np.array([9, 1], dtype=np.uint64),
        labels=np.array([0, 1], dtype=np.uint8),
    )
    return TrafficGenerator(
        profiles,
        GeneratorConfig(
            count=config.max_records,
            seed=config.seed,
            benign_ratio=config.benign_ratio,
            mode=config.mode,
        ),
    )


def wait_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("Timed out waiting for simulation")
        time.sleep(0.005)


@pytest.fixture
def controller():
    model, predictor = model_fixture()
    service = SimulationController(
        SimpleNamespace(entries={NF_ID: model}), Settings(), factory=factory
    )
    service.predictor = predictor
    yield service
    service.close()
    assert all(not t.is_alive() for s in service.sessions.values() for t in s.threads)


def config(**overrides):
    return SimulationConfig(
        **(
            {
                "max_records": 30,
                "generation_rate": 500,
                "max_duration": 3,
                "batch_size": 8,
                "event_capacity": 100,
            }
            | overrides
        )
    )


def test_create_no_work_until_start_and_opaque_ids(controller):
    first = controller.create(config())
    second = controller.create(config())
    assert first.id != second.id and len(first.id) == 32
    assert first.state == "created" and not first.threads
    assert controller.predictor.calls == []
    assert len(controller.list()) == 2
    first.control("stop")
    assert first.state == "stopped" and first.finished
    with pytest.raises(APIError):
        controller.start(first.id)
    controller.delete(first.id)
    with pytest.raises(APIError, match="Unknown"):
        controller.get(first.id)


def test_completed_metrics_order_batching_and_detached_events(controller):
    session = controller.create(config())
    controller.start(session.id)
    wait_until(lambda: session.finished)
    assert session.state == "completed" and session.reason == "max_records"
    metrics = session.metrics()
    assert metrics["generated"] == metrics["classified"] == 30
    assert metrics["benign_profile"] == 27 and metrics["attack_profile"] == 3
    assert metrics["predicted_benign"] == 27 and metrics["predicted_attack"] == 3
    assert metrics["source_agreement_fraction"] == 1
    assert metrics["discarded"] == metrics["queue_depth"] == metrics["inflight"] == 0
    assert max(controller.predictor.calls) <= 8 and max(controller.predictor.calls) > 1
    events = session.recent(limit=100)["events"]
    assert [e["sequence"] for e in events] == list(range(30))
    assert all(
        e["prediction"]["applied_threshold"] == NF_MODES["standard"] for e in events
    )
    for event in events:
        lat = event["latency_seconds"]
        assert lat["end_to_end"] == pytest.approx(
            lat["queue_wait"] + lat["batch_processing"]
        )
    events[0]["record"]["IN_BYTES"] = -123
    assert session.recent()["events"][0]["record"]["IN_BYTES"] >= 0
    assert metrics["latency_seconds"]["end_to_end"]["recent_samples"] == 30
    for action in ("pause", "resume", "stop"):
        with pytest.raises(APIError):
            session.control(action)
    with pytest.raises(APIError):
        controller.start(session.id)


def test_pause_resume_stop_drains_and_never_restarts(controller):
    session = controller.create(config(max_records=1000, generation_rate=100))
    controller.start(session.id)
    wait_until(lambda: session.counts["generated"] >= 5)
    session.control("pause")
    count = session.counts["generated"]
    time.sleep(0.07)
    assert session.state == "paused" and session.counts["generated"] == count
    with pytest.raises(APIError):
        session.control("pause")
    session.control("resume")
    wait_until(lambda: session.counts["generated"] > count)
    session.control("pause")
    session.control("stop")
    wait_until(lambda: session.finished)
    assert session.state == "stopped"
    m = session.metrics()
    assert m["generated"] == m["classified"] and m["discarded"] == 0
    assert m["queue_depth"] == 0
    with pytest.raises(APIError):
        controller.start(session.id)


def test_paused_duration_expires_and_drains(controller):
    session = controller.create(config(max_duration=0.15, max_records=10000))
    controller.start(session.id)
    wait_until(lambda: session.counts["generated"] > 1)
    session.control("pause")
    wait_until(lambda: session.finished)
    assert session.state == "completed" and session.reason == "max_duration"
    assert session.counts["generated"] == session.counts["classified"]


def test_backpressure_queue_bound_stop_while_full(controller):
    controller.predictor.delay = 0.05
    session = controller.create(
        config(max_records=1000, queue_capacity=2, batch_size=1)
    )
    controller.start(session.id)
    wait_until(lambda: session.counts["queue_full"] > 0)
    assert session.high_water == 2
    assert len(session.queue) <= 2
    session.control("stop")
    wait_until(lambda: session.finished)
    m = session.metrics()
    assert m["generated"] == m["classified"] and m["queue_backpressure_seconds"] > 0
    assert m["queue_high_water"] <= 2 and m["discarded"] == 0


def test_monotonic_slots_skip_lateness_without_accumulating_drift():
    due = 0
    for _ in range(100):
        due = advance_deadline(due, due, 0.01)
    assert due == pytest.approx(1)
    assert advance_deadline(0.1, 0.305, 0.01) == pytest.approx(0.31)


def test_rate_control_no_unlimited_burst(controller):
    session = controller.create(config(max_records=10, generation_rate=50))
    controller.start(session.id)
    wait_until(lambda: session.finished)
    events = session.recent()["events"]
    assert events[-1]["simulation_time"] - events[0]["simulation_time"] >= 0.17
    assert session.metrics()["actual_generation_rate"] <= 60


def test_event_cursor_gap_and_bounded_history(controller):
    session = controller.create(
        config(max_records=25, event_capacity=5, history_capacity=2)
    )
    controller.start(session.id)
    wait_until(lambda: session.finished)
    page = session.recent(after=0, limit=2)
    assert page["cursor_gap"] and page["oldest_available"] == 20
    assert [e["sequence"] for e in page["events"]] == [20, 21]
    assert (
        session.recent(after=page["next_cursor"], limit=10)["events"][-1]["sequence"]
        == 24
    )
    assert session.recent(after=24)["events"] == []
    assert len(session.history) <= 2 and len(session.events) == 5


@pytest.mark.parametrize("mode", ["empirical", "synthetic"])
def test_deterministic_sequence_independent_of_rate_and_batches(controller, mode):
    results = []
    for rate, batch in ((500, 8), (200, 3)):
        session = controller.create(
            config(mode=mode, generation_rate=rate, batch_size=batch)
        )
        controller.start(session.id)
        wait_until(lambda session=session: session.finished)
        results.append(
            [
                (e["record"], e["source_profile"], e["prediction"])
                for e in session.recent()["events"]
            ]
        )
    assert results[0] == results[1]


@pytest.mark.parametrize(
    "stage", ["generation", "inference", "invalid_record", "missing_profiles"]
)
def test_failures_release_workers_and_preserve_safe_diagnostics(
    controller, stage, tmp_path
):
    if stage == "inference":
        controller.predictor.fail = True
    elif stage == "missing_profiles":
        controller.factory = controller._generator
        controller.settings = Settings(simulation_profiles_path=tmp_path / "missing")
    elif stage == "generation":

        def broken(_config):
            raise RuntimeError("/secret/profile trace")

        controller.factory = broken
    else:

        def invalid(_config):
            yield {"record": {}, "simulation": {}}

        controller.factory = invalid
    session = controller.create(config(queue_capacity=2))
    controller.start(session.id)
    wait_until(lambda: session.finished)
    assert session.state == "failed" and session.error
    assert "/secret" not in str(session.snapshot())
    assert session.counts["worker_errors"] >= 1
    assert (
        session.counts["generated"]
        == session.counts["classified"] + session.counts["discarded"]
    )
    assert not session.queue and session.inflight == 0
    session.join()
    assert all(not t.is_alive() for t in session.threads)


def test_retained_and_active_limits_include_paused(controller):
    controller.settings = Settings(simulation_max_sessions=2)
    first = controller.create(config(max_records=1000))
    second = controller.create(config())
    with pytest.raises(APIError) as exc:
        controller.create(config())
    assert exc.value.status == 429
    controller.start(first.id)
    first.control("pause")
    with pytest.raises(APIError) as exc:
        controller.start(second.id)
    assert exc.value.code == "active_simulation_limit"
    with pytest.raises(APIError):
        controller.delete(first.id)
    first.control("stop")
    wait_until(lambda: first.finished)
    controller.start(second.id)
    wait_until(lambda: second.finished)


def test_close_joins_slow_inference_without_orphans(controller):
    controller.predictor.delay = 0.1
    session = controller.create(config(max_records=1000))
    controller.start(session.id)
    wait_until(lambda: controller.predictor.calls)
    controller.close()
    assert session.state == "stopped" and session.finished
    assert session.counts["generated"] == session.counts["classified"]
    assert all(not t.is_alive() for t in session.threads)
    with pytest.raises(APIError):
        controller.create(config())


@pytest.mark.parametrize(
    "kwargs", [{"model_id": "bot_iot_restricted_baseline"}, {"model_id": "unknown"}]
)
def test_unsupported_models(controller, kwargs):
    with pytest.raises(APIError) as exc:
        controller.create(config(**kwargs))
    assert exc.value.code == "unsupported_model"


def test_model_readiness_and_batch_limit(controller):
    controller.registry.entries[NF_ID].adapter = None
    with pytest.raises(APIError) as exc:
        controller.create(config())
    assert exc.value.status == 503
    controller.registry.entries[NF_ID], _ = model_fixture()
    session = controller.create(config())
    controller.registry.entries[NF_ID].adapter = None
    with pytest.raises(APIError):
        controller.start(session.id)
    controller.registry.entries[NF_ID], _ = model_fixture()
    controller.settings = Settings(max_batch_size=1)
    with pytest.raises(APIError):
        controller.create(config(batch_size=2))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"generation_rate": 0},
        {"generation_rate": 501},
        {"max_duration": 0},
        {"max_duration": 3601},
        {"max_records": 0},
        {"max_records": 1000001},
        {"queue_capacity": 4097},
        {"batch_size": 129},
        {"event_capacity": 2001},
        {"history_capacity": 601},
        {"seed": -1},
        {"max_records": True},
        {"generation_rate": float("nan")},
        {"benign_ratio": 0.9, "attack_ratio": 0.9},
        {"operating_mode": "custom"},
        {"mode": "gan"},
        {"unknown": 1},
    ],
)
def test_config_limits(kwargs):
    with pytest.raises(ValidationError):
        config(**kwargs)


def test_ratio_and_server_environment(monkeypatch, tmp_path):
    assert SimulationConfig(attack_ratio=0.9).benign_ratio == 0.1
    monkeypatch.setenv("CYBERGUARD_SIMULATION_MAX_ACTIVE", "2")
    monkeypatch.setenv("CYBERGUARD_SIMULATION_MAX_SESSIONS", "3")
    monkeypatch.setenv("CYBERGUARD_SIMULATION_PROFILES_PATH", str(tmp_path))
    settings = Settings.from_env()
    assert (
        settings.simulation_max_active == 2
        and settings.simulation_max_sessions == 3
        and settings.simulation_profiles_path == tmp_path
    )
    with pytest.raises(ValueError):
        Settings(simulation_max_active=5)


@pytest.fixture
def client(monkeypatch):
    def load(registry):
        registry.entries[NF_ID], _ = model_fixture()

    monkeypatch.setattr(ModelRegistry, "load", load)
    app = create_app(Settings(max_model_request_bytes=2048))
    with TestClient(app) as client:
        app.state.simulations.factory = factory
        yield client
    assert all(
        not t.is_alive()
        for s in app.state.simulations.sessions.values()
        for t in s.threads
    )


def test_api_lifecycle_cursor_errors_and_shutdown(client):
    base = "/api/v1/simulations"
    response = client.post(
        base, json=config(max_records=1000, generation_rate=100).model_dump()
    )
    assert response.status_code == 201
    identifier = response.json()["id"]
    path = base + "/" + identifier
    assert client.get(base).json()["simulations"][0]["state"] == "created"
    assert client.post(path + "/pause").status_code == 409
    assert client.post(path + "/start").status_code == 200
    assert client.post(path + "/start").status_code == 409
    assert client.post(path + "/pause").json()["state"] == "paused"
    assert client.post(path + "/resume").json()["state"] == "running"
    assert client.post(path + "/stop").status_code == 200
    wait_until(lambda: client.get(path).json()["finished"])
    assert client.get(path).json()["state"] == "stopped"
    metrics = client.get(path + "/metrics").json()
    assert metrics["generated"] == metrics["classified"]
    assert client.get(path + "/events?after=-1&limit=2").status_code == 200
    assert client.get(path + "/events?limit=1001").status_code == 422
    assert client.get(base + "/unknown").json()["error"]["code"] == "unknown_simulation"
    assert client.delete(path).status_code == 200
    assert client.get(path).status_code == 404


@pytest.mark.parametrize(
    "body,status",
    [
        ({"model_id": "unknown"}, 422),
        ({"generation_rate": 10000}, 422),
        ({"queue_capacity": 10000000}, 422),
        ({"operating_mode": "custom"}, 422),
    ],
)
def test_api_invalid_config(client, body, status):
    assert client.post("/api/v1/simulations", json=body).status_code == status


def test_api_body_limit_and_background_independence(client):
    assert (
        client.post(
            "/api/v1/simulations",
            content='{"x":"' + "x" * 3000 + '"}',
            headers={"Content-Type": "application/json"},
        ).status_code
        == 413
    )
    session = client.app.state.simulations.create(config(max_records=500))
    client.post(f"/api/v1/simulations/{session.id}/start")
    wait_until(lambda: session.counts["generated"] >= 10)
    # Exiting TestClient below must join both active workers.
    assert client.get("/health").status_code == 200


def test_partial_thread_start_failure_is_joined(controller, monkeypatch):
    from cyberguard.simulation import engine

    original = engine.Thread.start
    calls = 0

    def start(thread):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("Cannot start another thread")
        return original(thread)

    monkeypatch.setattr(engine.Thread, "start", start)
    session = controller.create(config())
    with pytest.raises(APIError) as exc:
        controller.start(session.id)
    assert exc.value.code == "worker_start_failure"
    wait_until(lambda: session.finished)
    assert session.state == "failed"
    session.join()
    assert all(not t.is_alive() for t in session.threads)


def test_high_sensitivity_inherits_verified_registry_threshold(controller):
    session = controller.create(config(operating_mode="high_sensitivity"))
    controller.start(session.id)
    wait_until(lambda: session.finished)
    assert all(
        e["prediction"]["operating_mode"] == "high_sensitivity"
        and e["prediction"]["applied_threshold"]
        == controller.registry.entries[NF_ID].modes["high_sensitivity"]
        for e in session.recent()["events"]
    )


def test_inference_failure_cancels_blocked_producer_without_losing_counts(controller):
    controller.predictor.delay = 0.04
    controller.predictor.fail = True
    session = controller.create(
        config(max_records=1000, batch_size=1, queue_capacity=1)
    )
    controller.start(session.id)
    wait_until(lambda: session.finished)
    metrics = session.metrics()
    assert metrics["worker_errors"] == 1 and session.state == "failed"
    assert metrics["queue_full"] > 0 and metrics["cancelled_before_enqueue"] == 1
    assert metrics["generated"] == metrics["classified"] + metrics["discarded"]
    assert metrics["queue_depth"] == metrics["inflight"] == 0
