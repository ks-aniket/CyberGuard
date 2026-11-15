"""Bounded browser-session data preparation. HTTP only; no simulation execution."""

import json
from collections import deque
from dataclasses import dataclass, field
from itertools import pairwise

import pandas as pd

from cyberguard.dashboard.api_client import APIError
from cyberguard.dashboard.batch import safe_csv
from cyberguard.dashboard.simulation_contracts import FEATURES, validate_config

EVENT_LIMIT = 1000
CHART_LIMIT = 120


def actions(snapshot):
    if not snapshot:
        return ()
    if snapshot["finished"]:
        return ("delete",)
    if snapshot["stop_requested"]:
        return ()
    state = snapshot["state"]
    if state == "created":
        return ("start", "stop")
    if state == "running":
        return (
            ("pause", "stop") if snapshot["termination_reason"] is None else ("stop",)
        )
    if state == "paused":
        return (
            ("resume", "stop") if snapshot["termination_reason"] is None else ("stop",)
        )
    return ()


def form_payload(values, schema, model, batch_limit):
    payload = dict(values)
    seed = str(payload.pop("seed_text", "")).strip()
    if seed:
        if not seed.isascii() or not seed.isdigit() or len(seed) > 19:
            raise ValueError("Random seed must be an integer in the API range")
        payload["seed"] = int(seed)
    payload["model_id"] = model.id
    payload = validate_config(payload, schema, model)
    if payload["batch_size"] > batch_limit:
        raise ValueError("Batch size exceeds the server's advertised model limit")
    return payload


def milliseconds(value):
    return "—" if value is None else f"{value * 1000:,.1f} ms"


def event_frame(events):
    rows = []
    for event in events:
        rows.append(
            {
                "sequence": event["sequence"],
                "simulation_time_s": event["simulation_time"],
                "source_profile": event["source_profile"],
                **{c: event["record"][c] for c in FEATURES},
                "predicted_class": event["prediction"]["predicted_class"],
                "attack_score": event["prediction"]["attack_score"],
                "operating_mode": event["prediction"]["operating_mode"],
            }
        )
    return pd.DataFrame(rows)


def activity_frame(history):
    """Observed counter differences / observed intervals, never interpolation."""
    rows = []
    for previous, current in pairwise(history):
        dt = current["elapsed_seconds"] - previous["elapsed_seconds"]
        if (
            dt > 0
            and current["generated"] >= previous["generated"]
            and current["classified"] >= previous["classified"]
        ):
            rows.append(
                {
                    "elapsed_seconds": current["elapsed_seconds"],
                    "Generated / s": (current["generated"] - previous["generated"])
                    / dt,
                    "Classified / s": (current["classified"] - previous["classified"])
                    / dt,
                    "interval_seconds": dt,
                }
            )
    return pd.DataFrame(rows)


@dataclass
class LabState:
    selected: str | None = None
    snapshot: dict | None = None
    metrics: dict | None = None
    cursor: int = -1
    events: list = field(default_factory=list)
    samples: deque = field(default_factory=lambda: deque(maxlen=CHART_LIMIT))
    runs: list = field(default_factory=list)
    error: str | None = None
    blocked: bool = False
    missing: bool = False
    gap: bool = False
    exhausted: bool = False
    creation_uncertain: bool = False
    creation_armed: bool = True
    selected_event: int | None = None
    refresh_history: bool = True

    def select(self, identifier, snapshot=None):
        if identifier == self.selected:
            return
        self.selected = identifier
        self.snapshot = snapshot
        self.metrics = None
        self.cursor = -1
        self.events = []
        self.samples.clear()
        self.error = None
        self.blocked = self.missing = self.gap = self.exhausted = False
        self.selected_event = None

    def needs_poll(self):
        if not self.selected or self.blocked or self.missing:
            return False
        if not self.snapshot:
            return True
        if not self.snapshot["finished"]:
            return self.snapshot["state"] != "created"
        return bool(
            self.metrics
            and not self.exhausted
            and self.cursor < self.metrics["classified"] - 1
        )

    def poll(self, client):
        if not self.selected or self.blocked or self.missing:
            return
        identifier = self.selected
        try:
            snapshot = client.get_simulation(identifier)
            metrics = client.simulation_metrics(identifier)
            if (
                metrics["state"] != snapshot["state"]
                or metrics["finished"] != snapshot["finished"]
            ):
                snapshot = client.get_simulation(identifier)
            if self.metrics and (
                metrics["elapsed_seconds"] < self.metrics["elapsed_seconds"]
                or metrics["generated"] < self.metrics["generated"]
                or metrics["classified"] < self.metrics["classified"]
            ):
                raise APIError(
                    "Simulation counters moved backwards. Refresh history; cached results were preserved."
                )
            events = list(self.events)
            cursor = self.cursor
            gap = self.gap
            exhausted = False
            # At most two bounded pages per tick, never an unbounded catch-up loop.
            for _ in range(2):
                page = client.simulation_events(identifier, after=cursor, limit=500)
                gap |= page["cursor_gap"]
                incoming = page["events"]
                if any(
                    e["prediction"]["operating_mode"]
                    != snapshot["config"]["operating_mode"]
                    for e in incoming
                ):
                    raise APIError(
                        "Event operating mode does not match the selected run"
                    )
                combined = {e["sequence"]: e for e in events}
                combined.update({e["sequence"]: e for e in incoming})
                events = [combined[k] for k in sorted(combined)][-EVENT_LIMIT:]
                cursor = page["next_cursor"]
                if len(incoming) < 500:
                    exhausted = bool(snapshot["finished"])
                    break
            if self.selected != identifier:
                return
            self.snapshot, self.metrics, self.events, self.cursor = (
                snapshot,
                metrics,
                events,
                cursor,
            )
            self.gap, self.exhausted = gap, exhausted
            point = {
                "elapsed_seconds": metrics["elapsed_seconds"],
                "predicted_benign": metrics["predicted_benign"],
                "predicted_attack": metrics["predicted_attack"],
                "queue_depth": metrics["queue_depth"],
                "actual_inference_rate": metrics["actual_inference_rate"],
                "mean_ms": None
                if metrics["latency_seconds"]["end_to_end"]["mean_lifetime"] is None
                else 1000 * metrics["latency_seconds"]["end_to_end"]["mean_lifetime"],
                "p95_ms": None
                if metrics["latency_seconds"]["end_to_end"]["p95_recent"] is None
                else 1000 * metrics["latency_seconds"]["end_to_end"]["p95_recent"],
            }
            if (
                self.samples
                and self.samples[-1]["elapsed_seconds"] == point["elapsed_seconds"]
            ):
                self.samples[-1] = point
            else:
                self.samples.append(point)
            self.error = None
        except APIError as exc:
            self.error = str(exc)
            self.blocked = True
            if exc.status == 404:
                self.missing = True
                self.refresh_history = True

    def create(self, client, payload):
        if self.creation_uncertain or not self.creation_armed:
            raise APIError(
                "Creation outcome is unverified. Refresh history before another create request."
            )
        # A failed POST may already have created a server run. Never auto-retry it.
        self.creation_uncertain = True
        self.creation_armed = False
        try:
            snapshot = client.create_simulation(payload)
        except APIError:
            self.refresh_history = True
            raise
        self.creation_uncertain = False
        self.select(snapshot["id"], snapshot)
        self.refresh_history = True
        return snapshot

    def command(self, client, action):
        if self.blocked or self.missing or action not in actions(self.snapshot):
            raise APIError("Refresh simulation state before this action")
        if action == "delete":
            client.delete_simulation(self.selected)
            self.select(None)
            self.refresh_history = True
            return
        # A single UI submission, followed by an authoritative state refresh.
        self.snapshot = getattr(client, action + "_simulation")(self.selected)
        self.poll(client)

    def event_export(self):
        return safe_csv(event_frame(self.events))

    def complete_export(self):
        return bool(
            self.metrics
            and self.snapshot
            and self.snapshot["finished"]
            and not self.gap
            and len(self.events) == self.metrics["classified"]
            and [e["sequence"] for e in self.events]
            == list(range(self.metrics["classified"]))
        )


def json_export(value):
    return json.dumps(value, indent=2, allow_nan=False).encode()
