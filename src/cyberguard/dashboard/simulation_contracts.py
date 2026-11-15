"""Public simulation DTOs only. No engine, profiles, estimator or feature imports."""

import math
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

NF_SIM_MODEL = "nf_cse_binary_completed_flow"
STATES = Literal["created", "running", "paused", "completed", "stopped", "failed"]
FEATURES = (
    "PROTOCOL",
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
)


class Public(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, allow_inf_nan=False)


class Snapshot(Public):
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    state: STATES
    config: dict
    stop_requested: bool
    finished: bool
    termination_reason: str | None
    error: dict | None
    elapsed_seconds: float = Field(ge=0)
    warning: str

    @model_validator(mode="after")
    def configuration(self):
        required = {
            "model_id",
            "mode",
            "seed",
            "generation_rate",
            "max_duration",
            "max_records",
            "benign_ratio",
            "attack_ratio",
            "operating_mode",
            "batch_size",
            "queue_capacity",
            "event_capacity",
            "history_capacity",
        }
        if (
            not required <= self.config.keys()
            or self.config["model_id"] != NF_SIM_MODEL
        ):
            raise ValueError("Incompatible simulation configuration")
        if self.config["mode"] not in {"empirical", "synthetic"}:
            raise ValueError("Invalid generator mode")
        for key in required - {"model_id", "mode", "operating_mode"}:
            value = self.config[key]
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise ValueError("Invalid configuration scalar")
        if self.finished and self.state not in {"completed", "stopped", "failed"}:
            raise ValueError("Invalid terminal state")
        return self


class Latency(Public):
    mean_lifetime: float | None = Field(ge=0)
    p95_recent: float | None = Field(ge=0)
    recent_samples: int = Field(ge=0, le=2000)


class HistoryPoint(Public):
    elapsed_seconds: float = Field(ge=0)
    generated: int = Field(ge=0)
    classified: int = Field(ge=0)
    queue_depth: int = Field(ge=0)


class Metrics(Public):
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    state: STATES
    finished: bool
    generated: int = Field(ge=0)
    classified: int = Field(ge=0)
    discarded: int = Field(ge=0)
    benign_profile: int = Field(ge=0)
    attack_profile: int = Field(ge=0)
    predicted_benign: int = Field(ge=0)
    predicted_attack: int = Field(ge=0)
    source_agreement: int = Field(ge=0)
    source_agreement_fraction: float | None = Field(ge=0, le=1)
    queue_depth: int = Field(ge=0, le=4096)
    queue_capacity: int = Field(ge=1, le=4096)
    queue_high_water: int = Field(ge=0, le=4096)
    inflight: int = Field(ge=0, le=128)
    queue_full: int = Field(ge=0)
    queue_backpressure_seconds: float = Field(ge=0)
    elapsed_seconds: float = Field(ge=0)
    requested_generation_rate: float = Field(ge=1, le=500)
    actual_generation_rate: float = Field(ge=0)
    actual_inference_rate: float = Field(ge=0)
    worker_errors: int = Field(ge=0)
    latency_seconds: dict[str, Latency]
    history: list[HistoryPoint] = Field(max_length=600)
    error: dict | None
    warning: str

    @model_validator(mode="after")
    def counts(self):
        if (
            self.generated
            != self.classified + self.discarded + self.queue_depth + self.inflight
            or self.benign_profile + self.attack_profile != self.generated
            or self.predicted_benign + self.predicted_attack != self.classified
            or self.source_agreement > self.classified
            or self.queue_depth > self.queue_capacity
            or self.queue_high_water > self.queue_capacity
        ):
            raise ValueError("Inconsistent simulation counts")
        if set(self.latency_seconds) != {
            "queue_wait",
            "batch_processing",
            "end_to_end",
        }:
            raise ValueError("Missing latency definitions")
        if self.source_agreement_fraction is not None and (
            not self.classified
            or not math.isclose(
                self.source_agreement_fraction,
                self.source_agreement / self.classified,
                abs_tol=1e-12,
            )
        ):
            raise ValueError("Inconsistent source agreement")
        return self


class Prediction(Public):
    predicted_class: Literal["Benign", "Attack"]
    attack_score: float = Field(ge=0, le=1)
    operating_mode: str
    applied_threshold: float = Field(ge=0, le=1)
    model_version: str


class FlowEvent(Public):
    sequence: int = Field(ge=0)
    simulation_time: float = Field(ge=0)
    source_profile: Literal["benign", "attack"]
    record: dict[str, int]
    model_id: Literal["nf_cse_binary_completed_flow"]
    prediction: Prediction
    latency_seconds: dict[str, float]

    @model_validator(mode="after")
    def record_values(self):
        if set(self.record) != set(FEATURES):
            raise ValueError("Expected seven model fields")
        for i, name in enumerate(FEATURES):
            maximum = 255 if i == 0 else 65535 if i < 3 else 2**53 - 1
            if not (-1 if i in (1, 2) else 0) <= self.record[name] <= maximum:
                raise ValueError("Invalid generated scalar")
        if set(self.latency_seconds) != {
            "queue_wait",
            "batch_processing",
            "end_to_end",
        } or any(v < 0 for v in self.latency_seconds.values()):
            raise ValueError("Invalid latency values")
        return self


class EventPage(Public):
    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    events: list[FlowEvent] = Field(max_length=1000)
    next_cursor: int = Field(ge=-1)
    oldest_available: int | None = Field(ge=0)
    cursor_gap: bool
    state: STATES
    finished: bool
    warning: str

    @model_validator(mode="after")
    def ordered(self):
        sequences = [e.sequence for e in self.events]
        if sequences != sorted(set(sequences)) or (
            sequences and self.next_cursor != sequences[-1]
        ):
            raise ValueError("Unordered events/cursor")
        return self


def validate_config(payload, schema, model):
    """Validate the form against the backend's discovered scalar request schema."""
    properties = schema["properties"]
    if set(payload) - set(properties):
        raise ValueError("Unsupported simulation fields; refresh API limits")
    out = dict(payload)
    for name, value in out.items():
        rule = properties[name]
        if "anyOf" in rule:
            rule = next(r for r in rule["anyOf"] if r.get("type") != "null")
        kind = rule.get("type")
        if kind in {"integer", "number"}:
            if type(value) not in (
                (int,) if kind == "integer" else (int, float)
            ) or not math.isfinite(value):
                raise ValueError(f"{name}: enter a finite {kind}")
            if (
                ("minimum" in rule and value < rule["minimum"])
                or ("maximum" in rule and value > rule["maximum"])
                or ("exclusiveMinimum" in rule and value <= rule["exclusiveMinimum"])
            ):
                raise ValueError(f"{name}: outside the API's accepted range")
        if "enum" in rule and value not in rule["enum"]:
            raise ValueError(f"{name}: unsupported option")
    if (
        model.id != NF_SIM_MODEL
        or out.get("model_id") != NF_SIM_MODEL
        or model.readiness != "ready"
    ):
        raise ValueError("The NF-CSE simulation model is unavailable")
    model.threshold(out["operating_mode"])
    if abs(out["benign_ratio"] + out["attack_ratio"] - 1) > 1e-12:
        raise ValueError("Profile proportions must total 100%")
    return out


def simulation_path(identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise ValueError("Invalid simulation ID; refresh simulation history")
    return "/api/v1/simulations/" + identifier
