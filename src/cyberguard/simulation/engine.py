"""Application-owned bounded threads, cancellable FIFO and detached snapshots.

Stop drains all admitted records. Failure discards queued/unclassified records
with explicit counters. Native inference is cooperative: shutdown joins workers
before releasing the shared registry, and cannot preempt a native model call.
"""

import logging
import math
import time
from collections import Counter, deque
from copy import deepcopy
from threading import Condition, Lock, Thread
from uuid import uuid4

import numpy as np

from cyberguard.api.dependencies import APIError
from cyberguard.core.model_schemas import NFCompletedFlowRecord
from cyberguard.inference.model_registry import NF_ID
from cyberguard.simulation.generator import TrafficGenerator
from cyberguard.simulation.profiles import Profiles
from cyberguard.simulation.schemas import GeneratorConfig

logger = logging.getLogger(__name__)
TERMINAL = {"completed", "stopped", "failed"}
WARNING = "Training-derived source profiles are not verified ground truth. Agreement is not test accuracy or deployment evidence."


def advance_deadline(previous, now, period):
    """Stay on monotonic slots; skip missed slots instead of catch-up bursts."""
    due = previous + period
    if due < now:
        due += (math.floor((now - due) / period) + 1) * period
    return due


class Simulation:
    def __init__(self, config, model, factory):
        self.id = uuid4().hex
        self.config, self.model, self.factory = config, model, factory
        self.condition = Condition()
        self.state = "created"
        self.started = self.ended = None
        self.stop_requested = self.abort = self.producer_done = False
        self.finished = False
        self.exited = 0
        self.reason = self.error = None
        self.queue = deque()
        self.events = deque(maxlen=config.event_capacity)
        self.history = deque(maxlen=config.history_capacity)
        self.latencies = {
            name: deque(maxlen=2000)
            for name in ("queue_wait", "batch_processing", "end_to_end")
        }
        self.latency_sums = Counter()
        self.counts = Counter(
            generated=0,
            classified=0,
            discarded=0,
            generation_attempts=0,
            cancelled_before_enqueue=0,
            benign_profile=0,
            attack_profile=0,
            predicted_benign=0,
            predicted_attack=0,
            source_agreement=0,
            queue_full=0,
            worker_errors=0,
            batches=0,
        )
        self.high_water = self.inflight = 0
        self.backpressure_seconds = 0.0
        self.last_history = -1.0
        self.threads = []

    def elapsed(self):
        return (
            0.0
            if self.started is None
            else (self.ended or time.monotonic()) - self.started
        )

    def expired(self):
        return (
            self.started is not None
            and time.monotonic() - self.started >= self.config.max_duration
        )

    def _wait(self, timeout=0.05):
        remaining = self.config.max_duration - self.elapsed()
        self.condition.wait(
            timeout=max(0.001, min(timeout, remaining) if remaining > 0 else timeout)
        )

    def start(self):
        with self.condition:
            if self.state != "created":
                raise APIError(
                    409, "invalid_transition", "Only a created simulation can start"
                )
            self.state, self.started = "running", time.monotonic()
            workers = [
                Thread(target=self._produce, name=f"simulation-{self.id}-producer"),
                Thread(target=self._consume, name=f"simulation-{self.id}-inference"),
            ]
            # Non-daemon workers are always joined before registry shutdown.
            try:
                for thread in workers:
                    thread.start()
                    self.threads.append(thread)
            except RuntimeError as exc:
                logger.exception(
                    "simulation_worker_start_failed simulation=%s", self.id
                )
                self.state, self.abort, self.reason = (
                    "failed",
                    True,
                    "worker_start_failure",
                )
                self.error = {
                    "code": "worker_start_failure",
                    "stage": "startup",
                    "message": "Simulation workers could not start",
                }
                self.counts["worker_errors"] += 1
                for _ in range(2 - len(self.threads)):
                    self._worker_done()
                self.condition.notify_all()
                raise APIError(
                    503, "worker_start_failure", "Simulation workers could not start"
                ) from exc

    def control(self, action):
        with self.condition:
            if (
                action == "pause"
                and self.state == "running"
                and not self.stop_requested
                and not self.producer_done
            ):
                self.state = "paused"
            elif (
                action == "resume"
                and self.state == "paused"
                and not self.stop_requested
                and not self.producer_done
            ):
                self.state = "running"
            elif action == "stop" and self.state == "created":
                self.state, self.finished, self.reason = "stopped", True, "user_stop"
            elif (
                action == "stop"
                and self.state in {"running", "paused"}
                and not self.stop_requested
            ):
                self.stop_requested, self.reason = True, "user_stop"
            else:
                raise APIError(
                    409, "invalid_transition", f"Cannot {action} this simulation"
                )
            self.condition.notify_all()

    def _failed(self, stage):
        logger.exception(
            "simulation_worker_failed simulation=%s stage=%s", self.id, stage
        )
        with self.condition:
            self.state, self.abort, self.reason = "failed", True, "worker_failure"
            self.error = {
                "code": "worker_failure",
                "stage": stage,
                "message": "Simulation worker failed; inspect server logs",
            }
            self.counts["worker_errors"] += 1
            self.counts["discarded"] += len(self.queue)
            self.queue.clear()
            if stage == "inference":
                self.counts["discarded"] += self.inflight
                self.inflight = 0
            self.condition.notify_all()

    def _worker_done(self):
        with self.condition:
            self.exited += 1
            if self.exited == 2:
                self.ended, self.finished = time.monotonic(), True
                if self.state != "failed":
                    self.state = "stopped" if self.stop_requested else "completed"
                self._history(force=True)
            self.condition.notify_all()

    def _produce(self):
        pending = False
        try:
            generator = self.factory(self.config)
            period, due = 1 / self.config.generation_rate, time.monotonic()
            for expected_sequence in range(self.config.max_records):
                with self.condition:
                    while not (
                        self.abort or self.stop_requested or self.expired()
                    ) and (self.state == "paused" or time.monotonic() < due):
                        self._wait(
                            max(0.001, due - time.monotonic())
                            if self.state != "paused"
                            else 0.05
                        )
                    if self.abort or self.stop_requested or self.expired():
                        break
                item = next(generator)
                NFCompletedFlowRecord.model_validate(item["record"])
                if (
                    item["simulation"]["source_profile"] not in {"benign", "attack"}
                    or item["simulation"]["sequence"] != expected_sequence
                ):
                    raise ValueError("Malformed generator metadata/order")
                pending = True
                with self.condition:
                    self.counts["generation_attempts"] += 1
                    blocked_start = None
                    while not self.abort and (
                        len(self.queue) >= self.config.queue_capacity
                        or self.state == "paused"
                    ):
                        # Finish this one generated record while inference drains.
                        if (self.expired() or self.stop_requested) and len(
                            self.queue
                        ) < self.config.queue_capacity:
                            break
                        if (
                            len(self.queue) >= self.config.queue_capacity
                            and blocked_start is None
                        ):
                            blocked_start = time.monotonic()
                            self.counts["queue_full"] += 1
                        self._wait()
                    if blocked_start is not None:
                        self.backpressure_seconds += time.monotonic() - blocked_start
                    if self.abort:
                        break
                    admitted = time.monotonic()
                    self.queue.append((item, admitted))
                    self.counts["generated"] += 1
                    self.counts[item["simulation"]["source_profile"] + "_profile"] += 1
                    pending = False
                    self.high_water = max(self.high_water, len(self.queue))
                    self._history()
                    self.condition.notify_all()
                    due = advance_deadline(due, admitted, period)
            with self.condition:
                if self.reason is None:
                    self.reason = "max_duration" if self.expired() else "max_records"
        except Exception:  # noqa: BLE001 -- contain background worker failures
            self._failed("generation")
        finally:
            with self.condition:
                if pending:
                    self.counts["cancelled_before_enqueue"] += 1
                self.producer_done = True
                self.condition.notify_all()
            self._worker_done()

    def _consume(self):
        try:
            while True:
                with self.condition:
                    # Expiration bypasses pause and drains already admitted records.
                    while not self.abort and (
                        not self.queue
                        or (
                            self.state == "paused"
                            and not self.stop_requested
                            and not self.expired()
                            and not self.producer_done
                        )
                    ):
                        if self.producer_done and not self.queue:
                            return
                        self._wait()
                    if self.abort:
                        return
                    batch = []
                    deadline = time.monotonic() + 0.05
                    while len(batch) < self.config.batch_size:
                        while self.queue and len(batch) < self.config.batch_size:
                            batch.append(self.queue.popleft())
                            self.inflight += 1
                        self.condition.notify_all()
                        if (
                            len(batch) >= self.config.batch_size
                            or self.producer_done
                            or self.stop_requested
                            or self.state == "paused"
                            or time.monotonic() >= deadline
                        ):
                            break
                        self.condition.wait(
                            timeout=max(0.001, deadline - time.monotonic())
                        )
                        if self.abort:
                            self.counts["discarded"] += self.inflight
                            self.inflight = 0
                            return
                    processing_start = time.monotonic()
                records = [item["record"] for item, _ in batch]
                # Existing registry validation -> shared NF adapter -> frozen modes.
                predictions = self.model.predict(records, self.config.operating_mode)
                if len(predictions) != len(batch):
                    raise ValueError("Prediction count mismatch")
                # Check serializability/score ranges before committing the batch.
                for prediction in predictions:
                    score = prediction["positive_class_score"]
                    if (
                        prediction["predicted_class"] not in {"Benign", "Attack"}
                        or score is None
                        or not math.isfinite(score)
                        or not 0 <= score <= 1
                    ):
                        raise ValueError("Malformed simulation prediction")
                finished = time.monotonic()
                with self.condition:
                    self.counts["batches"] += 1
                    for (item, admitted), prediction in zip(
                        batch, predictions, strict=True
                    ):
                        source = item["simulation"]["source_profile"]
                        label = prediction["predicted_class"]
                        durations = {
                            "queue_wait": processing_start - admitted,
                            "batch_processing": finished - processing_start,
                            "end_to_end": finished - admitted,
                        }
                        for name, value in durations.items():
                            self.latency_sums[name] += value
                            self.latencies[name].append(value)
                        self.events.append(
                            {
                                "sequence": item["simulation"]["sequence"],
                                "simulation_time": admitted - self.started,
                                "source_profile": source,
                                "record": item["record"],
                                "model_id": self.config.model_id,
                                "prediction": {
                                    "predicted_class": label,
                                    "attack_score": prediction["positive_class_score"],
                                    "operating_mode": prediction["operating_mode"],
                                    "applied_threshold": prediction[
                                        "applied_threshold"
                                    ],
                                    "model_version": prediction["model_version"],
                                },
                                "latency_seconds": durations,
                            }
                        )
                        self.counts["classified"] += 1
                        self.counts["predicted_" + label.lower()] += 1
                        self.counts["source_agreement"] += (source == "attack") == (
                            label == "Attack"
                        )
                    self.inflight = 0
                    self._history()
                    self.condition.notify_all()
        except Exception:  # noqa: BLE001 -- contain background worker failures
            self._failed("inference")
        finally:
            self._worker_done()

    def _history(self, force=False):
        elapsed = self.elapsed()
        if force or elapsed - self.last_history >= 1:
            self.history.append(
                {
                    "elapsed_seconds": elapsed,
                    "generated": self.counts["generated"],
                    "classified": self.counts["classified"],
                    "queue_depth": len(self.queue),
                }
            )
            self.last_history = elapsed

    def snapshot(self):
        with self.condition:
            return {
                "id": self.id,
                "state": self.state,
                "config": self.config.model_dump(),
                "stop_requested": self.stop_requested,
                "finished": self.finished,
                "termination_reason": self.reason,
                "error": deepcopy(self.error),
                "elapsed_seconds": self.elapsed(),
                "warning": WARNING,
            }

    def metrics(self):
        with self.condition:
            elapsed = self.elapsed()
            self._history()
            classified = self.counts["classified"]
            return {
                "id": self.id,
                "state": self.state,
                "finished": self.finished,
                **dict(self.counts),
                "queue_depth": len(self.queue),
                "queue_capacity": self.config.queue_capacity,
                "queue_high_water": self.high_water,
                "inflight": self.inflight,
                "queue_backpressure_seconds": self.backpressure_seconds,
                "elapsed_seconds": elapsed,
                "requested_generation_rate": self.config.generation_rate,
                "actual_generation_rate": self.counts["generated"] / elapsed
                if elapsed
                else 0,
                "actual_inference_rate": classified / elapsed if elapsed else 0,
                "source_agreement_fraction": self.counts["source_agreement"]
                / classified
                if classified
                else None,
                "latency_seconds": {
                    name: {
                        "mean_lifetime": self.latency_sums[name] / classified
                        if classified
                        else None,
                        "p95_recent": float(np.quantile(values, 0.95))
                        if values
                        else None,
                        "recent_samples": len(values),
                    }
                    for name, values in self.latencies.items()
                },
                "history": list(self.history),
                "worker_errors": self.counts["worker_errors"],
                "error": deepcopy(self.error),
                "warning": WARNING,
            }

    def recent(self, after=-1, limit=100):
        with self.condition:
            first = self.events[0]["sequence"] if self.events else None
            rows = [event for event in self.events if event["sequence"] > after][:limit]
            return {
                "id": self.id,
                "events": deepcopy(rows),
                "next_cursor": rows[-1]["sequence"] if rows else after,
                "oldest_available": first,
                "cursor_gap": first is not None and after < first - 1,
                "state": self.state,
                "finished": self.finished,
                "warning": WARNING,
            }

    def join(self):
        for thread in self.threads:
            thread.join()


class SimulationController:
    def __init__(self, registry, settings, factory=None):
        self.registry, self.settings = registry, settings
        self.lock = Lock()
        self.sessions = {}
        self.closed = False
        self.profiles = None
        self.profile_lock = Lock()
        self.factory = factory or self._generator

    def _generator(self, config):
        # Called only in producer thread; no profile I/O/filter work in requests.
        # Serialized by profile_lock if server explicitly allows >1 active run.
        with self.profile_lock:
            if self.profiles is None:
                self.profiles = Profiles(self.settings.simulation_profiles_path)
            profiles = self.profiles
        return TrafficGenerator(
            profiles,
            GeneratorConfig(
                count=config.max_records,
                seed=config.seed,
                benign_ratio=config.benign_ratio,
                mode=config.mode,
            ),
        )

    def _model(self, config):
        if config.model_id != NF_ID:
            raise APIError(
                422,
                "unsupported_model",
                "Simulation supports only the NF-CSE binary model",
            )
        model = self.registry.entries.get(config.model_id)
        if (
            model is None
            or model.adapter is None
            or model.metadata()["readiness"] != "ready"
        ):
            raise APIError(
                503, "model_unavailable", "Requested simulation model is not ready"
            )
        if config.operating_mode not in model.modes:
            raise APIError(422, "unsupported_mode", "Operating mode is not available")
        return model

    def create(self, config):
        with self.lock:
            if self.closed:
                raise APIError(
                    503, "simulation_shutdown", "Simulation service is shutting down"
                )
            model = self._model(config)
            if config.batch_size > self.settings.max_batch_size:
                raise APIError(
                    422,
                    "batch_limit",
                    "Simulation batch size exceeds server batch limit",
                )
            if len(self.sessions) >= self.settings.simulation_max_sessions:
                raise APIError(
                    429,
                    "simulation_capacity",
                    "Delete a finished simulation before creating another",
                )
            session = Simulation(config, model, self.factory)
            self.sessions[session.id] = session
            return session

    def get(self, identifier):
        with self.lock:
            session = self.sessions.get(identifier)
            if session is None:
                raise APIError(
                    404, "unknown_simulation", "Unknown simulation identifier"
                )
            return session

    def start(self, identifier):
        with self.lock:
            if self.closed:
                raise APIError(
                    503, "simulation_shutdown", "Simulation service is shutting down"
                )
            session = self.sessions.get(identifier)
            if session is None:
                raise APIError(
                    404, "unknown_simulation", "Unknown simulation identifier"
                )
            self._model(session.config)
            if session.state != "created":
                raise APIError(
                    409, "invalid_transition", "Only a created simulation can start"
                )
            # Reap terminal threads before reusing an active slot.
            for previous in self.sessions.values():
                if previous.finished:
                    previous.join()
            if (
                sum(
                    s.started is not None and not s.finished
                    for s in self.sessions.values()
                )
                >= self.settings.simulation_max_active
            ):
                raise APIError(
                    429,
                    "active_simulation_limit",
                    "Active simulation limit reached (paused/draining runs also count)",
                )
            session.start()
            return session

    def list(self):
        with self.lock:
            return [s.snapshot() for s in self.sessions.values()]

    def delete(self, identifier):
        with self.lock:
            session = self.sessions.get(identifier)
            if session is None:
                raise APIError(
                    404, "unknown_simulation", "Unknown simulation identifier"
                )
            if not session.finished:
                raise APIError(
                    409,
                    "invalid_transition",
                    "Only a finished simulation can be deleted",
                )
            session.join()
            del self.sessions[identifier]

    def close(self):
        with self.lock:
            self.closed = True
            sessions = list(self.sessions.values())
            for session in sessions:
                with session.condition:
                    if (
                        session.state in {"created", "running", "paused"}
                        and not session.stop_requested
                    ):
                        session.control("stop")
        for session in sessions:
            session.join()
        self.profiles = None
