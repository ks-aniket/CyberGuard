# Phase 6B — background simulation backend

Completed 2026-11-15. The backend now generates training-derived completed-flow feature records, classifies them through the existing NF registry entry and exposes bounded in-memory results. No Streamlit changes, dataset access, model retraining, artifact/threshold/preprocessing changes, packet generation, capture or external scanning occurred. Existing registry startup reads its published frozen verification metadata/metrics; it does not rerun evaluation or open dataset records. Phase 6A's existing files and artifacts were preserved.

## Architecture and concurrency

`SimulationController → TrafficGenerator → bounded FIFO → inference worker → bounded aggregator → FastAPI`.

- `simulation/engine_schemas.py`: public bounded request configuration and complementary source ratios.
- `simulation/engine.py`: controller/session lifecycle, pacing, condition-protected FIFO, producer/inference threads, counters/rings and detached polling snapshots.
- `api/routes/simulations.py`: versioned CRUD/control, metrics and event-cursor routes.
- Existing `api/main.py` lifespan owns the controller and joins simulation workers before closing the model registry. Existing request-body middleware now also bounds simulation POST requests.
- `core/config.py`: trusted profile directory and active/retained session caps, configured through environment variables. No new dependencies, launch scripts or frontend components.

Each started simulation owns exactly one non-daemon producer and one inference worker. The default is **one active simulation**; paused, profile-initializing and draining runs retain their slot. Terminal threads are reaped before a slot is reused. Maximum active setting is four, maximum retained is 100 (default 20). The same read-only profile instance is cached per controller; filtering/CDFs remain per generator. Profile checksumming/loading and generator initialization happen inside the producer, outside HTTP request handlers. Model readiness is checked at creation and again at start. The registry's already loaded NF entry and its `NFAdapter` are reused; its lock serializes model calls with ordinary HTTP inference and other sessions. There is no per-simulation deserialization and no duplicated classification/threshold logic.

Control and polling endpoints are synchronous FastAPI handlers; CPU work runs on the two explicitly bounded threads. A condition protects state, FIFO and metrics; waits release that lock. Inference executes outside it. Native CPU threads can be bounded at process startup (`OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2` used in verification). Use one Uvicorn worker without reload: limits/state are process-local, not a distributed coordination mechanism. No HTTP connection owns a worker's lifetime.

## Configuration and limits

Example verified request:

```json
{
  "model_id": "nf_cse_binary_completed_flow",
  "mode": "synthetic",
  "benign_ratio": 0.9,
  "attack_ratio": 0.1,
  "seed": 42,
  "generation_rate": 100,
  "max_duration": 60,
  "max_records": 6000,
  "batch_size": 32,
  "queue_capacity": 256,
  "event_capacity": 1000,
  "history_capacity": 120,
  "operating_mode": "standard"
}
```

Hard per-run bounds: generation rate 1..500/s; positive duration ≤3600 s; records 1..1,000,000; batch 1..128 and ≤server model batch limit; FIFO 1..4096; recent events 1..2000; history 1..600; seed integral 0..2^63−1. Defaults are the example except event capacity defaults to 500. Model is NF only. Mode is empirical/synthetic. Operating mode is standard/high_sensitivity, with thresholds read from the verified registry entry, never copied into engine source. Either ratio infers its complement; both must sum to one within 1e−12. Unknown fields are rejected.

Server settings: `CYBERGUARD_SIMULATION_PROFILES_PATH` defaults to `models/simulation/nf_cse`; `CYBERGUARD_SIMULATION_MAX_ACTIVE=1` accepts 1..4; `CYBERGUARD_SIMULATION_MAX_SESSIONS=20` accepts active limit..100. Clients cannot choose source paths or bypass fixed per-run ceilings. Existing body/batch server limits also apply. Created runs allocate no feature records/threads. Retention is bounded and explicit: terminal runs can be deleted to reclaim capacity; no silent eviction of simulation IDs occurs.

## Lifecycle, queue and cancellation policy

`created → running ↔ paused`; record exhaustion or duration yields `completed`; user stop yields `stopped`; worker failure yields `failed`. Start only accepts `created`; terminal sessions cannot restart. Pause only accepts a running producer that has not entered drain. Resume only accepts paused work. Stop of a created run is immediate; stop of running/paused work sets `stop_requested` and drains. While draining, the public state can remain running/paused; inspect `finished` rather than assuming the stop response means all work is done. An already gathering/processing batch may finish after pause.

The FIFO is a `deque` managed exclusively under one condition, with atomic capacity checks, admission/counter updates, dequeue and notification. The producer blocks when full; no records are silently dropped. `queue_full` counts admission episodes encountering full capacity; `queue_backpressure_seconds` measures elapsed blocking episode duration. In a paused/full episode this can include pause time. Queue high-water/depth exclude the in-flight batch and one pending candidate. Thus record storage is bounded by queue capacity + batch size + one candidate + event ring, plus fixed profile/CDF working memory and bounded metrics rings.

`generated` means admitted to the FIFO; `generation_attempts` counts validated candidates; a failed run's pending unadmitted candidate is tracked by `cancelled_before_enqueue`. Explicit stop/duration ends new generation but finishes admitting at most one already generated pending candidate while inference drains. At normal completion/stop, `generated == classified`, with queue/inflight/discarded zero. On failure, queued/unclassified in-flight records are explicitly counted as `discarded`, giving final `generated == classified + discarded`. Results already committed remain available. A producer failure may allow its current inference batch to commit; an inference failure cancels the producer and counts its pending candidate separately.

Errors are contained inside workers, set failed state and wake related waiters. Public errors carry a safe stage/code/message; raw exception details/tracebacks stay in server logs. Missing/corrupt profiles fail asynchronously in generation; invalid generated schema/metadata/order also fails before admission. Model unavailability is structured 503 before starting. Partial thread startup failure is handled, missing worker finalizers are accounted for and successfully started threads are joined. Application shutdown stops every session, wakes paused/full waits, drains accepted records and joins threads before clearing the registry. Native inference/profile I/O cannot be forcibly preempted by Python threads; shutdown waits for those calls. There is no unsafe timed join that abandons a live worker and no hard wall-clock kill guarantee.

Duration is monotonic wall time from start, **including profile setup and pauses**. Expiration bypasses pause for drain. Duration caps generation, not the final drain's elapsed time. No unbounded run is accepted; both duration and record caps apply.

## Pacing, determinism and batching

Pacing advances monotonic target slots at `1/generation_rate` intervals. Missed slots are skipped rather than accumulating sleep drift or issuing unrestricted catch-up bursts. Condition notifications make pause/resume/stop responsive without busy-spinning. Backpressure and scheduling contention can lower achieved rates. This is paced offline simulation, not precise real-time scheduling.

Inference gathers up to the configured batch size with a maximum **50 ms gathering wait**; partial final batches flush promptly. Batches preserve FIFO order, call `RegisteredModel.predict`, validate prediction count/ranges and commit results in order. Existing registry input validation, stateless NF preprocessing, frozen thresholds and shared adapter are retained. No score calibration or source-label correction is introduced.

The unmodified Phase 6A generator owns private RNGs; time and scheduling never supply randomness. Complete requested record-count runs retain half-up exact source composition. Duration/stop produces a deterministic feature-sequence prefix whose length depends on timing; the prefix ratio need not equal the planned full-run ratio. The real-model verification compared all 1,000 records, source labels and predictions between 100/s, batch 32 and 500/s, batch 16; they matched exactly. Timestamps/latencies/throughput differ as expected.

## Metrics, latency and polling contracts

Counters include generated/classified/discarded, benign/attack profile counts, predicted benign/attack, source agreement, queue-full/backpressure/high-water, in-flight work, batch count and worker errors. Source agreement is descriptive agreement with a training-derived label, **not accuracy, independent ground truth or deployment evidence**. Rates are lifetime counts / monotonic elapsed seconds, including setup/pauses/drain. Rings keep at most 2,000 record-experienced latency samples per metric; lifetime sums provide means without retaining all events.

Latency units are seconds:

- Queue wait: FIFO admission → registry processing start, including batch gathering.
- Batch processing: registry call plus output count/score verification, including input validation, preprocessing, shared adapter-lock contention and prediction; assigned to each batch record, **not divided by batch size**.
- End-to-end: admission → output verification completion. It equals queue wait + batch processing; event aggregation and HTTP serialization are excluded. Generation/profile initialization and producer admission blocking are excluded and separately observable through setup-inclusive rates/backpressure.

`mean_lifetime` is record-weighted; `p95_recent` is an exact percentile of the latest 2,000 classified-record samples, not a lifetime percentile. Before classifications these are null. History samples cumulative counters at most once/second plus finalization, bounded by requested history capacity.

Events contain sequence, monotonic simulation admission time, source profile, seven fields, model ID, score/class/mode/verified threshold/version and latencies. Simulation metadata never enters predictor fields. Recent events use an exclusive `after` sequence cursor (initial −1), ascending order, default limit 100, max 1000. `next_cursor` advances polling; `oldest_available` and `cursor_gap` explicitly report overwritten ring entries. Overwritten event history is not a pipeline discard. No SSE/WebSocket endpoint or durable event log is implemented.

## API and manual commands

All endpoints are under `/api/v1/simulations`:

| Method | Suffix | Behavior |
| --- | --- | --- |
| POST / GET | empty | Create (201) / list |
| GET | `/{id}` | Inspect |
| POST | `/{id}/start`, `/pause`, `/resume`, `/stop` | Lifecycle control |
| GET | `/{id}/metrics` | Bounded aggregates/history |
| GET | `/{id}/events?after=-1&limit=100` | Recent cursor page |
| DELETE | `/{id}` | Delete finished run |

Errors use the existing `{error:{code,message}}` API envelope: 404 unknown ID, 409 transition, 422 schema/model/mode/batch restriction, 429 active/retained limit, 503 model/shutdown/startup unavailable, 413 body too large. Creation starts no generation. Empty control bodies cannot change configuration or thresholds. Read the root [README curl lifecycle](../../README.md#verified-curl-lifecycle) for launch, create, start, poll, pause, resume, stop, final inspection and deletion commands. The launcher is unchanged and no planned command is documented as implemented.

Actual event from the naturally completed standard-mode synthetic run:

```json
{
  "sequence": 0,
  "simulation_time": 0.0376483969957917,
  "source_profile": "benign",
  "record": {
    "PROTOCOL": 6,
    "L4_SRC_PORT": 53597,
    "L4_DST_PORT": 443,
    "IN_BYTES": 2668,
    "OUT_BYTES": 652434,
    "IN_PKTS": 39,
    "OUT_PKTS": 461
  },
  "model_id": "nf_cse_binary_completed_flow",
  "prediction": {
    "predicted_class": "Benign",
    "attack_score": 0.012303024987551068,
    "operating_mode": "standard",
    "applied_threshold": 0.5,
    "model_version": "sha256:598129ae5580ad386937f78f4a9d7f8a668557e63cd15db20fcbde9696665e7a"
  },
  "latency_seconds": {
    "queue_wait": 0.050653081001655664,
    "batch_processing": 0.022738722997019067,
    "end_to_end": 0.07339180399867473
  }
}
```

## Actual verification and performance

[Machine-readable evidence](phase6b_manual.json) records **105 curl HTTP checks** against a temporary localhost server on port 18006 using the existing frozen model and existing profiles. Checks covered readiness, creation, start, polling, pause admission freeze, resume, stop/drain, invalid restart, unknown ID, invalid rate, active-slot rejection while paused, deletion, natural completion and cursor order. These requests did not open raw/validation/test records. The server ran with two OpenMP/BLAS threads; the full fixture test suite ran concurrently during the initial checks, so timings are observations under that load, not isolated hardware capacity claims.

| Run | Requested / actual rate (records/s) | Generated / classified | Source benign / attack | Predicted benign / attack | Queue high-water / full episodes | Final state |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| stopped | 100 / 85.45 | 403 / 403 | 363 / 40 | 379 / 24 | 3 / 0 | stopped |
| completed | 100 / 99.47 | 1000 / 1000 | 900 / 100 | 939 / 61 | 4 / 0 | completed |
| reproduced | 500 / 421.35 | 1000 / 1000 | 900 / 100 | 939 / 61 | 12 / 0 | completed |

Stopped run: all 403 admitted records classified; queue/in-flight/discards zero. Pause froze generated count across a 300 ms observation. Natural run: all 1,000 records classified, exact 900/100 composition, completed under its 60 s cap. Reproduction: same features/source/predictions at a different target rate/batch size; the 500/s target was **not achieved** (about 421/s). Queue never filled in these real-model runs; forced backpressure/failure behavior was separately exercised with deliberately slow synthetic adapters. No independent test metrics were calculated.

Latency for the natural 100/s run (1,000 samples):

| Component | Lifetime mean ms | Recent p95 ms |
| --- | ---: | ---: |
| queue_wait | 36.721 | 68.960 |
| batch_processing | 23.828 | 29.836 |
| end_to_end | 60.549 | 92.961 |

The natural run completed in 10.054 s. Largest observed curl request wall time was 92.62 ms (includes curl process startup and transport); worker work did not occupy HTTP handlers. Linux `/proc/<server-pid>/status` showed **VmHWM 404,772 kB = 395.29 MiB peak RSS**, current RSS 306,932 kB = 299.74 MiB after these runs. Profile mappings/CDFs dominate working memory; this is an observed process peak, not a worst-case guarantee for every configuration. No GPU or full dataset copies were used.

A final active simulation was started before sending SIGTERM to the temporary server. Uvicorn logged `Application shutdown complete` and `Finished server process` after lifespan joined workers; the process was confirmed absent. The uv launcher propagated signal exit **143**, not exit zero. The temporary server was removed; other services were not stopped.

## Automated checks and artifact integrity

`uv run --frozen --offline pytest -q`: **444 passed in 21.80 s**, including **46 new engine/API tests**. One SQLite `ResourceWarning` about an unclosed connection surfaced during the network-training fixture test; it also appeared in the Phase 6A suite and no tests failed.

The new tests use tiny in-memory generator profiles and mocked predictors behind the real registry/NF adapter. They cover creation, all lifecycle states/transitions, paused wall-duration expiry, exact source composition, ordered batching, deterministic features/predictions across rates, monotonic slots, queue bounds/backpressure, stop with full queue, failure with a blocked producer, safe diagnostics, missing profiles, invalid records, native-call drain/join, partial thread startup failure, high-sensitivity mode delegation, event cursor gaps, bounded event/history/latency storage, model readiness, unsupported models, resource limits, structured API errors/body limits and lifespan shutdown. No real dataset partition is accessed by the tests. Existing synthetic training tests may fit their tiny software fixtures; no saved classifier is retrained.

Ruff check/format and `git diff --check` passed for changed files. The README documents current backend usage; `AGENTS.md` already contained the permanent documentation-maintenance rule and was preserved.

Classifier hashes remain unchanged:

- BoT: `93b744ada3af044e2d0e7d4dd6d5fa70870536e7a972443c806a232ce9052c6f`.
- NF: `598129ae5580ad386937f78f4a9d7f8a668557e63cd15db20fcbde9696665e7a`.

## Remaining limits

Only NF completed-flow simulation is supported. Pacing is approximate; CPU/adapter contention and skipped slots affect rate. Batch processing blocks a worker until native inference returns. Duration/stop drains instead of imposing a hard termination deadline. Per-process RAM state is lost on restart; there is no cross-process coordination, persistence, authentication, event subscription, worker pool/queue service or simulation UI. Client polling can miss overwritten ring entries, explicitly signaled by cursors. Full source composition applies only when the planned generator count is exhausted. Phase 6A's local perturbation/tail/label/artifact limitations still apply.

Source labels are training-derived profiles, scores are uncalibrated, and prediction agreement is not independent test accuracy or evidence of a real attack/safety. Simulated metrics must not be combined with frozen test metrics or used to update models without a separate approved experiment. No Streamlit or network-traffic integration was implemented.
