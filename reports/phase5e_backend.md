# Phase 5E: multi-model FastAPI integration

Completed backend integration on 2026-11-15. Streamlit, saved model artifacts, preprocessing implementations, thresholds, dataset partitions and final evaluation results were not modified. No training, calibration, threshold optimization or reserved-dataset evaluation occurred.

## Architecture

`src/cyberguard/inference/model_registry.py` defines allowlisted registry entries with stable IDs, private trusted artifact paths, public metadata, independent readiness and model-specific adapters. Each artifact is deserialized once during an application lifespan. BoT reuses the existing `NetworkDetector`, preprocessing, label order and score semantics. NF uses the saved `NFCSEBinaryModel.predict_proba` raw-input pipeline without fitting; its adapter applies the selected frozen presentation threshold without changing the saved threshold. Per-model locks serialize estimator access. Runtime failures return structured errors rather than predictions.

`core/model_schemas.py` adds separate typed record/envelope schemas and bounded batch types. The new router accepts the typed alternatives and requires the validated alternative to match the selected model. All records validate before a single vectorized adapter call; order is preserved, with no partial silent results. `api/body_limit.py` bounds additive prediction bodies before JSON parsing, including chunked bodies. Existing legacy schemas and routes are unchanged.

Registered IDs:

- `bot_iot_restricted_baseline`: protocol/port multiclass Normal, DoS, DDoS, Reconnaissance; `default` mode, no threshold.
- `nf_cse_binary_completed_flow`: completed bidirectional flow binary Benign/Attack; `standard` default = 0.5, `high_sensitivity` = 0.03090052128234102. The versioned mode configuration is checked against frozen model and final-evaluation metadata.

NF requires all seven exact fields `PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS`. API semantic validation rejects missing/null, malformed, nonfinite, fractional, out-of-range and Boolean values; valid sentinels and nontransport statuses follow the unchanged normalizer. API discovery exposes this stricter serving policy separately from the broader offline normalizer contract. Fields cannot prove completed-flow provenance; callers must supply compatible final exporter totals.

NF startup checks model checksum, sidecar and embedded metadata, model/estimator/normalizer types, raw/encoded feature order, class mapping, saved threshold, final manifest association, preprocessing and inference-code compatibility, frozen operating modes and historical metrics checksum. No processed/raw data is needed or opened. Matched historical performance is exposed using allowlisted metric keys, with evidence boundaries. A load failure affects only that model. Invalid server settings still fail configuration; liveness remains independent of model readiness.

## API contracts and compatibility

New endpoints:

- `GET /api/v1/models`
- `GET /api/v1/models/{model_id}`
- `GET /api/v1/models/{model_id}/ready`
- `POST /api/v1/models/{model_id}/predict`
- `POST /api/v1/models/{model_id}/predict/batch`

Single body: `{"record":{...},"operating_mode":"standard"}`; batch body: `{"records":[{...}],"operating_mode":"standard"}`. Omit mode to use the selected model's default. BoT supports only `default`.

Responses include model ID/hash version/task, predicted class, ordered class scores, NF positive-class score, applied mode/threshold, input contract version, UTC inference time and limitations. Scores are uncalibrated. Batches wrap ordered predictions with count. HTTP errors are structured: 404 unknown ID, 503 model unavailable, 422 invalid schema/mode/batch, 413 excessive body, 500 inference failure. Public metadata/errors omit local artifact paths and internal exceptions.

Unchanged legacy contracts: `/health`, `/health/ready`, `/api/v1/model/info`, `/api/v1/predict`, `/api/v1/predict/batch`. Legacy readiness remains BoT readiness; legacy predictions need no ID and retain their original request/response keys. A missing BoT artifact now permits the process and available NF model to serve; legacy readiness/predictions return 503. This deliberately replaces the previous all-process startup failure while preserving successful legacy behavior. Streamlit remains BoT-only and uses these legacy endpoints.

New optional configuration (relative paths resolve from the project root): `CYBERGUARD_NF_CSE_MODEL_PATH`, `CYBERGUARD_NF_CSE_EVALUATION_DIR`, and `CYBERGUARD_MAX_MODEL_REQUEST_BYTES` (default 1,048,576). Existing `CYBERGUARD_MAX_BATCH_SIZE` defaults to 1,000 and bounds both models. No automatic .env loading. Central instructions and exact curl examples are in the root README; `.env.example` includes the new settings.

## Verification

- Complete suite: `UV_CACHE_DIR=/tmp/cyberguard-uv-cache uv run --frozen --offline pytest -q`: **309 passed in 10.87 seconds**; **53 new model API cases**. API tests need normal local socket/thread support. They use temporary synthetic serialized predictors, forbid fitting and block real dataset paths.
- Tests cover discovery, lifecycle/reuse, readiness, unknown IDs, independent/partial availability, missing metadata/artifacts, checksum/contract/runtime-class/threshold failures, operating mode boundaries with score >= threshold, class-score ordering, single/batch parity and ordering, no partial inference on validation failure, body and record limits, environment settings, error sanitization, no artifact mutation and backward compatibility. Existing dashboard regression tests passed unchanged.
- Ruff checks and formatting passed for all eight new/changed Python files. `git diff --check` passed.
- Launched the actual saved artifacts using the unchanged `bash scripts/start_api.sh` with `CYBERGUARD_API_PORT=18005` to avoid interfering with another service. The documented new curl block was executed with that base URL; **12 curl requests** verified discovery, model details, model/legacy readiness, both-model single/batch inference, both NF modes and legacy health/predictions. All returned successfully. No Streamlit process is required.
- The synthetic TCP flow (protocol 6, ports 49152/443, bytes 1200/2400, packets 8/12) returned **Benign** with positive-class score **0.0009946485796402205** at both frozen thresholds. Two synthetic NF records returned Benign then Benign. This is software evidence only, not measured detection quality.
- The BoT synthetic input tcp/49152/80 returned **DDoS** through both old and new APIs with identical scores: Normal 0, DoS 0.4174163758509647, DDoS 0.5732050811375292, Reconnaissance 0.009378543011762379. Legacy/new batches also agreed in order.
- Frozen model hashes remain BoT `93b744ada3af044e2d0e7d4dd6d5fa70870536e7a972443c806a232ce9052c6f`, NF `598129ae5580ad386937f78f4a9d7f8a668557e63cd15db20fcbde9696665e7a`.

## Evidence limits

NF's previously frozen final-test recall/FPR remain 94.3563% / 0.043752% at standard, and 94.9925% / 1.24108% at high sensitivity. The latter exceeds its validation 1% FPR selection constraint. Infilteration recall remains 8.16% / 18.17%, with very small SQL Injection support. The server only reads published metrics; it does not regenerate them. Offline completed-flow metrics do not establish deployment effectiveness, calibrated probabilities, live/packet detection, exporter parity or independent capture/session generalization.

This remains a local unauthenticated inference API with no packet capture, model upload, training endpoint, DNS model or dashboard model selector. Schema presence cannot authenticate observation provenance. Missing/incompatible models require restoring the frozen trusted artifacts/metadata and restarting, not retraining or consuming a reserved benchmark. Stop scope: backend integration only.
