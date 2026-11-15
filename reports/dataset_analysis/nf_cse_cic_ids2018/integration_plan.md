# NF-CSE-CIC-IDS2018: CyberGuard integration proposal

No serving/UI changes or model switching are implemented. NF-CSE has no trained artifact. Existing BoT-IoT behavior and artifacts are preserved.

## Actual constraints in current code

- `src/cyberguard/core/schemas.py`: NetworkRecord requires exactly proto/sport/dport (strict string/integer/null, extras forbidden); response labels are Literal Normal/DoS/DDoS/Reconnaissance.
- `src/cyberguard/inference/network_detector.py`: constructor and predict_frame require the three-feature order and fixed four classes, select those inputs, validate probability columns and emit BoT-specific warning. A differently shaped artifact cannot be swapped in safely.
- `src/cyberguard/inference/model_loader.py`, API lifespan/dependencies/config: trusted joblib loading and per-app startup ownership currently serve one detector. A different file path does not provide a different schema or class contract automatically.
- `src/cyberguard/dashboard/api_client.py`: metadata and OpenAPI validation enforce the three inputs/four classes; it imports strict shared response schemas. `dashboard/batch.py` and test_lab form/labels/colors are also tied to the BoT contract. Existing metadata fields are a useful starting point, not a general registry.
- `src/cyberguard/testing/network_model_cli.py` likewise uses fixed BoT features/labels and protected test/data paths. NF-CSE must not be routed through it by renaming columns and assuming equivalence.

## Later implementation design

Create an allowlisted registry keyed by stable model ID, e.g. `bot-iot-restricted-v1` and a future `nf-cse-finalized-v1` (examples, not runnable IDs). Each entry owns a trusted artifact/hash, input schema/version, feature order/type/unit/range/status rules, finalized versus header observation contract, preprocessing version, label vocabulary, probability support/calibration warning, dataset/group provenance and validation limitations. Binary and multiclass fits need separate model IDs and vocabularies. Do not collapse NF attack names to BoT classes without a separately reviewed taxonomy.

Keep existing endpoints/backward compatibility during a future versioned extension. Add explicit registry discovery and model-specific prediction routes/request types in a later task; never let a caller provide arbitrary artifact filesystem paths. Validate against the selected schema before calling its detector. Keep normalization inside the saved model-specific pipeline, fit nothing at startup/request time, load trusted artifacts once, and return model ID/schema/version/warnings with each result. Probability keys and response validation must derive from the selected vocabulary, not the current four-class Literal. Readiness/errors and per-model limits must be explicit if one registered artifact is unavailable.

Extend safe metadata with bounded declarative fields for frontend rendering: display name, exact feature schema, enum/range/unit/help, requiredness, observation boundary, schema and normalization versions, class labels/colors, supported task and probability status. Validate advertised fields against the loaded model. No arbitrary executable frontend code in metadata.

Dashboard model selection should fetch a compatible schema and clear model-specific input/results/session state on change. Render separate finalized-flow inputs explaining forward/reverse counters and observation boundaries; expose duration units only for a later verified duration-inclusive contract; retain current three-field BoT form for its model. CSV upload must require the selected exact columns, reject duplicate/missing headers and invalid values, preserve row order, enforce size/batch limits, and display model-specific labels/status. Labeled offline evaluation belongs to a separately extended CLI with explicit vocabulary/support policy. Do not imply a finalized-flow form captures live traffic.

Tests before integration: registry unknown ID/path rejection; model/schema/hash mismatch; independent detector lifecycles; old BoT API compatibility; NF units/types/nonfinite handling; class/probability alignment; per-model batch limits; frontend/CSV switching and stale-state clearing; no fit on requests; local trusted artifact and diagnostic sanitization. Update root README alongside every implemented command/route/workflow. Keep the current API and dashboard unchanged until explicitly authorized.
