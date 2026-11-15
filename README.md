# CyberGuard

CyberGuard is an experimental AI-assisted network intrusion detection MVP. It analyzes offline datasets and serves BoT-IoT multiclass and NF-CSE binary inference through a local FastAPI backend, with a BoT-specific offline testing CLI and a multi-model dashboard. It is **not a production IDS** and does not capture packets or detect live attacks.

## Project overview

Implemented:

- Chunked EDA for BoT-IoT and DNS Threats, including duplicate, label-conflict, feature-availability and leakage audits.
- NF-CSE-CIC-IDS2018 audit, versioned completed-flow preprocessing, sealed group-disjoint partitions, two weighted CPU classifier fits with validation-only threshold/model selection, and a guarded frozen final-test evaluation CLI. The frozen binary histogram-boosting artifact is integrated into model-specific FastAPI endpoints; **Streamlit now supports both models through registry discovery**.
- Reusable protocol/port preprocessing and a small CPU-only decision-tree baseline with deterministic group-aware training/validation separation.
- A fitted four-class model: **Normal, DoS, DDoS, Reconnaissance**.
- Model inspection, repeated interactive predictions, chunked CSV predictions and labeled offline evaluation through the network testing CLI.
- A lifespan-managed FastAPI backend with an allowlisted two-model registry, per-model discovery/readiness, typed single/batch predictions and unchanged BoT legacy endpoints.
- A cyberpunk-inspired Streamlit intelligence console with Overview, Interactive Testing, Batch Testing, Model Performance and About pages, using HTTP inference and saved historical reports.
- Training-only Simulation Lab feature-record generator: multiplicity-weighted empirical replay, bounded joint-counter synthesis, deterministic diagnostics, incremental CSV/JSONL export. No inference or network traffic is performed by this generator.
- FastAPI Simulation Lab backend: controlled background generation → bounded FIFO → shared NF inference → bounded events/metrics, with pause/resume/stop and graceful shutdown.
- Streamlit Simulation Lab: HTTP-only configuration and lifecycle controls, fragment-based monitoring, bounded charts/events, retained history and downloadable results.
- Experimental attack-family feasibility study using only frozen NF-CSE train/validation partitions; research results are separate from deployed binary inference.
- Unit/integration tests, reports and reproducible baseline artifacts.

Planned, not implemented: packet capture/live monitoring, streaming replay and alert/storage services. Those components remain scaffolding. The dashboard and Swagger UI provide manual testing, with no live monitoring. Authentication and persistence are not implemented. Simulation-specific in-process workers are implemented; other background services remain planned.

Known limitations:

- The currently trained BoT-IoT model uses only `proto`, `sport`, `dport`. IPs, record IDs, labels, flow state, rates and historical aggregates are excluded. Headers alone do not reliably distinguish every attack.
- Theft and unknown attack classes are unsupported. A Normal prediction does not establish that traffic is safe.
- Training contains only 370 benign records; internal validation had 79 benign records. Reported validation macro-F1 was 0.6753 and benign false-positive rate was 15.19%. These are **internal validation results**, not independent final-test performance or a deployment guarantee.
- NF-CSE validation selects a threshold at 1% benign FPR; this is a selection-set constraint, not an independent deployment guarantee. Infilteration recall remains poor and SQL Injection has only seven validation records. Completed bidirectional flow inputs are required.
- Model probabilities are uncalibrated estimates, not calibrated confidence that traffic is malicious.
- DNS three-class training remains NO-GO because of representation inconsistencies and leakage/ambiguity risks. There is no DNS model integration.

See the [baseline validation report](reports/model_evaluation/bot_iot_validation.md), [feature audit](reports/model_evaluation/bot_iot_feature_audit.md), [EDA summary](reports/dataset_analysis/summary.md) and [DNS investigation](reports/dataset_analysis/dns_investigation.md) for evidence and recommendations.

## Installation and setup

Use a CPU machine with Python **3.13** and `uv` available on `PATH`. The project declares Python >=3.13 and `.python-version` selects 3.13; the current environment was tested with 3.13.12. Approximately 16 GB RAM is sufficient; chunked analyses also need temporary disk space. No GPU is required.

Run commands from the repository root:

```bash
uv sync --frozen --group dev
uv run python --version
uv run pytest -q
```

`uv sync` creates/updates `.venv` using `pyproject.toml` and `uv.lock`, including test/lint dependencies. An initial install requires access to the locked packages and a Python 3.13 interpreter (or permission for uv to obtain one). `uv run` selects this environment automatically; manual activation is optional (`source .venv/bin/activate` on POSIX).

For an already provisioned environment, `uv run --frozen --offline ...` avoids dependency resolution/network access and requires dependencies to be installed or cached. If the default uv cache is unwritable, set `UV_CACHE_DIR` to a writable directory, for example `/tmp/cyberguard-uv-cache`. Direct `.venv/bin/python` / `.venv/bin/pytest` are also usable on POSIX.

### Configuration and locations

EDA, baseline training and the testing CLI require no environment variables or API keys. The backend accepts optional exported `CYBERGUARD_*` settings documented under [Running the application](#running-the-application); development defaults work without configuration. `configs/app.yaml`, `configs/training.yaml` and `configs/replay.yaml` remain empty placeholders and are not read. `configs/nf_cse_training.json` is the implemented NF-CSE training configuration; it is read by the new training CLI. Neither the Python application nor the launcher automatically loads `.env`. CLI arguments control offline input/output/model/chunking options; the training baseline has fixed settings documented in its report.

Datasets must be acquired separately; raw data and models are ignored by Git. Preserve the raw files at these exact paths when running EDA or baseline training:

```text
data/raw/bot_iot/train/UNSW_2018_IoT_Botnet_Final_10_best_Training.csv
data/raw/bot_iot/test/UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv
data/raw/dns_threats/train_combined_multiclass.csv
data/raw/dns_threats/test_combined_multiclass.csv
data/raw/nf-cse-cic-ids2018/<discovered-bag-directory>/data/NF-CSE-CIC-IDS2018.csv
data/raw/nf-cse-cic-ids2018/<discovered-bag-directory>/data/NetFlow_v1_Features.csv
data/raw/nf-cse-cic-ids2018/nf-data2018.zip
```

The prediction CLI and API need only a fitted model and supplied input records; raw datasets are not required. Default artifact locations:

```text
models/network/bot_iot_restricted_baseline.joblib   # fitted preprocessing + classifier
models/network/bot_iot_split_manifest.csv.gz       # group/label/count/partition audit
reports/model_evaluation/bot_iot_validation_metrics.json
models/network/nf_cse_binary_completed_flow.joblib
models/network/nf_cse_binary_completed_flow.metadata.json
reports/model_evaluation/nf_cse_binary/training_report.md
```

Use the existing trusted trained artifact when available. The CLI's `--model PATH` selects another trusted compatible artifact. Joblib artifacts deserialize Python objects: only load files you trust, and use compatible Python/dependency versions. Custom pipeline classes live under `src/cyberguard`; the executable scripts add this import path automatically.

## Project structure

```text
CyberGuard/
├── AGENTS.md                       # repository instructions, including README maintenance
├── README.md                       # current usage and workflows
├── pyproject.toml / uv.lock         # dependencies and pytest configuration
├── configs/                        # future application configuration placeholders
├── data/raw/                       # immutable external datasets (Git-ignored)
├── data/processed/nf_cse_cic_ids2018/ # sealed compact binary partitions + manifests (Git-ignored)
├── data/samples/                   # optional local CSV samples (Git-ignored)
├── models/network/                 # fitted pipeline and group manifest (Git-ignored)
├── models/simulation/nf_cse/        # train-derived simulation arrays/index/metadata (Git-ignored)
├── reports/dataset_analysis/        # EDA and DNS investigation
├── reports/model_evaluation/        # baseline and user-requested evaluation reports
├── runtime/                        # local predictions/output (Git-ignored)
├── scripts/                        # EDA, training, network testing, API/dashboard launchers
├── src/cyberguard/features/         # BoT pipeline; nf_cse normalizer + disk-backed preparation
├── src/cyberguard/training/         # group assignment, baseline fit, validation reporting
├── src/cyberguard/research/         # isolated weighted attack-family feasibility study
├── src/cyberguard/simulation/       # profiles, incremental generator, background engine, validation/export/audit
├── src/cyberguard/testing/          # implemented network_model_cli.py; other files are placeholders
├── src/cyberguard/api/              # app factory, lifespan, dependency injection and routes
├── src/cyberguard/inference/        # artifact loaders, model_registry.py adapters and NetworkDetector
├── src/cyberguard/core/             # backend settings, legacy schemas, model_schemas.py, settings and logging
├── src/cyberguard/dashboard/        # registry client, contracts, model_ui session/forms, CSV/report readers and pages
├── .streamlit/config.toml          # dark theme, localhost, 5 MiB server upload limit
├── src/cyberguard/{streaming,storage,ingestion}/
│                                   # unimplemented application scaffolding
└── tests/                          # unit software tests and API integration tests
```

`tests/integration/test_api.py` and `test_model_api.py` exercise the API with FastAPI TestClient and synthetic local model fixtures. Other integration files remain placeholders. Synthetic fixtures in the unit tests check software behavior; they are not evidence of detection generalization.

## Running scripts

All examples below run from the repository root. The table lists working user-facing entry points; empty scripts are listed separately to avoid implying they work.

| Script | Purpose | Example command |
| --- | --- | --- |
| `scripts/inspect_datasets.py` | Analyze both datasets and write EDA reports | `uv run python scripts/inspect_datasets.py --chunk-size 50000 --sample-size 30000` |
| `scripts/inspect_nf_cse.py` | Audit the NF-CSE download and design its future pipeline | `uv run python scripts/inspect_nf_cse.py --chunk-size 50000` |
| `scripts/prepare_nf_cse.py` | Normalize and prepare sealed binary NF-CSE partitions | `uv run python scripts/prepare_nf_cse.py --chunk-size 50000 --seed 20261115` |
| `scripts/train_network_baseline.py` | Train the fixed restricted network baseline | `uv run python scripts/train_network_baseline.py` |
| `scripts/evaluate_nf_cse.py` | Evaluate the frozen NF-CSE test once; inspect published results | `uv run python scripts/evaluate_nf_cse.py --inspect` |
| `scripts/study_attack_families.py` | Research direct/hierarchical attack-family feasibility on frozen train/validation | `uv run python scripts/study_attack_families.py --threads 4` |
| `scripts/train_nf_cse.py` | Train/validate two NF-CSE binary candidates, inspect or verify the selected artifact | `uv run python scripts/train_nf_cse.py train --threads 4` |
| `scripts/test_network_model.py` | Inspect, predict and evaluate using a fitted model | `uv run python scripts/test_network_model.py interactive` |
| `scripts/build_traffic_profiles.py` | Build training-only NF simulation profiles and diagnostics | `uv run python scripts/build_traffic_profiles.py` |
| `scripts/generate_traffic.py` | Stream training-derived NF feature records | `uv run python scripts/generate_traffic.py --count 10000 --benign-ratio 0.9 --mode empirical --seed 42` |
| `scripts/start_api.sh` | Serve the fitted model over localhost HTTP | `bash scripts/start_api.sh` |
| `scripts/start_dashboard.sh` | Launch the HTTP-based Streamlit testing workspace | `bash scripts/start_dashboard.sh` |
| `main.py` | Initial greeting stub only | `uv run python main.py` |

### Dataset inspection

Prerequisites: all four raw CSVs at the documented locations and writable report/temporary directories. No required arguments. Optional arguments:

| Option | Default | Meaning |
| --- | --- | --- |
| `--chunk-size` | `50000` | Positive CSV chunk size |
| `--sample-size` | `30000` | Positive uniform sample size per split for quantile/distribution estimates |
| `--output-dir` | `reports/dataset_analysis` | Generated report/plot directory |
| `--temp-dir` | System temporary directory | Disk-backed audit workspace; budget several GB free |

Outputs: `bot_iot_report.md`, `dns_threats_report.md`, `summary.md`, six SVG plots and two correlation CSVs. Counts and moments cover full files; quantiles/outlier estimates use samples. Raw records are not modified or merged for training. **Rerunning replaces these generated EDA artifacts.** This script reads both official splits for descriptive analysis; that does not make a model evaluation independent. It does not regenerate the separately authored `dns_investigation.md`.

```bash
uv run python scripts/inspect_datasets.py --help
```

### NF-CSE-CIC-IDS2018 audit

Prerequisites: the extracted BagIt dataset under `data/raw/nf-cse-cic-ids2018/`, including `bag-info.txt`, `bagit.txt`, `FurtherInformation.txt`, both SHA-1 manifests and both payload CSVs, plus exactly one downloaded ZIP in that directory tree. The opaque bag directory is discovered, not hardcoded. Download/extract separately; the audit never downloads or extracts over raw files. Existing Python 3.13 `uv` dependencies suffice; no model or environment variables are required.

```bash
uv run python scripts/inspect_nf_cse.py --help
uv run python scripts/inspect_nf_cse.py --chunk-size 50000 --sample-size 30000
uv run pytest -q tests/unit/test_inspect_nf_cse.py
```

No required arguments. All options:

| Option | Default | Purpose |
| --- | --- | --- |
| `--input-dir PATH` | `data/raw/nf-cse-cic-ids2018` under the repository | Discover exactly one dataset CSV and one ZIP, with accompanying BagIt metadata |
| `--output-dir PATH` | `reports/dataset_analysis/nf_cse_cic_ids2018` under the repository | Write audit evidence/reports; **replaces generated files on rerun** |
| `--chunk-size N` | `50000` | Positive maximum CSV chunk size |
| `--sample-size N` | `30000` | Positive seeded sample size for approximate quantiles/correlations |
| `--temp-dir PATH` | System temporary directory | Existing writable directory for disposable SQLite indexes |

Progress is printed to the terminal. Outputs: [overview](reports/dataset_analysis/nf_cse_cic_ids2018/overview.md), `feature_audit.md`, `data_quality.md`, `evaluation_strategy.md`, `preprocessing_design.md`, `integration_plan.md`, `audit.json` and two self-contained log-scale class-count SVGs under `figures/`. Counts, checksums and duplicate comparisons cover the full file; quantiles/correlations are sampled. No records are removed or relabeled, and no preprocessing, splits or models are generated. Existing BoT-IoT/DNS reports, models and API/dashboard behavior remain separate.

CPU only; use 25k–50k chunks, a bounded sample, and at least 8 GiB free temporary disk for combined exact indexes/sorts, plus source storage. SQLite limits its page cache to 64 MiB; endpoint-connectivity diagnostics stop explicitly above 200,000 host tokens rather than growing without bound. Measured runtime/RAM/disk and checksum results are in the overview. Missing/ambiguous inputs, unsupported schema, invalid UTF-8 and filesystem/database errors produce exit status 2; integrity failures remain visible in the evidence and must block future training. Output/temporary directories inside raw inputs are refused.

**Phase 5A status:** audit/design only; its reports are historical. Phase 5B implements the preparation workflow below, with no model training. The initial contract is offline finalized flows, not packet or partial-flow detection. Counter accounting/orientation, rare-class/group support and missing capture/session provenance require explicit review. The initial recommendation uses seven header/final-counter fields; duration, L7 codes and cumulative flags are excluded pending exporter evidence. Phase 5B freezes deterministic input/group rules and creates a reserved test. Phase 5C below trains and validates the bounded CPU baselines using that frozen snapshot. Capture/session separation is preferred; a duplicate-group fallback cannot establish independent deployment generalization. NF-CSE features/labels cannot be passed directly to the existing three-field/four-class BoT API. See [integration plan](reports/dataset_analysis/nf_cse_cic_ids2018/integration_plan.md).

### NF-CSE binary preprocessing and reproducible splitting

Prerequisites: the NF-CSE CSV and adjacent `NetFlow_v1_Features.csv` at the location above, provisioned Python 3.13 `uv` dependencies, and writable output/temp directories. No model, service, environment variables or new dependency is needed. Actual source paths are discovered; required feature descriptions must match the approved dictionary. The workflow never reads BoT-IoT or DNS data.

```bash
uv run python scripts/prepare_nf_cse.py --help
uv run pytest -q tests/unit/test_nf_cse_preparation.py
# Optional full-file preflight: performs normalization/grouping but publishes no partitions.
uv run python scripts/prepare_nf_cse.py --dry-run --chunk-size 50000 --seed 20261115
# Preparation always performs the same preflight before materializing.
uv run python scripts/prepare_nf_cse.py --chunk-size 50000 --seed 20261115
```

No required CLI arguments. Options:

| Option | Default | Meaning |
| --- | --- | --- |
| `--input-dir PATH` | `data/raw/nf-cse-cic-ids2018` under the repository | Discover exactly one dataset CSV and its adjacent feature dictionary |
| `--output-dir PATH` | `data/processed/nf_cse_cic_ids2018` under the repository | Atomically publish a new compact dataset snapshot |
| `--chunk-size N` | `50000` | Positive CSV and compact shard batch size |
| `--seed N` | `20261115` | Frozen hash-split seed, integer 0..2^63−1; **not for searching better distributions** |
| `--temp-dir PATH` | System temporary directory | Existing writable directory for disposable SQLite grouping/sorts |
| `--dry-run` | Off | Full descriptive preflight and terminal JSON, no processed outputs or preparation report |

The frozen raw contract is `nf-cse-netflow-v1-completed-flow-v1`, ordered `PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS`. These are finalized, bidirectional export records: IN/OUT preserve the supplied incoming/outgoing counter definitions. Initiator orientation, byte accounting and cross-exporter parity are unverified. Header-only records are rejected; no first-packet, partial-flow or live detection is supported. IPs, duration, L7 codes, cumulative flags and every label/identifier are excluded from predictors. Original `Label` 0=Benign / 1=Attack is the only target; `Attack` stays offline metadata. No multiclass model is created.

Normalization is stateless: fixed protocol aliases/categories, exact integer conversion, protocol-aware ports, explicit missing/invalid/not-applicable/sentinel states, and legitimate zero preservation. Counts are int64 bounded at 2^53−1 for exact future float64 conversion; do not cast them to float32. Missing field names fail, while explicit missing values get a status. The reusable `cyberguard.features.nf_cse.NFCSECompletedFlowFeatures` produces fixed value/status fields for a future saved pipeline without learning statistics, scaling or target encoding. The machine-readable contract documents ranges, units, field/status order and categorical protocol handling. These new modules do not alter the BoT normalizer.

Exact normalized feature groups, including all conflicting labels and multiplicities, use schema/seed/vector SHA-256 assignment to nominal 60/20/20 train/validation/test. Capture/session/time independence cannot be established; a both-endpoint-disjoint all-class split was infeasible in Phase 5A. Before staging any partition, fixed guards require each achieved row fraction within 10 percentage points of target and at least 10 distinct groups per binary class per partition. Failure returns status 2 and reports the blocker without changing seed/labels/guards. These are engineering guards, not evidence of independent episodes.

Outputs:

```text
data/processed/nf_cse_cic_ids2018/
├── train/part-*.npz
├── validation/part-*.npz
├── test/part-*.npz                 # RESERVED; no predictions/model selection
├── metadata/
│   ├── feature_contract.json
│   ├── split_manifest.json
│   ├── split_manifest.sha256
│   ├── class_distribution.json
│   └── preprocessing_manifest.json
└── README.md                      # generated format/weighting/sealing instructions
```

NPZ arrays: canonical `features` (seven int64 columns), `Label` (uint8), `Attack` (Unicode metadata), `multiplicity` (uint64 original row count), `group_id` (S64 digest identifier). Load with `numpy.load(..., allow_pickle=False)` or `cyberguard.features.nf_cse_preparation.iter_partition(root, "train")`; the reader checks only the requested partition's shard hashes, with explicit test selection required. For canonical `features`, call `nf_cse.model_features(DataFrame(features, columns=nf_cse.RAW_FEATURES))`; for **raw** inputs, use `NFCSECompletedFlowFeatures.transform`. Do not re-normalize canonical negative statuses as raw tokens. No estimator is included or fitted.

Compaction preserves separate `(normalized vector, Label, Attack)` multiplicities. Use multiplicity as sample weight for original-record population metrics; any future class balancing is computed from train only. Validation/test retain original weights. Compact fitting may change estimator rules based on unweighted sample counts. Neither repeated records nor weights establish independent observations. Keep validation out of final fitting under this experiment; reserve test until a later authorized frozen-model evaluation. Checksums seal against accidental changes; files are **not encrypted or access-controlled**.

The command prints progress, full-data descriptive ambiguity and achieved supports, then writes [preparation_report.md](reports/dataset_analysis/nf_cse_cic_ids2018/preparation_report.md). A compatible rerun verifies/reuses existing artifacts without rewriting them. Different source/contract/code/seed or changed files fail; **there is no overwrite option**. Shard size can vary between fresh snapshots; row/group assignment remains invariant. Output/temp paths inside raw inputs are refused. Errors exit 2; success/dry-run exit 0. The default preparation report is regenerated by non-dry invocations; preserve reviewed reports if doing separate experiments.

Use CPU only, 25k–50k chunks and several GB free temporary disk (budget 8 GiB for grouping/sorts plus processed storage). No expanded raw CSV copies or worker pool are created. A full dry-run costs almost another indexing pass; it is optional because materialization already checks the plan. Actual runtime, memory, sizes, ambiguity and distributions are in the preparation report and manifests. NF-CSE preprocessing is implemented; **NF-CSE training and model-specific API routing are implemented; multi-model dashboard integration is implemented in Phase 5F**. Current BoT API forms/CSV schemas cannot be used for this model; see the [integration plan](reports/dataset_analysis/nf_cse_cic_ids2018/integration_plan.md).

### NF-CSE frozen final evaluation (Phase 5D)

This standalone CPU CLI needs the frozen trusted local histogram-boosting model and adjacent metadata under `models/network/`, the sealed `data/processed/nf_cse_cic_ids2018/` snapshot, and `reports/model_evaluation/nf_cse_binary/validation_metrics.json`. Use the installed Python 3.13 uv environment; no server, configuration file, API key or environment variable is required. Both thresholds are fixed: high sensitivity `0.03090052128234102`, lower false alarm `0.5`; scores at or above the threshold map to Attack (1), otherwise Benign (0). Neither preprocessing nor model is refitted.

```bash
uv run python scripts/evaluate_nf_cse.py --help
# Authorized one-time final evaluation only; refuses an existing result/attempt:
uv run python scripts/evaluate_nf_cse.py --allow-final-test
# Normal subsequent use: verify report hashes and inspect, without data/model access:
uv run python scripts/evaluate_nf_cse.py --inspect
uv run pytest tests/unit/test_nf_cse_final_evaluation.py -q
```

No subcommand is required. `--allow-final-test` is mandatory for scoring and mutually exclusive with `--inspect`. Optional `--threads` (default 4) bounds CPU threads and `--batch-size` (default 50000) bounds prediction batches; neither changes thresholds or populations. Input/model/output paths are fixed to the frozen project artifacts. Exit 0 means success; exit 2 means missing consent, invalid/missing metadata, failed integrity, or existing results/attempt. There is no force/overwrite or alternate-output option. `--inspect` requires previously published results and verifies their hashes.

The evaluator checks model/metadata, frozen thresholds, class mapping, exact contract, preprocessing code, manifest and every test checksum before test inference; population checks require 1,689,195 original rows (1,485,639 Benign / 203,556 Attack), 953,681 compact records and 947,108 groups. Compact records retain original multiplicity weights and conflicting labels. Test encoding follows the sealed canonical-to-model path; raw-input inference is checked with synthetic software probes. Training and validation shards are never opened; the frozen validation metrics JSON supplies comparisons only. The process uses bounded compact arrays and per-shard encoding, never expanded rows. Peak RSS, prediction throughput, CPU settings and runtime are recorded.

Outputs are atomically published under `reports/model_evaluation/nf_cse_binary/final_test/`: [evaluation_report.md](reports/model_evaluation/nf_cse_binary/final_test/evaluation_report.md), `test_metrics.json`, `threshold_comparison.csv`, `confusion_matrices.csv`, `attack_family_recall.csv`, `validation_test_comparison.csv`, `score_summary.csv`, `evaluation_manifest.json`, and self-contained SVG figures. The manifest records source hashes, integrity checks, dependencies, timestamp and configuration. A persistent exclusive `reports/model_evaluation/nf_cse_binary/final_test_attempt.json` is written before test access; interrupted attempts also block automatic retries. Preserve failed-attempt evidence for investigation; do not delete the ledger or outputs to rerun for tuning. Inspect published results instead. Missing artifacts require restoring the exact frozen snapshot, never silently regenerating it against observed test results.

Validation was used for model/threshold selection; this final test evaluates those frozen choices once. After final evaluation it is a consumed benchmark: tuning/retraining/calibrating from its results and rerunning invalidates its untouched-test role. Further development needs new development data and an independent holdout. Offline group-disjoint test metrics are **not** real-world deployment effectiveness, independent capture/session generalization, packet detection, or proof of calibrated probabilities. Small family supports and Infilteration weakness remain material limitations. Model-specific FastAPI inference is implemented in Phase 5E; multi-model dashboard integration is implemented in Phase 5F.

Phase 5D final evaluation is **complete**. On 1,689,195 original weighted test records:

| Frozen threshold | Attack recall | Benign FPR | Precision | F1 |
|---|---|---|---|---|
| `0.03090052128234102` | 94.9925% | 1.24108% | 91.2947% | 0.931069 |
| `0.5` | 94.3563% | 0.043752% | 99.6627% | 0.969370 |

Final test ROC-AUC is **0.988610**, AP **0.971543**, Brier **0.0069275** (diagnostic, not calibration evidence). The sensitivity threshold **exceeds** its validation 1% FPR selection constraint on test; recall falls 0.1146 percentage points and FPR rises 0.2424 points. At 0.5 recall falls 0.0789 points and FPR rises 0.0118 points. Infilteration recall remains **18.17% / 8.16%**; SQL Injection detects **3/5 / 0/5**, with inadequate support for a robust category claim. Evaluation used four CPU threads, **6.56 s** through plots/input rehashes, **559.17 MiB** peak RSS and approximately **638k compact predictions/s** (encoding/IO excluded). These are offline test results; see the report for confusion matrices, all family names, score distributions, exact deltas and limitations. **Do not rerun scoring; use `--inspect`.**

### NF-CSE binary training, inspection and validation

Prerequisites: the existing sealed Phase 5B snapshot at `data/processed/nf_cse_cic_ids2018`, Python 3.13 and installed locked dependencies. Raw datasets and running API/dashboard services are not needed. **Do not regenerate partitions to train or choose a different split seed.** Run the preprocessing/training unit tests first:

```bash
uv run pytest -q tests/unit/test_nf_cse_preparation.py tests/unit/test_nf_cse_training.py
uv run python scripts/train_nf_cse.py --help
uv run python scripts/train_nf_cse.py train --help
uv run python scripts/train_nf_cse.py train --threads 4 --seed 20261115
uv run python scripts/train_nf_cse.py info
uv run python scripts/train_nf_cse.py verify
```

The CLI requires one subcommand (`train`, `info`, `verify`); `--help` does not fit anything. Each subcommand supports `--help`. Training has no required options:

| `train` option | Default | Meaning |
| --- | --- | --- |
| `--processed-dir PATH` | `data/processed/nf_cse_cic_ids2018` under the repository | Existing sealed train/validation shards and common contract/manifest |
| `--output-dir PATH` | `models/network` under the repository | Selected artifact and its metadata; existing BoT files remain separate |
| `--report-dir PATH` | `reports/model_evaluation/nf_cse_binary` under the repository | New validation report directory; nonempty directories are refused |
| `--config PATH` | `configs/nf_cse_training.json` under the repository | Strict JSON configuration for one logistic and one histogram fit |
| `--threads N` | `min(4, CPU count)` | Positive CPU thread cap, applied to BLAS/OpenMP |
| `--seed N` | `20261115` | Model/development-sampling seed; does not change the frozen split |
| `--dev-fraction F` | `1.0` | Optional `(0,1]` training-only hash-group sample; validation remains full |
| `--batch-size N` | `50000` | Positive validation scoring batch size |

`info` and `verify` accept `--model PATH`, default `models/network/nf_cse_binary_completed_flow.joblib`. `verify` also accepts `--threads N` (default up to four). Both require the adjacent `.metadata.json` checksum/contract file. They load only a **trusted local** joblib, with compatible Python/library versions and project classes installed/on the import path. Joblib deserialization can execute code: checksums detect changes, not authenticity. `info` prints artifact metadata to terminal JSON; `verify` runs two synthetic completed-flow software probes, checks class/probability ordering and threshold application, and prints JSON. Neither fits a model or accesses datasets. Synthetic predictions are not accuracy evidence.

The default JSON config disables class balancing, sets logistic `C=1`, `max_iter=200`, `tol=1e-4`, and histogram `max_iter=150`, `max_leaf_nodes=31`, `learning_rate=0.1`, `l2_regularization=1`, `min_samples_leaf=20`. The implementation fixes logistic solver to LBFGS, histogram `early_stopping=False`, and native protocol/status categorical fields. Unsupported configuration keys fail; no automated parameter search or full-data cross-validation is implemented. Optional `balance_classes=true` derives factors from the selected training population only and multiplies original multiplicity once; estimator class weights remain disabled. Validation always uses original multiplicities.

Both candidates use the frozen seven-field completed-flow contract. Logistic adds fixed counter `log1p`, fixed port division, fixed categorical one-hot encoding and multiplicity-weighted **train-only** numeric scaling; all fitted transformations are serialized. Histogram uses Phase 5B's fixed model fields with native categorical protocol/status handling. No IPs, duration, labels, Attack names or identifiers enter either predictor matrix. The reserved test is inaccessible to the training loader/audit guard; common manifest test objects are skipped without decoding, and test shards/class-distribution metadata are not opened. Only train/validation artifacts are verified/rehashed; no raw CSV or split regeneration occurs.

Threshold selection uses validation only: maximize weighted attack recall subject to benign FPR <=1%, tie-breaking by lower FPR then higher threshold. `score >= threshold` means Attack. Results at 0.5 are reported separately. Equal-score ties stay together; reject-all is explicit if useful recall cannot meet the constraint. Selection ranks recall at the FPR constraint, then precision, average precision, minimum family recall, CPU throughput and model size. Exactly two configured fits are recorded. Probabilities are uncalibrated, and threshold/model selection on validation makes these selection-set estimates. Keep validation out of final fitting. Phase 5D has now completed the separately authorized frozen-model final evaluation; do not reuse its results for further selection.

Outputs:

```text
models/network/nf_cse_binary_completed_flow.joblib
models/network/nf_cse_binary_completed_flow.metadata.json
reports/model_evaluation/nf_cse_binary/
├── training_report.md
├── model_comparison.csv
├── validation_metrics.json
├── classification_report.csv
├── confusion_matrix.csv
├── threshold_analysis.csv
├── attack_family_recall.csv
└── figures/                       # six self-contained weighted-validation SVGs
```

The selected artifact accepts raw fields `PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS`; `predict()` returns numeric 0/1, `predict_labels()` returns Benign/Attack, and `predict_proba()` columns are `[Benign, Attack]`. The validation-selected threshold is stored with it. Do not feed canonical negative status codes to its raw-input interface. Phase 5E serves this model through its own typed FastAPI adapter; legacy endpoints retain the three-input/four-class BoT contract; Phase 5F dashboard requests use the selected model-specific endpoint. Changing the BoT artifact path is not model switching.

Progress, fit times and achieved validation FPR/recall print to the terminal. Existing NF model/metadata and nonempty report directories are refused; no overwrite option is provided. Use a distinct directory only for a documented experiment, not repeated hidden validation tuning. Failures return exit 2; success returns 0. Partial experiment directories after a failed run require review before retrying. The existing BoT model is never overwritten.

CPU/RAM: original multiplicities stay weights; no expanded copies. Models fit sequentially, compact float64 arrays preserve integer precision, and threadpool limits constrain CPU use. Budget several GB RAM within the approximately 16 GB target, plus model/report storage; measured fit times, cumulative peak RSS, candidate sizes, compact-record throughput and raw-probe latency appear in the report. If resources require a development sample, choose it **before fitting** and use separate output/report directories, for example:

```bash
uv run python scripts/train_nf_cse.py train --dev-fraction 0.05 --threads 2 \
  --output-dir models/network/nf_cse_development \
  --report-dir reports/model_evaluation/nf_cse_development
```

That is sampled training, not full-data performance. Do not sample validation or select the fraction/seed repeatedly to improve reported results. All scores must be described as **Offline group-disjoint validation on NF-CSE-CIC-IDS2018**, with no capture/session/host/time independence or deployment claim. Byte accounting/orientation, generation artifacts, mixed-label groups and small minority-family supports remain limitations. See the [training report](reports/model_evaluation/nf_cse_binary/training_report.md) for the actual comparison and selected artifact.

Current full-data NF-CSE result: histogram boosting selected at threshold `0.03090052128234102`, validation attack recall **95.11%**, benign FPR **0.9987%**, precision **92.99%**, and average precision **0.9730**. At threshold 0.5 it has lower recall (**94.44%**) and much lower benign FPR (**0.0320%**). The selected operating point follows the requested recall objective and increases false alarms substantially; it is not a deployment recommendation. See the report for family-level failures and complete metrics.

### Network baseline training

Prerequisites: BoT-IoT **training** CSV, a working environment and passing pipeline tests:

```bash
uv run pytest -q tests/unit/test_preprocessing.py tests/unit/test_network_training.py
uv run python scripts/train_network_baseline.py
```

There are **no required or optional CLI arguments**; this script has no argparse interface. Do not pass `--help` expecting a dry run: invoking it runs training. Settings are fixed in the implementation; there is no hyperparameter search. All Theft rows are counted/excluded as unsupported attacks, never mapped to Normal.

Outputs: the model and manifest listed above, plus `reports/model_evaluation/bot_iot_validation.md`, `bot_iot_validation_metrics.json` and `bot_iot_validation_confusion.csv`. It prints validation macro-F1, benign FPR, model path and memory usage. **It replaces the existing baseline artifacts and validation results.** It reads only the original training CSV, checks its SHA-256 unchanged, and neither trains DNS nor evaluates the official test file. Do not rerun training merely to use the testing CLI.

### Network testing CLI

Prerequisites: a trusted fitted model with the existing preprocessing/input contract. No raw dataset is required for `info` or `interactive`. The next section contains complete examples.

| Command | Required arguments | Optional arguments | Output |
| --- | --- | --- | --- |
| `info` | None | `--model PATH` | Inspected model details as terminal JSON; no files |
| `interactive` | None | `--model PATH` | Repeated prompted predictions/probabilities; no files |
| `predict` | `--input CSV --output CSV` | `--model PATH`, `--chunk-size N`, `--probabilities`, `--overwrite`, `--allow-official-test` | Prediction CSV |
| `evaluate` | `--input CSV --output DIRECTORY` | Same as `predict`, plus `--exclude-unsupported` | Five-file evaluation directory |

`--model` defaults to `models/network/bot_iot_restricted_baseline.joblib`; chunk size defaults to 10,000. Options belong after the subcommand. Every subcommand supports `--help`. Missing models, malformed schemas/CSVs, output collisions and protected paths produce a clear error and exit status 2. Successful commands return 0. The CLI never retrains, refits preprocessing, tunes or selects a model.

### API launcher

Prerequisites: Bash, `uv` on `PATH`, provisioned project dependencies (`uv sync --frozen --group dev`) and a trusted compatible fitted model. The launcher runs from any working directory when invoked by its path; it locates the repository, sets the package import path and uses `uv run --frozen --no-sync` so it does not install packages or train a model on launch. It prints a dependency/setup diagnostic if imports fail.

There are no script arguments; exported `CYBERGUARD_*` variables configure it. It starts an HTTP service, writes logs to stderr, and creates no prediction files or model artifacts. Default address: `127.0.0.1:8000`. Automatic reload is disabled. Stop with Ctrl-C. See the endpoint/configuration examples below. It has no authentication or live traffic capture.

### Existing placeholders

`scripts/prepare_data.py`, `scripts/train_models.py` and `scripts/evaluate_models.py` are empty. They have no implemented arguments, outputs or runnable workflows; do not use them as launchers. `main.py` only prints `Hello from cyberguard!` and accepts no implemented options; it does not launch an application.

### Dashboard launcher

Prerequisites: Bash, `uv`, installed locked dependencies including Streamlit/Plotly, and the existing FastAPI backend for predictions. Raw datasets are not needed. There are no required or optional script arguments. Export `CYBERGUARD_API_URL` to select a different backend; it defaults to `http://127.0.0.1:8000`. The launcher works from any cwd when invoked by its path, checks dependencies without installing them, and serves `http://127.0.0.1:8501`. Stop with Ctrl-C. It creates no model, dataset or prediction files; downloads are explicitly requested in the browser. See [Dashboard workflow](#dashboard-workflow) for usage, limits and direct invocation.

## Testing the Trained Network Model

**Manual prediction** means entering or supplying header fields to the saved classifier. **Offline evaluation** compares predictions with provided labels. **Real network intrusion detection** additionally needs validated capture, causal feature extraction, deployment-oriented evaluation and operational handling, which are not implemented.

### Inspect a model

```bash
uv run python scripts/test_network_model.py info
uv run python scripts/test_network_model.py info --model models/network/bot_iot_restricted_baseline.joblib
```

The CLI displays the serialized type, feature/class metadata when exposed, pipeline steps when inspectable, probability support, file size and SHA-256. Baseline metadata is included only when its recorded model hash matches the selected artifact. Unavailable metadata is reported as null rather than guessed.

### Interactive predictions

```bash
uv run python scripts/test_network_model.py interactive
```

Enter protocol, source port and destination port. Enter `q`, `quit` or `exit` at the protocol prompt, answer `n` after a prediction, or use EOF/Ctrl-C to exit. Each run loads the model once. Actual predictions and, when available, per-class **uncalibrated model probabilities** come from the saved artifact. No probability is a guarantee that traffic is malicious or benign.

The pipeline accepts case/whitespace protocol aliases such as `TCP`, `6`, `udp`, `17`, `icmp`, `1`, `ipv6-icmp`, `icmpv6`, `58`, and `arp`. TCP/UDP ports accept decimal integers (leading zeroes allowed), hex such as `0x50`, valid port zero, and sentinels `-`/`-1`. Missing, malformed and out-of-range port tokens are represented by existing pipeline statuses; they are not silently dropped or clamped. Text `80.0` is invalid; text `80` is valid. ICMP/ARP fields are not interpreted as TCP/UDP ports. Unknown protocols are represented as `other`.

### Batch CSV prediction

Create reproducible **synthetic demonstration records**, with no claim that they are independent attack/benign evidence:

```bash
mkdir -p data/samples
cat > data/samples/network_test.csv <<'CSV'
proto,sport,dport
tcp,49152,80
udp,50000,53
tcp,12345,22
icmp,-1,-1
CSV
uv run python scripts/test_network_model.py predict \
  --input data/samples/network_test.csv \
  --output runtime/predictions.csv \
  --chunk-size 2 --probabilities
```

Output preserves original columns, token strings and input row order, adding `prediction` and optional `probability_Normal`, `probability_DoS`, `probability_DDoS`, `probability_Reconnaissance` columns aligned by the model's class names. Additional input columns are preserved but are not model features. Probability columns require `predict_proba()`.

CSV headers must be unique and nonempty and include `proto,sport,dport`. Every data record must have the header's field count; blank records and malformed quoting/row widths are errors. Empty files and header-only files are errors. Input columns named like generated output columns must be renamed to prevent overwriting them. Feature tokens handled by the model's invalid/missing statuses remain in the output; a rejected record aborts the run rather than being dropped.

Outputs are staged until the input succeeds. Existing output files/directories are refused unless **`--overwrite`** is explicit. The input CSV, selected model artifact and `data/raw/` cannot be output destinations, even with that flag.

### Evaluate a labeled CSV

The required schema adds `category` to the three predictor columns. Supported labels are exactly `Normal`, `DoS`, `DDoS`, `Reconnaissance` after trimming label whitespace. Example software fixture:

```bash
cat > data/samples/labeled_network_test.csv <<'CSV'
proto,sport,dport,category
tcp,49152,80,DDoS
udp,50000,53,Normal
tcp,12345,22,Reconnaissance
tcp,40000,80,DoS
CSV
uv run python scripts/test_network_model.py evaluate \
  --input data/samples/labeled_network_test.csv \
  --output reports/model_evaluation/manual_test \
  --chunk-size 2
```

These labels are **illustrative assignments**, not verified ground truth. Scores on this fixture test the CLI only. Use independently collected, correctly labeled data for meaningful evaluation.

Evaluation produces:

```text
reports/model_evaluation/manual_test/
├── metrics.json                 # provenance, supports, exclusions, timing and metrics
├── classification_report.csv    # per-class precision/recall/F1/support
├── confusion_matrix.csv         # fixed actual-row / predicted-column ordering
├── predictions.csv             # every original row + prediction + evaluation status/label
└── summary.md                   # readable results, exclusions and limitations
```

By default, unsupported labels—including Theft, unknown names and empty labels—fail evaluation and report counts. `--exclude-unsupported` explicitly excludes them from four-class metrics and records their counts. Their original rows and predictions remain in `predictions.csv` with `evaluation_status=excluded_unsupported`. The model cannot recognize Theft; it is never relabeled benign. If all rows are excluded, metrics are undefined, not a successful four-class benchmark.

### Interpret metrics and protect evaluation boundaries

- Accuracy is the fraction correct; extreme imbalance can make it misleading.
- Balanced accuracy is mean recall over classes with actual support. Absent classes are explicitly listed; their recall is undefined (`null`/blank).
- Macro-F1 averages the fixed four target classes, with undefined class F1 contributing zero under sklearn's `zero_division=0`. Weighted-F1 weights by actual row support. Incomplete class coverage cannot establish complete four-class performance.
- Per-class support is always shown. Confusion rows are actual labels and columns are predictions in order: **Normal, DoS, DDoS, Reconnaissance**.
- Benign FPR is Normal rows predicted as any attack divided by all Normal rows. Without Normal examples it is **undefined**, not zero.
- Throughput covers prediction/probability calls and DataFrame formatting for all input rows, excluding model load and CSV disk I/O. It is not live packet throughput. Repeated/related records are not independent observations.

**Validation** is the deterministic group-aware held-out partition of the original BoT-IoT training file; the saved manifest identifies its groups. Evaluating the entire original training CSV includes fitted records and is not independent testing. The CLI warns on that documented path and its symlink/hardlink aliases.

The **reserved official test** is `data/raw/bot_iot/test/UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv`. No command selects it automatically. Both `predict` and `evaluate` refuse this documented path and filesystem aliases unless `--allow-official-test` is explicitly supplied. Evaluating it consumes the reserved benchmark: subsequent model or preprocessing changes informed by its results invalidate its status as an untouched final test. The flag does not bypass unsupported-label checks or output protections. Path guards do not identify independently copied/renamed content, so preserve provenance yourself. The official test was not evaluated while implementing or demonstrating this CLI.

## Testing and development

```bash
# Complete implemented test suite
uv run pytest -q

# Individual modules
uv run pytest -q tests/unit/test_network_model_cli.py
uv run pytest -q tests/unit/test_preprocessing.py
uv run pytest -q tests/unit/test_network_training.py
uv run pytest -q tests/unit/test_inspect_datasets.py
uv run pytest -q tests/unit/test_network_inference.py
uv run pytest -q tests/integration/test_api.py
uv run pytest -q tests/unit/test_dashboard.py
uv run pytest -q tests/unit/test_dashboard_design.py
uv run pytest -q tests/unit/test_simulation.py
uv run pytest -q tests/unit/test_simulation_engine.py
uv run pytest -q tests/unit/test_simulation_dashboard.py

# CLI and EDA help (safe; no model fitting)
uv run python scripts/test_network_model.py --help
uv run python scripts/test_network_model.py evaluate --help
uv run python scripts/inspect_datasets.py --help
```

The Phase 7A full suite passed **511 tests** (22 research cases); see [attack-family feasibility](reports/model_evaluation/nf_cse_attack_family/feasibility_report.md). The Phase 6C full suite passed **489 tests** (45 Simulation Lab tests), with no warnings; see [dashboard verification](reports/simulation/phase6c_dashboard.md). The Phase 6B full suite passed **444 tests** (46 new engine/API tests; one SQLite resource warning); see [backend verification](reports/simulation/phase6b_engine.md). The Phase 6A full suite passed **398 tests** (54 generator tests); see [the generator verification report](reports/simulation/phase6a_generator.md). Tests use temporary small fixtures; they do not evaluate the real official test dataset. Training tests fit only synthetic software fixtures and do not alter the saved baseline. The CLI test fixtures exercise model loading, input handling, chunking/order, probability alignment, metrics, exclusions, overwrite protection and no-refit/protected-path behavior. API tests use FastAPI TestClient (`httpx2` is a locked dev dependency for the installed Starlette version), synthetic serialized predictors and temporary files; they verify partial model availability, model reuse, strict schemas, bounds, error responses and model integrity. If a restricted execution sandbox blocks local sockets or cross-thread event-loop wakeups, run API integration tests in a normal local environment; do not disable the tests or protections.

Before completing development work, update this root README for every introduced/changed script, CLI interface, entry point, configuration requirement or workflow; verify commands and paths, correct stale examples and distinguish implemented features from plans. This maintenance requirement also lives in [AGENTS.md](AGENTS.md).

## Attack-family feasibility study (Phase 7A)

This research CLI compares direct 15-class classification against the frozen binary detector plus an attack-only family classifier. It uses the existing seven completed-flow inputs and all original family names; no categories are merged. It does not change/register models, thresholds, API routes, Streamlit or Simulation Lab. Generator source labels are not evaluation ground truth.

Prerequisites: the existing sealed NF-CSE root at `data/processed/nf_cse_cic_ids2018`, its common manifest/contract, and the trusted frozen binary model plus adjacent metadata in `models/network`. Use Python 3.13 and the existing `uv` environment; no new dependencies, environment variables or GPU are required. Do not regenerate partitions to run the study.

```bash
uv run python scripts/study_attack_families.py --help
OMP_NUM_THREADS=4 OPENBLAS_NUM_THREADS=4 uv run python scripts/study_attack_families.py --threads 4
uv run pytest tests/unit/test_attack_family_study.py -q
```

There are no required CLI arguments. `--data-dir PATH` selects a compatible sealed root (default above); only `train/` and `validation/` are loaded. `--output-dir PATH` selects a **new** research report directory (default `reports/model_evaluation/nf_cse_attack_family`); existing output is refused, and dataset/model destinations are prohibited. `--threads N` bounds native CPU threads to 1..8 (default 4). To reproduce after a published run, choose a new output directory, for example `--output-dir reports/model_evaluation/nf_cse_attack_family_repeat`. A failed run leaves its predeclared plan and partial artifacts for diagnosis; retry in a new directory. There is no overwrite flag.

The CLI verifies hashes, original multiplicities, labels, canonical group lineage and train/validation disjointness; an access guard prohibits reserved-test shards and processed-data writes. It never reads raw records or the reserved test partition. Four predetermined CPU fits use full compact training records with multiplicity weights: direct and attack-only linear SGD log-loss baselines, plus histogram boosting. Five linear epochs and 60 boosting iterations are fixed in advance; no hyperparameter search, internal random-row validation, class balancing or binary retraining occurs. Both existing binary operating thresholds are read from verified registry configuration/metadata. All candidate metrics use full original validation multiplicities.

Outputs include the predeclared experiment plan/criteria, class mapping/inventory, collision/overlap statistics, full weighted protocol/port/counter/conditional distributions, direct/conditional/hierarchical metrics and confusion matrices, per-family error decomposition, exploratory abstention coverage/rejection/error statistics, measured time/peak RSS, SVG figures, integrity/access ledger and artifact checksums. Experimental estimators are not serialized. The [feasibility report](reports/model_evaluation/nf_cse_attack_family/feasibility_report.md) records the final decision, per-family reliability and observed costs; machine-readable evidence is adjacent.

Observed Phase 7A result: **CONDITIONAL GO for further research on a supported subset; NO-GO for a reliable full-taxonomy deployment now**. Direct histogram macro-F1 was **0.6882** (benign FPR **0.0510%**, attack detection recall **94.4804%**). Hierarchical histogram macro-F1 was **0.6626 standard / 0.6919 high sensitivity** (FPR **0.0320% / 0.9987%**, attack detection recall **94.4352% / 95.1072%**). Eight of fourteen attack families meet predeclared support/recall gates; SlowHTTPTest and FTP share all vectors, SQL is exceptionally rare/ambiguous, and Infilteration remains a binary-detection bottleneck. A 0.9 raw-score abstention cutoff rejects all SlowHTTPTest/FTP validation records despite high accepted accuracy. Four fixed fits plus analysis took **162.12 s**, peak process RSS **2,370.09 MiB** at four threads. These are exploratory validation estimates, not production approval. See the linked report for every family and all linear/boosting results.

Do not interpret collision lookup ceilings as universal bounds, raw class scores as calibrated confidence, conditional family performance as end-to-end detection, or duplicate multiplicities as independent episodes. Validation has already informed the existing binary model, and this study reuses it exploratorily. The reserved test remains untouched by this phase; its existing binary evaluation history is not reset. Independent capture/host/time/exporter evidence is still needed before deployment claims. Extremely rare SQL Injection and low-group Web/XSS categories require explicit support/uncertainty disclosure.

## Simulation Lab: feature-record generator (Phase 6A)

This offline component produces **seven-field completed-flow feature records**, without sending packets, loading classifiers, making predictions, or starting FastAPI/Streamlit. The generator remains service-independent; Phase 6B below adds the background simulation backend. The Phase 6C Simulation Lab page now controls the backend through HTTP. Profiles are derived exclusively from the existing sealed **training** partition. Do not rebuild data partitions to run it. No environment variables or new dependencies are required.

Build profiles once (requires processed training shards and their common sealed manifest/contract):

```bash
uv run python scripts/build_traffic_profiles.py --help
uv run python scripts/build_traffic_profiles.py
uv run python scripts/generate_traffic.py --help
```

The builder verifies source checksums, preprocessing identity, feature order, training population and unique-vector count. It opens only `train/*.npz` and three common metadata files. Shared manifest bytes are hashed/scanned for structure, but validation/test objects are skipped before decoding; their records are never opened. Unsupported canonical statuses fail the build rather than silently dropping rows. Profiles go to `models/simulation/nf_cse/`: read-only-loadable `vectors.npy`, `weights.npy`, `labels.npy`, an exact all-training-vector `membership.sqlite` index, and versioned `metadata.json` with artifact hashes. These are simulation artifacts, separate from classifier models. The builder also writes `reports/simulation/statistical_validation.json` (5,000 deterministic samples per mode/profile by default). Existing profile/output/report paths are not overwritten; select new paths for another run.

Builder options: `--processed-dir PATH`, `--output-dir PATH`, `--audit-count N` (1..100000), `--audit-seed N` (default 20261115), `--audit-report PATH`. Defaults target the locations above. The audit compares full weighted protocol/port histograms, counter means/correlations, a separate deterministic weighted training sample for counter quantiles and sampling variability, and paired anchors to isolate perturbation effects; novelty checks exact canonical membership against **all training vectors**, ignoring labels. The report includes duplicate/invalid rates and source composition. See [methodology, measured fidelity and performance](reports/simulation/phase6a_generator.md).

Generate records (profile artifacts are the only data dependency):

```bash
# Exact 90% benign / 10% attack-profile composition; empirical training replay.
uv run python scripts/generate_traffic.py --count 10000 --benign-ratio 0.9 --mode empirical --seed 42
# Benign-only JSONL with separate simulation metadata.
uv run python scripts/generate_traffic.py --count 1000 --benign-ratio 1 --mode empirical --seed 42 --metadata --output runtime/simulation/benign.jsonl
# Attack-profile-only bounded synthesis, exported as CSV.
uv run python scripts/generate_traffic.py --count 1000 --attack-ratio 1 --mode synthetic --seed 42 --format csv --output runtime/simulation/attack.csv
# Mixed synthetic records conditioned on TCP destination port 443.
uv run python scripts/generate_traffic.py --count 1000 --benign-ratio 0.9 --mode synthetic --protocol 6 --destination-port 443 --output runtime/simulation/tcp443.jsonl
# Identical configuration/artifacts/seed -> identical record bytes in another file.
uv run python scripts/generate_traffic.py --count 10000 --benign-ratio 0.9 --mode empirical --seed 42 --output runtime/simulation/reproduced.jsonl
cmp runtime/simulation/traffic.jsonl runtime/simulation/reproduced.jsonl
```

Generator options:

| Option | Meaning / default |
| --- | --- |
| `--profiles PATH` | Profile directory; `models/simulation/nf_cse/` |
| `--count N`, `--seed N` | Positive output count (up to 2^63−1), nonnegative private NumPy seed; 10000 / 42 |
| `--benign-ratio R` / `--attack-ratio R` | Mutually exclusive fractions in [0,1]; default benign 0.9. Attack ratio is converted to its benign complement. Benign count is decimal `count * benign_ratio` rounded half up; attack count is the remainder. |
| `--mode empirical\|synthetic` | Complete-vector weighted replay / conditional anchor with joint bounded counter perturbation; empirical default |
| `--protocol BYTE` | Optional repeatable byte restriction, e.g. `--protocol 6 --protocol 17`; restricted original weights are renormalized |
| `--destination-port PORT` | Optional repeatable 0..65535 TCP/UDP service restriction; nontransport placeholders cannot satisfy it |
| `--perturbation R` | Synthetic common counter scale ±R, default 0.1, range (0,0.25]; integer rounding, positive/zero preservation and upper bound apply |
| `--format jsonl\|csv` | JSONL default; extension is not auto-detected |
| `--output PATH` | New file; default `runtime/simulation/traffic.<format>` |
| `--metadata` | JSONL `{record,simulation}` envelope or `simulation_*` CSV columns; metadata never belongs in a model input |

Unsupported restrictions fail if any requested source profile has no support; there is no distribution fallback. Output without `--metadata` has exactly `PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS` in that order. Every output gets an adjacent `.simulation.json` provenance sidecar with configuration, profile/output hashes and evidence warning. JSONL metadata envelopes must be unwrapped and CSV `simulation_*` columns removed before a strict seven-field API request. Neither timestamps nor wall-clock performance measurements are inserted into record sequences. CLI stdout reports load/filter time, streaming export throughput and process peak RSS (Linux MiB).

`Profiles(path)` can be reused across generators. `TrafficGenerator(profiles, GeneratorConfig(...))` is an iterator; `next(generator)` returns one `{record, simulation}` item. Profile arrays are memory-mapped; filtering/cumulative weights use memory proportional to compact profile size, never output count. Serialization streams records and audits cap diagnostic sample size. Generation never rescans source training shards; default output grows on disk with count. Run `uv run pytest tests/unit/test_simulation.py -q` for fixture-only generator tests.

Reproducibility requires identical profile files, complete configuration, software versions and seed. Empirical replay preserves the complete **normalized model information**, not discarded raw tokens: nontransport ports use raw 0 (normalizes back to not-applicable), and a transport sentinel uses raw -1. Coalesced/missing protocols and missing/invalid counters cannot be reconstructed and fail closed. No training records in the built profiles were excluded.

Synthetic mode samples a complete weighted anchor conditional on source profile and restrictions, retains protocol/ports, and applies one shared uniform bounded scale to its four counters. This preserves directional coupling approximately, including structural zeros, but integer rounding changes ratios and large-counter boundary handling can make the scale asymmetric. Packet-size/MTU/timeout/exporter rules have not been established and are not invented. Statistical fidelity and novelty are measured, not guaranteed. Repeated training vectors may carry conflicting source labels. **Neither mode is an independent evaluation dataset**: source profiles are not verified attack behavior, prediction agreement would not be test accuracy, and simulated results must never be combined with final-test metrics or used to update frozen classifiers without a separate approved experiment.

## Simulation Lab backend (Phase 6B)

The API owns `SimulationController → TrafficGenerator → bounded FIFO → inference worker → bounded aggregator`. Each active run has one producer and one inference thread, independent of HTTP request lifetimes. Profiles load lazily in a worker and are reused; the existing registry owns the **same NF model instance** used by prediction endpoints. Registry input validation, preprocessing and verified operating-mode thresholds are reused. This backend generates feature records only; the Phase 6C Streamlit Simulation Lab controls it through HTTP. No packets are sent.

Use a **single Uvicorn process**, without reload: state/limits are in memory per process and disappear on restart. The existing launcher does this. Prerequisites are the ready frozen NF artifact/metadata and published registry verification reports, plus the Phase 6A simulation profiles. No dataset partitions are opened by the engine. Optional server settings (export before launch; no automatic `.env` loading):

| Environment variable | Default / limit |
| --- | --- |
| `CYBERGUARD_SIMULATION_PROFILES_PATH` | `models/simulation/nf_cse/`; trusted server-side profile directory; clients cannot choose paths |
| `CYBERGUARD_SIMULATION_MAX_ACTIVE` | 1; 1..4. Paused, starting and draining runs count toward the limit. |
| `CYBERGUARD_SIMULATION_MAX_SESSIONS` | 20 retained runs; active limit..100. Stop then delete finished runs to free slots. |

No new executable script is needed: `scripts/start_api.sh` also serves simulations. Existing `CYBERGUARD_MAX_MODEL_REQUEST_BYTES` applies to simulation POST bodies, and simulation batches cannot exceed `CYBERGUARD_MAX_BATCH_SIZE`. Native CPU thread limits can be set before process startup, as in the verified example below.

### Simulation API and configuration

| Method | Path | Purpose |
| --- | --- | --- |
| POST / GET | `/api/v1/simulations` | Create without work (201) / list retained runs |
| GET | `/api/v1/simulations/{id}` | State, configuration, termination reason, safe error, `finished` |
| POST | `/api/v1/simulations/{id}/start` | Start a created run asynchronously |
| POST | `/api/v1/simulations/{id}/pause` | Pause generation and new batch work; an already gathering/processing batch may finish |
| POST | `/api/v1/simulations/{id}/resume` | Resume paused work |
| POST | `/api/v1/simulations/{id}/stop` | End generation and drain accepted records; poll `finished` |
| GET | `/api/v1/simulations/{id}/metrics` | Lifetime counters/rates/means, rolling latency p95, bounded history |
| GET | `/api/v1/simulations/{id}/events?after=-1&limit=100` | Sequence cursor, ascending events, `next_cursor`, `oldest_available`, `cursor_gap` |
| DELETE | `/api/v1/simulations/{id}` | Delete a finished run; active/created runs must first be stopped |

Unknown IDs return structured 404; invalid transitions 409; resource exhaustion 429; unsupported models/schema 422; unavailable models/shutdown/startup resources 503. Worker failures become inspectable `failed` runs with sanitized stage/code and server-side logs. POST body limits return 413. No raw tracebacks or artifact paths are returned.

Creation fields (all optional, unexpected fields forbidden):

| Field | Default | Allowed |
| --- | ---: | --- |
| `model_id` | `nf_cse_binary_completed_flow` | This model only |
| `mode` | `empirical` | `empirical`, `synthetic` |
| `benign_ratio`, `attack_ratio` | 0.9 / 0.1 | [0,1]; either infers the complement, both must sum to 1 within 1e−12 |
| `seed` | 42 | Integral 0..2^63−1 |
| `generation_rate` | 100 | 1..500 feature records/s |
| `max_duration` | 60 | >0..3600 seconds from start; includes profile initialization and pauses |
| `max_records` | 6000 | Integral 1..1000000 |
| `batch_size` | 32 | Integral 1..128 and ≤ server batch limit |
| `queue_capacity` | 256 | Integral 1..4096 |
| `event_capacity` | 500 | Integral 1..2000 recent classified events |
| `history_capacity` | 120 | Integral 1..600 recent history samples |
| `operating_mode` | `standard` | `standard`, `high_sensitivity`; thresholds come from verified registry configuration |

Lifecycle: `created → running ↔ paused`; exhaustion/duration ends as `completed`; explicit stop ends as `stopped` after drain; worker errors end as `failed`. Stopping a created run is immediate. Terminal runs cannot restart. During draining, state may still be `running`/`paused` with `stop_requested=true`; control operations are rejected. `finished=true` means both worker finalizers completed (shutdown/delete also join their threads). Stop is not an immediate thread kill.

Pacing uses monotonic target slots, skips missed slots rather than emitting catch-up bursts, and uses condition waits. Queue-full backpressure blocks the producer without dropping accepted records. Capacity excludes the bounded in-flight batch and at most one pending generated candidate. A stop/duration can admit that one pending candidate before drain. `generated` counts FIFO admissions; `generation_attempts` includes generated candidates and `cancelled_before_enqueue` counts abandoned pending candidates on failure. At successful completion/stop, `generated == classified`, queue/in-flight/discarded counts are zero. On failure, accepted unclassified records are counted as `discarded`; final `generated == classified + discarded`.

Rates are lifetime admissions/classifications divided by monotonic elapsed seconds, including pauses/setup/draining; the requested rate is a target, not a scheduling guarantee. Duration ends **generation**, then queued records drain, so final elapsed time can exceed the duration cap. The exact source composition rounding from Phase 6A applies when all `max_records` are generated; duration/stop produces only a deterministic prefix and need not have the full planned ratio. Different wall-clock scheduling can change prefix length, not the seeded feature sequence.

Latency definitions: queue wait = admission → batch processing start (includes batch gathering); batch processing = registry call plus prediction count/score verification, assigned to each participating record, not divided by batch size; end-to-end = admission → that verification completing (excludes event aggregation/HTTP serialization). Means are lifetime record-weighted values. `p95_recent` is the exact percentile of the latest **2,000 classified-record latency samples**, not a lifetime percentile or confidence interval. Bounded history records cumulative counters at most once/second plus the final sample; ring buffers overwrite oldest entries. Event polling uses exclusive sequence cursors (`after`), default limit 100, maximum 1000; `cursor_gap=true` reports overwritten events, not pipeline drops. Resume polling with `next_cursor`.

### Verified curl lifecycle

From the repository root, start the backend in one terminal (the verification used port 18006):

```bash
OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 CYBERGUARD_API_PORT=18006 bash scripts/start_api.sh
```

In another terminal, use `curl` and Python 3.13 from the uv environment to capture the opaque ID:

```bash
SIM_BASE=http://127.0.0.1:18006/api/v1/simulations
SIM_ID=$(curl --fail-with-body -sS -X POST "$SIM_BASE" \
  -H 'Content-Type: application/json' \
  --data '{"model_id":"nf_cse_binary_completed_flow","mode":"synthetic","benign_ratio":0.9,"attack_ratio":0.1,"seed":42,"generation_rate":100,"max_duration":60,"max_records":6000,"batch_size":32,"queue_capacity":256,"event_capacity":1000,"history_capacity":120,"operating_mode":"standard"}' \
  | uv run python -c 'import json,sys; print(json.load(sys.stdin)["id"])')
curl --fail-with-body -sS -X POST "$SIM_BASE/$SIM_ID/start"
curl --fail-with-body -sS "$SIM_BASE/$SIM_ID/metrics"
curl --fail-with-body -sS "$SIM_BASE/$SIM_ID/events?after=-1&limit=100"
curl --fail-with-body -sS -X POST "$SIM_BASE/$SIM_ID/pause"
curl --fail-with-body -sS -X POST "$SIM_BASE/$SIM_ID/resume"
curl --fail-with-body -sS -X POST "$SIM_BASE/$SIM_ID/stop"
# Repeat these GETs until finished=true; verify generated == classified and queue_depth=0.
curl --fail-with-body -sS "$SIM_BASE/$SIM_ID"
curl --fail-with-body -sS "$SIM_BASE/$SIM_ID/metrics"
curl --fail-with-body -sS -X DELETE "$SIM_BASE/$SIM_ID"
```

Pause/resume before the run reaches its duration/record limit. Stop returns promptly; wait for `finished=true` before deleting. For a naturally completed exact 90/10 example, create with `max_records:1000`, keep `max_duration:60` and rate 100, start, then poll to completion. The measured run classified all 1,000 records at about **99.47/s**; mean/p95 end-to-end latency was **60.55/92.96 ms**, with about **395.29 MiB** peak process RSS. Timing is machine/load dependent. See [Phase 6B evidence and measurements](reports/simulation/phase6b_engine.md).

Shutdown requests stop for all runs and joins producer/inference threads **before** closing the shared model registry; HTTP disconnects do not cancel simulations. Native inference/profile I/O cannot be forcibly interrupted safely by Python threads, so shutdown waits for in-flight calls before draining. There is no hard wall-clock kill, durable storage, distributed scheduling, SSE/WebSocket stream or packet-traffic integration. Source-label agreement is a descriptive training-derived statistic, **not test accuracy**. Model scores remain uncalibrated; no simulation establishes live deployment performance.

## Simulation Lab dashboard (Phase 6C)

Choose **Simulation Lab** in the dashboard navigation. It uses only FastAPI simulation/model/OpenAPI endpoints; it does not import workers, read profiles, load a classifier or run inference locally. Its target is always NF-CSE, independently of the sidebar model workspace. Existing pages keep their selected model and inputs.

Start the existing launchers in separate terminals from the repository root:

```bash
OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 bash scripts/start_api.sh
bash scripts/start_dashboard.sh
```

Open `http://127.0.0.1:8501`, then select Simulation Lab. The API defaults to localhost:8000; set exported `CYBERGUARD_API_URL` before starting Streamlit to use another backend. For an occupied dashboard port, use the equivalent `uv run streamlit run src/cyberguard/dashboard/app.py --server.address 127.0.0.1 --server.port 8503`. Backend models/verification metadata and the existing Phase 6A profiles are prerequisites; the dashboard needs only HTTP access. Keep the API to one process as documented above.

1. **Configure:** expand Configure a simulation. Choose empirical training replay or bounded synthetic perturbation, attack-profile percentage (benign is its complement), a rate preset (10/50/100/250/500 flows/s), duration cap, maximum records, optional seed and operating mode. Limits come from the current API OpenAPI schema, while mode IDs/thresholds come from NF model metadata. Blank seed uses the backend default; record/prediction reproducibility does not guarantee reproducible timing. The UI offers whole-second durations (1..3600 today); backend accepts >0..3600 seconds. Advanced settings expose batch size, queue capacity and backend event retention, respecting advertised bounds and the server model batch limit.
2. **Create, then Start:** creation performs no generation. Create is locked after submission; use Prepare new simulation to explicitly prepare another run. An uncertain POST outcome is never automatically retried: Refresh Lab and inspect history before trying again.
3. **Monitor:** Auto-refresh uses supported Streamlit fragments at 500/750/1000 ms, default 1000. It refreshes state, metrics and incremental event cursors without a polling thread or blocking loop. Turn it off for manual Refresh Lab. A terminal run stops polling after available events are fetched; any API error stops polling until explicit refresh. Created runs do not poll continuously.
4. **Pause/Resume/Stop:** only currently valid controls appear. Pause allows an already gathering/processing batch to finish and does not suspend the wall-duration cap. Stop ends generation and drains accepted records; it preserves results. Wait for finished status and reconciled counters. Completed/stopped/failed runs cannot silently restart.
5. **Inspect or delete:** select a retained simulation in history, inspect its state/configuration/metrics/events, or prepare another run. The history table is explicitly a snapshot from its last refresh. Only finished runs can be deleted; deleting retained results requires a confirmation checkbox. Deletion differs from stopping and cannot be undone. In-memory backend history is transient; a restart removes IDs. Missing IDs are marked unavailable and cached results stay visible/exportable until selecting another run.

KPI cards show generated/classified/predicted counts, rates, queue depth and end-to-end mean/recent p95. Generated means accepted into the queue; classified can lag while work is queued/in flight. Chart A derives interval rates from adjacent **observed backend cumulative counters divided by the actual interval**—it does not interpolate missing history. Predictions, queue depth, lifetime inference throughput and latency charts use bounded poll snapshots. Latency means are lifetime record-weighted values; recent p95 covers up to 2,000 backend records. They are not interval-specific latency measurements. Mean/p95 display milliseconds; queue gathering, model-lock contention and exclusions retain the backend definitions above.

The event table shows the latest 100 frontend events, with sequence/time/profile, all seven inputs and prediction/score/mode. Its inspector and CSV cover up to **1,000 frontend-retained events**. Rows remain sorted/deduplicated, and evicted selections recover safely. Cursor gaps are disclosed when backend retention overwrites unseen events. At most two 500-event pages are fetched per poll; no full-history refetch occurs. Chart snapshots are capped at 120; backend history also remains bounded. Navigation preserves the selected run, committed form settings, preferences, cursor, events and charts without creating another simulation. Unsaved form edits follow Streamlit form submission behavior.

**Prediction Agreement with Generator Profiles** displays the backend lifetime agreement and separate profile/prediction marginals. Source-profile counts refer to generated inputs and prediction counts to classifications, so denominators can differ during execution. The API does not expose joint cross-counts; no confusion matrix is inferred from a truncated event buffer. Training-derived source labels are not verified ground truth, and agreement is **not independent test accuracy**.

Downloads provide retained-event CSV, configuration JSON and backend aggregate-metrics JSON. CSV is labeled partial unless the frontend holds every classified sequence for a finished run with no known gaps. It never claims all generated records were exported. Charts/prediction history only cover observed polls; exports cannot restore overwritten events. Connection errors preserve the last verified snapshot; Refresh Lab rechecks metadata/history and reports restarts. A missing/unavailable model, missing profiles, configuration rejection, worker failure or transition race produces a readable message, without exposing tracebacks or retrying mutations.

See [Phase 6C implementation, screenshots and verification](reports/simulation/phase6c_dashboard.md). Tests: `uv run pytest tests/unit/test_simulation_dashboard.py -q`; the complete suite remains `uv run pytest -q`.

## Running the application

See the [Phase 4A completion record](reports/phase4a_backend.md) for the original backend and [Phase 5E verification](reports/phase5e_backend.md) for the additive multi-model backend (309 passing tests and verified curl examples).

### Start, configure and stop the backend

```bash
uv sync --frozen --group dev
bash scripts/start_api.sh
```

Open [Swagger UI](http://127.0.0.1:8000/docs) in a browser. Expand **POST /api/v1/predict** or **POST /api/v1/predict/batch**, choose **Try it out**, enter JSON and **Execute**. Swagger validates the same request schemas and configured batch limit. `/openapi.json` exposes that schema; `/redoc` is also available. Stop the server with **Ctrl-C**; shutdown clears its detector state.

Direct uvicorn launch is also supported from the repository root:

```bash
uv run uvicorn cyberguard.api.main:app \
  --app-dir src --host 127.0.0.1 --port 8000
```

`--host`, `--port` and uvicorn's logging flags govern the direct command; `CYBERGUARD_API_HOST`, `CYBERGUARD_API_PORT` and `CYBERGUARD_LOG_LEVEL` govern the launcher. `CYBERGUARD_LOG_LEVEL` also governs CyberGuard application logs in either mode. Model path and batch size settings apply to both launches. Each available model is loaded once per application lifespan/process, with no reload flag by default. Multiple explicitly configured uvicorn workers would each have their own model copy; no workers are started by this launcher.

| Environment variable | Default | Validation / meaning |
| --- | --- | --- |
| `CYBERGUARD_NETWORK_MODEL_PATH` | `models/network/bot_iot_restricted_baseline.joblib` under the repository/package root | Trusted local fitted artifact. Relative paths resolve from that root, independent of cwd. No HTTP request can select a model file. |
| `CYBERGUARD_NF_CSE_MODEL_PATH` | `models/network/nf_cse_binary_completed_flow.joblib` | Trusted NF artifact; adjacent `.metadata.json` required; relative paths resolve from project root |
| `CYBERGUARD_NF_CSE_EVALUATION_DIR` | `reports/model_evaluation/nf_cse_binary/final_test` | Frozen `evaluation_manifest.json` + `test_metrics.json`, needed to verify provenance, preprocessing and both thresholds; no datasets are loaded |
| `CYBERGUARD_MAX_MODEL_REQUEST_BYTES` | `1048576` | Positive integer; additive model POST request-body byte cap, including chunked transfers, before JSON parsing. Legacy request behavior stays unchanged |
| `CYBERGUARD_API_HOST` | `127.0.0.1` | Nonblank launcher bind host; localhost by default |
| `CYBERGUARD_API_PORT` | `8000` | Integer 1–65535, used by launcher |
| `CYBERGUARD_MAX_BATCH_SIZE` | `1000` | Positive integer; enforced and reflected in OpenAPI |
| `CYBERGUARD_LOG_LEVEL` | `INFO` | DEBUG, INFO, WARNING, ERROR or CRITICAL |
| `CYBERGUARD_API_URL` | `http://127.0.0.1:8000` | Dashboard HTTP destination; HTTP(S) URL without credentials, query or fragment. Changing the backend port requires updating this URL separately. |

[.env.example](.env.example) lists supported settings. To use a trusted local copy on POSIX:

```bash
cp .env.example .env
# Edit .env, then explicitly export it; no automatic dotenv loading occurs.
set -a
. ./.env
set +a
bash scripts/start_api.sh
```

`.env` is Git-ignored. No credentials are required for this local backend. Invalid configuration fails startup. Missing/incompatible/unfitted artifacts or failed compatibility probes mark only the affected model unavailable; the process and other model can remain healthy. It never falls back to a dummy model. Existing preprocessing is used directly without refitting; startup performs small synthetic compatibility probes, not training or model evaluation.

### Endpoints

| Method / path | Purpose | Result |
| --- | --- | --- |
| `GET /health` | Basic service liveness, without inference | `{"status":"ok","service":"cyberguard-api"}` |
| `GET /health/ready` | Legacy BoT availability, without inference | `{"status":"ready","model_loaded":true}` or 503 |
| `GET /api/v1/model/info` | Model identifier/type, features, classes, probability availability, SHA-256 and contract version when verified | No local filesystem paths; unavailable metadata is null |
| `POST /api/v1/predict` | One supplied header record | Class, optional probabilities, model identifier and limitations warning |
| `POST /api/v1/predict/batch` | Vectorized ordered batch | `{"predictions":[...],"count":N}` |

All three fields (`proto`, `sport`, `dport`) are required, even when explicitly null. Each accepts a strict JSON string, integer or null. Null represents missingness; pipeline-supported empty/NA/malformed/sentinel/out-of-range string values remain model inputs under its existing statuses. Protocol aliases and decimal/hex string ports follow the CLI contract above. Booleans, floating JSON numbers, arrays, objects, missing fields and unexpected fields are schema errors. Use a string for textual values such as `"80.0"` if intentionally testing the pipeline's invalid-port representation. No client-supplied addresses, labels or model paths are accepted.

A batch requires `records`, rejects empty lists, and defaults to a maximum of 1,000 records. An oversized batch is rejected as a whole before inference. Results preserve record order; the model is reused across requests. The framework-independent `NetworkDetector` shares the CLI's prediction/probability helper and serializes access to its loaded estimator; each batch makes vectorized pipeline calls, not one call per row.

### Multi-model API (Phase 5E)

The allowlisted registry in `inference/model_registry.py` owns model metadata, private trusted artifact paths, readiness and inference adapters. `core/model_schemas.py` provides separate request schemas; the additive router validates a schema union, then requires it to match the selected registry entry. Both single and batch requests share the same adapter. Loaded estimators are reused and protected by per-model locks; failed loading is isolated. Metadata exposes artifact-hash model versions, schema/contract, required features, classes, frozen modes, limitations and matched historical validation/final-test metrics. No local filesystem paths or arbitrary artifact metadata are returned. No fitting, calibration, test reevaluation or dataset access happens in the server.

| Stable model ID | Task / classes | Input record | Default / alternatives |
|---|---|---|---|
| `bot_iot_restricted_baseline` | Multiclass: Normal, DoS, DDoS, Reconnaissance | `proto,sport,dport`, unchanged legacy semantics | `default`, no threshold |
| `nf_cse_binary_completed_flow` | Binary: Benign (0), Attack (1) | Exact seven completed-flow fields below | `standard` = 0.5; `high_sensitivity` = 0.03090052128234102 |

The NF serving mode defaults to 0.5 without modifying the saved artifact's validation-selected threshold. The versioned presentation-mode configuration is verified against the saved metadata and frozen final evaluation. Missing/inconsistent checksums, contract, source-code compatibility, class mapping or thresholds leave NF unavailable; thresholds are never substituted or recalculated. Only trusted local joblib artifacts are supported; never load an untrusted uploaded model.

| Method / path | Purpose |
|---|---|
| `GET /api/v1/models` | List all registered models, including unavailable ones |
| `GET /api/v1/models/{model_id}` | Detailed public model metadata and input schema |
| `GET /api/v1/models/{model_id}/ready` | Per-model readiness: 200 or structured 503 |
| `POST /api/v1/models/{model_id}/predict` | `{"record": {...}, "operating_mode": "..."}` |
| `POST /api/v1/models/{model_id}/predict/batch` | `{"records": [{...}, ...], "operating_mode": "..."}` |

`operating_mode` is optional and defaults per model. NF requires `PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS`. JSON integers, integral finite numeric scalars and exact integral decimal/exponent strings are accepted; protocol aliases and hexadecimal port strings use the frozen normalizer. Protocols must be valid aliases or bytes 0..255; ports must be 0..65535 or explicit `-`/`-1` sentinels. Counts must be 0..9007199254740991. Valid zero is preserved; explicit sentinels/nontransport ports retain the pipeline's status semantics. Unlike its broader offline missing-status contract, the **NF API rejects nulls, missing columns, malformed/nonfinite/fractional/out-of-range values and booleans**, then passes valid original scalars to the saved pipeline. It never supplies missing counters or infers a completed flow from headers. Supplying seven fields cannot verify that their observations were actually finalized; the caller must provide exporter-compatible completed bidirectional statistics.

Extra record/envelope keys and arbitrary thresholds are rejected. A batch validates all records before inference, preserves input order, accepts 1..`CYBERGUARD_MAX_BATCH_SIZE` records and uses one vectorized adapter call. The additive POST routes also enforce `CYBERGUARD_MAX_MODEL_REQUEST_BYTES` before parsing JSON. Mixed schemas or invalid members fail the whole batch; there are no partial silent results. Swagger/OpenAPI exposes both typed alternatives and record-count bounds; choose the alternative matching the path ID.

Errors use `{"error":{"code":"...","message":"..."}}` (422 errors can include sanitized field details): unknown ID 404, unavailable model 503, invalid schema/mode/batch 422, body limit 413, inference failure 500. Failed predictions never return 200. `/health` stays process liveness, `/health/ready` stays **legacy BoT readiness**, and `/api/v1/model/info`, `/api/v1/predict`, `/api/v1/predict/batch` retain their exact BoT request/response contracts. Legacy clients can continue using those routes. The Phase 5F dashboard discovers the registry and uses model-specific routes; its BoT input behavior remains compatible.

With `bash scripts/start_api.sh` running, these verified examples use synthetic software inputs only (no detection-quality evidence). If port 8000 is occupied, launch with `CYBERGUARD_API_PORT=18005 bash scripts/start_api.sh` and set `API=http://127.0.0.1:18005` below.

```bash
API=http://127.0.0.1:8000
curl --fail "$API/api/v1/models"
curl --fail "$API/api/v1/models/nf_cse_binary_completed_flow"
curl --fail "$API/api/v1/models/nf_cse_binary_completed_flow/ready"
curl --fail "$API/health/ready"
curl --fail "$API/api/v1/models/bot_iot_restricted_baseline/predict" \
  -H 'Content-Type: application/json' \
  -d '{"record":{"proto":"tcp","sport":"49152","dport":"80"}}'
curl --fail "$API/api/v1/models/nf_cse_binary_completed_flow/predict" \
  -H 'Content-Type: application/json' \
  -d '{"record":{"PROTOCOL":6,"L4_SRC_PORT":49152,"L4_DST_PORT":443,"IN_BYTES":1200,"OUT_BYTES":2400,"IN_PKTS":8,"OUT_PKTS":12}}'
curl --fail "$API/api/v1/models/nf_cse_binary_completed_flow/predict" \
  -H 'Content-Type: application/json' \
  -d '{"operating_mode":"high_sensitivity","record":{"PROTOCOL":6,"L4_SRC_PORT":49152,"L4_DST_PORT":443,"IN_BYTES":1200,"OUT_BYTES":2400,"IN_PKTS":8,"OUT_PKTS":12}}'
curl --fail "$API/api/v1/models/nf_cse_binary_completed_flow/predict/batch" \
  -H 'Content-Type: application/json' \
  -d '{"records":[{"PROTOCOL":6,"L4_SRC_PORT":49152,"L4_DST_PORT":443,"IN_BYTES":1200,"OUT_BYTES":2400,"IN_PKTS":8,"OUT_PKTS":12},{"PROTOCOL":1,"L4_SRC_PORT":0,"L4_DST_PORT":0,"IN_BYTES":0,"OUT_BYTES":0,"IN_PKTS":0,"OUT_PKTS":0}]}'
curl --fail "$API/api/v1/models/bot_iot_restricted_baseline/predict/batch" \
  -H 'Content-Type: application/json' \
  -d '{"records":[{"proto":"tcp","sport":"49152","dport":"80"},{"proto":"udp","sport":"53","dport":"53"}]}'
```

The response envelope includes `model_id`, SHA-256 `model_version`, `task`, `predicted_class`, ordered `class_scores`, `positive_class_score` (NF only), `operating_mode`, `applied_threshold` (null for BoT), `input_contract_version`, UTC `inference_timestamp`, `score_semantics` and `limitations`. Batches return `{"predictions":[...],"count":N}`. The first NF example returns `Benign`, positive-class score `0.0009946485796402205`, class scores `{"Benign":0.9990053514203597,"Attack":0.0009946485796402205}`, mode `standard` and threshold `0.5`; high sensitivity returns the same raw scores with its own threshold. The two-row NF batch returns Benign then Benign. BoT's example returns DDoS with the same four scores as the legacy example below. These are uncalibrated outputs, not calibrated risk or proof of attack occurrence.

NF final-test performance remains the frozen Phase 5D result: standard recall **94.3563%**, FPR **0.043752%**; high-sensitivity recall **94.9925%**, FPR **1.24108%** (exceeds the validation selection constraint). Infilteration recall is **8.16% / 18.17%**, and tiny SQL Injection support is **0/5 / 3/5** in standard/sensitivity order. See [final report](reports/model_evaluation/nf_cse_binary/final_test/evaluation_report.md) for full metrics. API integration does not establish deployment, packet-level or independent-session performance. No reserved dataset was reevaluated. See [Phase 5E verification](reports/phase5e_backend.md).

Run focused software tests with `uv run pytest tests/integration/test_model_api.py tests/integration/test_api.py -q`; run everything with `uv run pytest -q`. Fixtures serialize synthetic inference-only predictors, forbid fitting and block real dataset paths. No services need to be running for these tests.

### Example requests and actual saved-model output

With the API running:

```bash
curl --fail http://127.0.0.1:8000/health/ready
curl --fail http://127.0.0.1:8000/api/v1/model/info
curl --fail http://127.0.0.1:8000/api/v1/predict \
  -H 'Content-Type: application/json' \
  -d '{"proto":"tcp","sport":"49152","dport":"80"}'
curl --fail http://127.0.0.1:8000/api/v1/predict/batch \
  -H 'Content-Type: application/json' \
  -d '{"records":[{"proto":"tcp","sport":"49152","dport":"80"},{"proto":"udp","sport":"50000","dport":"53"}]}'
```

For the current saved artifact, the single example returned:

```json
{
  "prediction": "DDoS",
  "probabilities": {
    "Normal": 0.0,
    "DoS": 0.4174163758509647,
    "DDoS": 0.5732050811375292,
    "Reconnaissance": 0.009378543011762379
  },
  "model": "bot_iot_restricted_baseline",
  "warning": "Experimental header-only prediction; probabilities are uncalibrated. Normal does not establish safety. Theft and unknown attacks are unsupported. No live packet-level detection is performed."
}
```

The batch example returns DDoS followed by Normal for this artifact; its entries use the same response structure and warning. These are manual software demonstrations, not labeled validation evidence. Values are obtained from the loaded model; another compatible artifact may yield different predictions. When `predict_proba()` is unavailable, `probabilities` is null. The estimator's actual class ordering determines the probability mapping.

### Errors, logs and serving boundary

Errors share `{"error":{"code":"...","message":"..."}}`; validation errors add sanitized `details` containing location/type/message, never the submitted values or internal traceback.

| Status | Code | Meaning |
| --- | --- | --- |
| 422 | `validation_error` | Invalid JSON/schema, missing/extra fields, empty or oversized batch |
| 503 | `model_unavailable` | Selected detector is not ready; other models and process liveness can remain available |
| 500 | `inference_failed` | Loaded estimator failed; no placeholder prediction is returned |
| 500 | `internal_error` | Unexpected application failure; details stay on the server |
| 404/405 | `http_error` | Unknown route or unsupported method |

Logs include startup/shutdown, model loading status/identifier, prediction request counts and batch sizes, and error types. They do not log raw network records or request bodies. Startup diagnostics can name the configured local model path on the server; HTTP model metadata/error responses omit local paths. This is a local, unauthenticated inference-serving backend, not packet capture, live monitoring or an operational IDS. Replay, persistence, alert generation and DNS detection remain unimplemented.

### Dashboard workflow

Start the backend and dashboard in separate terminals:

```bash
# Terminal 1
bash scripts/start_api.sh
# Terminal 2
bash scripts/start_dashboard.sh
```

Open [CyberGuard dashboard](http://127.0.0.1:8501). The backend defaults to localhost:8000 and the dashboard to localhost:8501. The dashboard makes server-side HTTP requests and never loads models, trains, normalizes features, evaluates labels or reads dataset partitions. No keys or new dependencies are needed. Export `CYBERGUARD_API_URL` before starting to select another API address; `.env` is not loaded automatically. The backend needs its trusted artifacts and frozen metadata; dashboard performance details also use published local reports.

If ports are already occupied, leave those processes alone and use the supported direct launch with different ports:

```bash
# Terminal 1
CYBERGUARD_API_PORT=18005 bash scripts/start_api.sh
# Terminal 2
CYBERGUARD_API_URL=http://127.0.0.1:18005 uv run streamlit run \
  src/cyberguard/dashboard/app.py --server.address 127.0.0.1 --server.port 8502
```

Stop with Ctrl-C. Imports work under the existing `src/` layout. The launcher fixes localhost:8501; direct Streamlit invocation accepts `--server.port`. `.streamlit/config.toml` retains the dark theme, minimal toolbar, localhost, disabled usage statistics and 5 MiB upload limit. Local `theme.css` and `theme.py` preserve the navy glass cards, cyan/violet accents, restrained class colors, monospace metadata, reduced-motion support and responsive stacked layouts. No external font/CDN, new authentication flow or live-monitoring component is introduced.

**Model selection and connection.** The prominent sidebar selector preserves API registry order and lists models returned by `GET /api/v1/models`; no model list is hardcoded. Details and readiness come from `/api/v1/models/{id}` and `/ready`. Metadata is requested on initial connection, explicit **Refresh connection**, or selection of a different model, not every widget rerun. Selection persists across pages. A missing/unavailable selected model remains selected with predictions blocked; choose another explicitly or restore the service and refresh. There is no silent fallback. Refresh clears results and uploads, retaining model preferences. Status is a timestamped snapshot, not background monitoring.

**Operating modes.** NF-CSE exposes **Standard** (default, threshold 0.5) and **High Sensitivity** (0.03090052128234102). Mode identifiers/defaults/thresholds come entirely from API metadata. Only the identifier is submitted; the API computes the class and returns the applied threshold. The frontend never recalculates decisions. A single-mode model such as BoT hides the mode selector. Previous valid mode preferences are remembered per model. Model or mode changes clear previous predictions; model changes reset upload/validation state, while form values are remembered separately per model and survive page navigation.

- **Overview:** shows registered/ready model counts, API connectivity, selected-model task/readiness/input contract, compact model cards and evidence boundaries. The BoT snapshot remains historical validation, matched to its artifact hash. Models are not ranked against each other using different datasets/tasks.
- **Interactive Testing — BoT:** retains common/custom protocol, decimal/hex/sentinel/invalid port tokens and explicit JSON null controls. Select BoT, enter the three fields and click **Analyze traffic**. Four existing class colors and uncalibrated score bars are preserved.
- **Interactive Testing — NF-CSE:** supplies all seven fields `PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS` with human-readable labels and exact field-name help. Counters start blank, requiring explicit input; missing values are never replaced by zero. Aliases/integral numeric tokens, port ranges/sentinels and counter bounds follow the API contract. IN/OUT are exporter-relative, not verified client/server directions. Fields must come from completed bidirectional flows, not header-only/partial observations. The result shows Benign (restrained green) or Attack (warning), raw attack score, class scores, model/task/mode/threshold/input contract, submitted record and limitations. Scores are uncalibrated and no prediction is a confirmed attack.
- **Batch Testing:** choose the model and optional mode first. **Download CSV template** provides its exact required headers only, without invented traffic or labels; the schema expander shows types/ranges. Upload UTF-8 CSV with those columns, inspect up to 20 rows and click **Classify CSV**. BoT requires `proto,sport,dport`; NF requires its seven exact columns. Each record validates against the selected contract before any HTTP request. Extra columns stay local and are preserved for export. BoT's existing four-row synthetic demonstration is still available and explicitly labeled as software examples; NF templates contain no sample rows.
- Upload bounds remain **5 MiB / 20,000 records**; unique/nonempty headers, consistent row widths and valid quoting are required. Header-only templates must be filled before upload. Generated-column collisions, missing columns and invalid NF counters fail explicitly. Requests use at most `min(advertised OpenAPI limit, 250)` records, a 10-second timeout and no automatic retries. The server additionally caps request bytes; split files if it rejects a large request. Any failed chunk discards the attempted complete result rather than offering a partial export.
- Complete batch results show class counts/percentages, mode, NF raw score distributions and ordered results paginated by 100. **Download prediction CSV** preserves original columns/row order and adds prediction/model/warning, model version, mode, applied threshold, input contract, timestamp, available `score_<class>` columns and NF `positive_class_score`. Counts are assignments on the supplied sample, not verified network attack prevalence. Text cells/headers with spreadsheet formula prefixes are escaped with an apostrophe on export only, including sentinel `-1`; submitted values remain unchanged. Data stays in session memory until the user downloads it.
- **Model Performance — BoT:** retains historical validation summary, per-class precision/recall/F1, logarithmic supports, exact/row-normalized confusion matrix and metric tables. Only 79 Normal validation records exist; these are not independent-session results.
- **Model Performance — NF:** uses the existing `final_test/evaluation_manifest.json`, `test_metrics.json`, `attack_family_recall.csv` and fixed ROC/PR/family SVGs, verifying hashes and selected artifact association. Standard recall/FPR are **94.36% / 0.04375%**; sensitivity **94.99% / 1.2411%**, with ROC-AUC **0.98861** and AP **0.97154**. Values come from stored artifacts, never rounded frontend constants or new scoring. The page highlights Infilteration recall **18.17% sensitivity / 8.16% standard**, SQL Injection's five test records, uncalibrated scores, group-disjoint rather than independent-capture evidence, and the sensitivity FPR constraint failure. Missing/inconsistent artifacts show a warning; verified API summary metadata is available as a labeled fallback, without detailed local figures.
- **About CyberGuard:** explains Streamlit → FastAPI registry → separate BoT multiclass and NF binary pipelines, their different input requirements, completed-flow meaning, uncalibrated scores and evidence limits, with expandable existing reports.

The generic form machinery reads feature names/scalar types from public schemas. NF's JSON schema omits some semantic string/sentinel rules, so a narrowly scoped adapter for `nf-cse-netflow-v1-completed-flow-v1` supplies validation and human-readable roles while retaining API field ordering. NF numeric text tokens are limited to 128 ASCII characters locally before conversion (a frontend resource bound); it validates only and returns original tokens; the API pipeline owns preprocessing. Unsupported schemas require a reviewed frontend adapter rather than guessed field types. Predictions verify model/version/classes/mode/threshold metadata before display so incompatible/stale responses are rejected. Prediction errors clear results and block that selection until refresh; another model can be chosen explicitly.

Software tests use mocked HTTP, synthetic records, temporary report fixtures and Streamlit AppTest; no model or reserved dataset is loaded. Run `uv run pytest tests/unit/test_dashboard_models.py tests/unit/test_dashboard.py tests/unit/test_dashboard_design.py -q`, or `uv run pytest -q` for the complete suite. At Phase 5F completion, the full suite passed **344 tests**, including 35 new multi-model dashboard tests. See [Phase 5F frontend report](reports/phase5f_frontend.md) and its screenshots for browser verification. Historical [Phase 4B](reports/phase4b_dashboard.md), [redesign](reports/dashboard_redesign.md) and [Phase 5E](reports/phase5e_backend.md) records describe their respective earlier implementation states.

## Troubleshooting

| Problem | Action |
| --- | --- |
| Missing pandas/sklearn/joblib or pytest | Run `uv sync --frozen --group dev`; use `uv run`, not an unrelated system Python. For offline use, install/cache the locked dependencies first. |
| Python version/environment mismatch | Check `uv run python --version` is 3.13 and run from the repo root. Confirm `.python-version`, `pyproject.toml`, and `uv.lock` are present. |
| uv cache permission errors | Set `UV_CACHE_DIR` to a writable path. A direct `.venv/bin/python` invocation also works once provisioned. |
| Simulation profile missing / checksum mismatch | Build once from sealed training with `scripts/build_traffic_profiles.py`; for mismatch restore trusted profiles or build into a new dedicated directory. No classifier is needed. |
| Simulation Lab polling stopped / cached run unavailable | Refresh Lab explicitly. If the backend restarted, keep/export cached results or select a current ID; never restart a completed ID. Refresh the sidebar connection too if model batch limits are missing. |
| Simulation Lab cursor gap / partial CSV | Older events were overwritten or the frontend reached its 1,000-event bound. Metrics still cover the backend run; a bounded event export cannot recover missing history. |
| Simulation API returns 429 | Stop/drain active runs (paused runs still occupy slots), or delete finished runs. Server-side active/retained caps are separate. |
| Simulation API run is failed | Inspect its sanitized `error` stage and server logs. Restore profiles/ready NF artifact, then create a new run; terminal runs never restart. |
| Simulation filter has no support | Choose restrictions represented in each requested training source profile, or explicitly change composition. The generator never substitutes another profile. |
| Simulation output already exists | Choose a new `--output`; for profile rebuilding choose new `--output-dir` and `--audit-report`. No overwrite flag is provided. |
| Missing model artifact | Supply the existing trusted model via `--model`. Git ignores models. Recreating the baseline requires the documented training workflow and overwrites its artifacts; the testing CLI does not train automatically. |
| Invalid/incompatible model artifact | Use the trusted fitted pipeline and matching dependencies. Run `info`; a readable file without a callable `predict()` is rejected. |
| Missing raw dataset | Check the exact paths above. EDA requires all four CSVs; baseline training requires its training CSV only. Manual prediction requires neither. |
| `ModuleNotFoundError: cyberguard` when loading manually | Use the executable scripts, or set `PYTHONPATH=src` for your own Python process. |
| CSV schema/format error | Require `proto,sport,dport` and, for evaluation, `category`; use unique nonempty headers and equal field counts. Rename generated-column collisions. No records are silently skipped. |
| Unsupported category or undefined metric | Verify ground truth; use `--exclude-unsupported` only deliberately. Check class supports; do not turn undefined FPR or absent recall into zero. |
| Output already exists | Choose another output path or deliberately pass `--overwrite`. Raw inputs/model artifacts remain protected. |
| Reserved-test protection error | Use development fixtures or independent evaluation data. Only pass `--allow-official-test` when intentionally consuming the frozen benchmark. |
| Configuration errors | Backend reads exported `CYBERGUARD_*` variables, not YAML or `.env` automatically. Check port/batch/log-level constraints and explicitly export your trusted `.env` if used. Offline scripts retain their documented CLI options. |
| API startup fails / model returns 503 | Check configuration first; inspect `/api/v1/models` for independent readiness. Restore the trusted artifact, adjacent NF metadata and frozen evaluation manifest/metrics; do not retrain or reevaluate to repair startup. Restart to reload. There is no dummy fallback. |
| Port already in use / bind denied | Stop the previous local server or change `CYBERGUARD_API_PORT` (launcher) / uvicorn `--port`. A sandbox may require local socket permission. |
| HTTP 422 | Check exact required field names/types, unexpected fields and configured batch limit. A string represented as invalid by preprocessing is different from an invalid JSON structure. |
| API tests hang in a restricted sandbox | TestClient needs event-loop thread wakeups; run the same tests in a normal local environment with local socket support. |
| Dashboard says backend or selected model unavailable | Check `/health` and `/api/v1/models/{id}/ready` separately. Verify `CYBERGUARD_API_URL`, restore the selected artifact if needed and click **Refresh connection**. Another model may still be available; choose it explicitly. There is no automatic fallback or background polling. |
| Dashboard has no historical metrics | Restore the selected model’s published JSON/CSV/figure artifacts and matching manifest. NF metrics must match the selected artifact version. Never regenerate metrics from a reserved dataset to repair the dashboard. |
| Dashboard upload rejected | Use UTF-8, the required schema, consistent CSV rows, and at most 5 MiB / 20,000 records. Split larger files explicitly. Uploaded model/pickle files are never accepted. |
| Dashboard batch interrupted | No partial result is offered. Check the backend, refresh connection, then rerun the whole file explicitly. API errors are sanitized; inspect backend logs locally for diagnostics. |
| Poor predictions / high false positives | Review the linked reports and header-only limitations. Do not interpret manual probabilities or synthetic-fixture scores as a production safety assessment. |
