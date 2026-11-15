# CyberGuard

CyberGuard is an experimental AI-assisted network intrusion detection MVP. It analyzes offline datasets and serves a restricted BoT-IoT network classifier through a testing CLI and local FastAPI backend. It is **not a production IDS** and does not capture packets or detect live attacks.

## Project overview

Implemented:

- Chunked EDA for BoT-IoT and DNS Threats, including duplicate, label-conflict, feature-availability and leakage audits.
- Reusable protocol/port preprocessing and a small CPU-only decision-tree baseline with deterministic group-aware training/validation separation.
- A fitted four-class model: **Normal, DoS, DDoS, Reconnaissance**.
- Model inspection, repeated interactive predictions, chunked CSV predictions and labeled offline evaluation through the network testing CLI.
- A lifespan-managed FastAPI backend with health/readiness, model metadata, single/batch JSON predictions and interactive Swagger documentation.
- A dark Streamlit dashboard with Overview, Interactive Testing, Batch Testing, Model Performance and About pages, using HTTP inference and saved historical reports.
- Unit/integration tests, reports and reproducible baseline artifacts.

Planned, not implemented: packet capture/live monitoring, streaming replay and alert/storage services. Those components remain scaffolding. The dashboard and Swagger UI provide manual testing, with no live monitoring. Authentication, persistence and background workers are not implemented in this phase.

Known limitations:

- Predictors are only `proto`, `sport`, `dport`. IPs, record IDs, labels, flow state, rates and historical aggregates are excluded. Headers alone do not reliably distinguish every attack.
- Theft and unknown attack classes are unsupported. A Normal prediction does not establish that traffic is safe.
- Training contains only 370 benign records; internal validation had 79 benign records. Reported validation macro-F1 was 0.6753 and benign false-positive rate was 15.19%. These are **internal validation results**, not independent final-test performance or a deployment guarantee.
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

EDA, baseline training and the testing CLI require no environment variables or API keys. The backend accepts optional exported `CYBERGUARD_*` settings documented under [Running the application](#running-the-application); development defaults work without configuration. `configs/app.yaml`, `configs/training.yaml` and `configs/replay.yaml` remain empty placeholders and are not read. Neither the Python application nor the launcher automatically loads `.env`. CLI arguments control offline input/output/model/chunking options; the training baseline has fixed settings documented in its report.

Datasets must be acquired separately; raw data and models are ignored by Git. Preserve the raw files at these exact paths when running EDA or baseline training:

```text
data/raw/bot_iot/train/UNSW_2018_IoT_Botnet_Final_10_best_Training.csv
data/raw/bot_iot/test/UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv
data/raw/dns_threats/train_combined_multiclass.csv
data/raw/dns_threats/test_combined_multiclass.csv
```

The prediction CLI and API need only a fitted model and supplied input records; raw datasets are not required. Default artifact locations:

```text
models/network/bot_iot_restricted_baseline.joblib   # fitted preprocessing + classifier
models/network/bot_iot_split_manifest.csv.gz       # group/label/count/partition audit
reports/model_evaluation/bot_iot_validation_metrics.json
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
├── data/samples/                   # optional local CSV samples (Git-ignored)
├── models/network/                 # fitted pipeline and group manifest (Git-ignored)
├── reports/dataset_analysis/        # EDA and DNS investigation
├── reports/model_evaluation/        # baseline and user-requested evaluation reports
├── runtime/                        # local predictions/output (Git-ignored)
├── scripts/                        # EDA, training, network testing, API/dashboard launchers
├── src/cyberguard/features/         # implemented network normalizer and sklearn pipeline
├── src/cyberguard/training/         # group assignment, baseline fit, validation reporting
├── src/cyberguard/testing/          # implemented network_model_cli.py; other files are placeholders
├── src/cyberguard/api/              # app factory, lifespan, dependency injection and routes
├── src/cyberguard/inference/        # shared artifact loader and independent NetworkDetector
├── src/cyberguard/core/             # backend settings, strict JSON schemas and logging
├── src/cyberguard/dashboard/        # HTTP client, CSV/report readers, pages and charts
├── .streamlit/config.toml          # dark theme, localhost, 5 MiB server upload limit
├── src/cyberguard/{streaming,storage,ingestion}/
│                                   # unimplemented application scaffolding
└── tests/                          # unit software tests and API integration tests
```

`tests/integration/test_api.py` exercises the API with FastAPI TestClient and synthetic local model fixtures. Other integration files remain placeholders. Synthetic fixtures in the unit tests check software behavior; they are not evidence of detection generalization.

## Running scripts

All examples below run from the repository root. The table lists working user-facing entry points; empty scripts are listed separately to avoid implying they work.

| Script | Purpose | Example command |
| --- | --- | --- |
| `scripts/inspect_datasets.py` | Analyze both datasets and write EDA reports | `uv run python scripts/inspect_datasets.py --chunk-size 50000 --sample-size 30000` |
| `scripts/train_network_baseline.py` | Train the fixed restricted network baseline | `uv run python scripts/train_network_baseline.py` |
| `scripts/test_network_model.py` | Inspect, predict and evaluate using a fitted model | `uv run python scripts/test_network_model.py interactive` |
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

# CLI and EDA help (safe; no model fitting)
uv run python scripts/test_network_model.py --help
uv run python scripts/test_network_model.py evaluate --help
uv run python scripts/inspect_datasets.py --help
```

Tests use temporary small fixtures; they do not evaluate the real official test dataset. Training tests fit only synthetic software fixtures and do not alter the saved baseline. The CLI test fixtures exercise model loading, input handling, chunking/order, probability alignment, metrics, exclusions, overwrite protection and no-refit/protected-path behavior. API tests use FastAPI TestClient (`httpx2` is a locked dev dependency for the installed Starlette version), synthetic serialized predictors and temporary files; they verify startup failures, model reuse, strict schemas, bounds, error responses and model integrity. If a restricted execution sandbox blocks local sockets or cross-thread event-loop wakeups, run API integration tests in a normal local environment; do not disable the tests or protections.

Before completing development work, update this root README for every introduced/changed script, CLI interface, entry point, configuration requirement or workflow; verify commands and paths, correct stale examples and distinguish implemented features from plans. This maintenance requirement also lives in [AGENTS.md](AGENTS.md).

## Running the application

See the [Phase 4A completion record](reports/phase4a_backend.md) for verification evidence and the complete file list.

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

`--host`, `--port` and uvicorn's logging flags govern the direct command; `CYBERGUARD_API_HOST`, `CYBERGUARD_API_PORT` and `CYBERGUARD_LOG_LEVEL` govern the launcher. `CYBERGUARD_LOG_LEVEL` also governs CyberGuard application logs in either mode. Model path and batch size settings apply to both launches. One model is loaded per application lifespan/process, with no reload flag by default. Multiple explicitly configured uvicorn workers would each have their own model copy; no workers are started by this launcher.

| Environment variable | Default | Validation / meaning |
| --- | --- | --- |
| `CYBERGUARD_NETWORK_MODEL_PATH` | `models/network/bot_iot_restricted_baseline.joblib` under the repository/package root | Trusted local fitted artifact. Relative paths resolve from that root, independent of cwd. No HTTP request can select a model file. |
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

`.env` is Git-ignored. No credentials are required for this local backend. Startup fails clearly if configuration is invalid, the model is missing/incompatible/unfitted, or a prediction compatibility check fails. It never falls back to a dummy model. Existing preprocessing is used directly without refitting; startup performs one two-record synthetic compatibility batch, not training or model evaluation.

### Endpoints

| Method / path | Purpose | Result |
| --- | --- | --- |
| `GET /health` | Basic service liveness, without inference | `{"status":"ok","service":"cyberguard-api"}` |
| `GET /health/ready` | Model availability, without inference | `{"status":"ready","model_loaded":true}` or 503 |
| `GET /api/v1/model/info` | Model identifier/type, features, classes, probability availability, SHA-256 and contract version when verified | No local filesystem paths; unavailable metadata is null |
| `POST /api/v1/predict` | One supplied header record | Class, optional probabilities, model identifier and limitations warning |
| `POST /api/v1/predict/batch` | Vectorized ordered batch | `{"predictions":[...],"count":N}` |

All three fields (`proto`, `sport`, `dport`) are required, even when explicitly null. Each accepts a strict JSON string, integer or null. Null represents missingness; pipeline-supported empty/NA/malformed/sentinel/out-of-range string values remain model inputs under its existing statuses. Protocol aliases and decimal/hex string ports follow the CLI contract above. Booleans, floating JSON numbers, arrays, objects, missing fields and unexpected fields are schema errors. Use a string for textual values such as `"80.0"` if intentionally testing the pipeline's invalid-port representation. No client-supplied addresses, labels or model paths are accepted.

A batch requires `records`, rejects empty lists, and defaults to a maximum of 1,000 records. An oversized batch is rejected as a whole before inference. Results preserve record order; the model is reused across requests. The framework-independent `NetworkDetector` shares the CLI's prediction/probability helper and serializes access to its loaded estimator; each batch makes vectorized pipeline calls, not one call per row.

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
| 503 | `model_unavailable` | Detector is not ready; normal startup failures prevent serving at all |
| 500 | `inference_failed` | Loaded estimator failed; no placeholder prediction is returned |
| 500 | `internal_error` | Unexpected application failure; details stay on the server |
| 404/405 | `http_error` | Unknown route or unsupported method |

Logs include startup/shutdown, model loading status/identifier, prediction request counts and batch sizes, and error types. They do not log raw network records or request bodies. Startup diagnostics can name the configured local model path on the server; HTTP model metadata/error responses omit local paths. This is a local, unauthenticated inference-serving backend, not packet capture, live monitoring or an operational IDS. Replay, persistence, alert generation and DNS detection remain unimplemented.

### Dashboard workflow

Start the API and dashboard in separate terminals:

```bash
# Terminal 1
bash scripts/start_api.sh
# Terminal 2
bash scripts/start_dashboard.sh
```

Open [CyberGuard dashboard](http://127.0.0.1:8501). Backend port **8000** serves JSON/Swagger; dashboard port **8501** serves the browser interface. The dashboard makes server-side HTTP calls; browser CORS settings are unnecessary. From the repository root, direct launch also works:

```bash
uv run streamlit run src/cyberguard/dashboard/app.py
```

Imports work under the existing `src/` layout without installation of a separate package. `.streamlit/config.toml` configures the dark theme, localhost, disabled usage statistics and a 5 MiB upload bound. For direct invocation, Streamlit's own `--server.port PORT` option can override its port; the launcher intentionally fixes localhost:8501. No `.env` is automatically loaded. Export `CYBERGUARD_API_URL` before starting the dashboard when using a nondefault API address; restart the dashboard after configuration changes. No keys are required.

- **Overview:** reads API liveness/readiness, actual model identifier/type, classes/features and probability availability. Historical validation scores are read from the existing JSON/CSV artifacts, with an artifact-hash match check against the API when connected. These are never live statistics.
- **Interactive Testing:** choose a common or custom protocol, enter port tokens (including decimal/hex, sentinel or invalid strings), or explicitly select JSON null. Click **Predict record**. Results show the actual API class, submitted values, model identifier and optional uncalibrated probabilities. ICMP/ARP fields are not TCP/UDP ports. The last successful submitted record is shown explicitly, even if controls have since changed.
- **Batch Testing:** upload UTF-8 CSV with exact columns `proto,sport,dport`, preview the first 20 rows, then click **Classify CSV**. Extra columns remain local and are retained in results; labels are never evaluated. Tokens, all rows and row order are preserved. The **Load demonstration CSV** button supplies the same four synthetic unlabeled examples shown above; they establish no detection quality. Uploads take priority over that example.
- Batch bounds are **5 MiB / 20,000 records**. Headers must be unique/nonempty, row widths consistent, and quoting valid; empty/header-only files, output-column collisions and malformed records fail explicitly. Requests contain at most `min(advertised API maximum, 250)` records. The bound is read from `/openapi.json`, not assumed. Each HTTP request has a 10-second timeout; there are no automatic retries. Progress covers completed records, and a failing request discards the entire attempted result rather than offering a partial export. Start again explicitly after refreshing the connection.
- Completed batch results show class counts/percentages, an ordered feature/prediction table paginated at 100 records and **Download prediction CSV** for all records. These are **Model predictions on uploaded records**, not verified attacks. Downloads contain original columns plus `prediction`, `model`, `warning` and available `probability_*` columns. Spreadsheet formula prefixes in all text cells and headers are escaped with an apostrophe on export only, including sentinel strings like `-1`; preserve that distinction if reusing a download as machine input. Raw previews/results use native tables without an alternate unescaped dataframe CSV download. Uploads/results stay in session memory and are not written to the repository.
- **Model Performance:** reads `bot_iot_validation_metrics.json` and `bot_iot_validation_confusion.csv` from `reports/model_evaluation/`. Displays summary scores, grouped precision/recall/F1, exact confusion counts (actual rows/predicted columns), optional row percentages and logarithmic class supports. It remains usable without the backend. Missing/inconsistent artifacts show a clear warning; nothing is recomputed or fabricated.
- **About CyberGuard:** architecture, input contract, scope/limitations and expandable existing local documentation.

Use **Refresh connection** in the sidebar after starting/restarting the API. Status is checked on the initial session and explicit refresh, not on every widget interaction; its timestamp can therefore be stale. Prediction failures mark the connection unavailable and clear results; submissions remain blocked until refreshed. Refresh also clears prior prediction results. There is no silent fallback model. A Normal prediction does not establish safety; a DDoS prediction does not prove an attack. Theft/unknown attacks and DNS remain unsupported.

All displayed validation numbers are labeled **Historical offline validation — not live detection performance.** The deterministic group-aware partition comes from the original training file, has only 79 Normal rows, and does not establish independent-session generalization. The reserved official test is never read by the dashboard. Software tests use mocked HTTP, bounded CSV fixtures, report fixtures and Streamlit AppTest, with no required backend. See the [Phase 4B completion record](reports/phase4b_dashboard.md) for verification and remaining limitations.

## Troubleshooting

| Problem | Action |
| --- | --- |
| Missing pandas/sklearn/joblib or pytest | Run `uv sync --frozen --group dev`; use `uv run`, not an unrelated system Python. For offline use, install/cache the locked dependencies first. |
| Python version/environment mismatch | Check `uv run python --version` is 3.13 and run from the repo root. Confirm `.python-version`, `pyproject.toml`, and `uv.lock` are present. |
| uv cache permission errors | Set `UV_CACHE_DIR` to a writable path. A direct `.venv/bin/python` invocation also works once provisioned. |
| Missing model artifact | Supply the existing trusted model via `--model`. Git ignores models. Recreating the baseline requires the documented training workflow and overwrites its artifacts; the testing CLI does not train automatically. |
| Invalid/incompatible model artifact | Use the trusted fitted pipeline and matching dependencies. Run `info`; a readable file without a callable `predict()` is rejected. |
| Missing raw dataset | Check the exact paths above. EDA requires all four CSVs; baseline training requires its training CSV only. Manual prediction requires neither. |
| `ModuleNotFoundError: cyberguard` when loading manually | Use the executable scripts, or set `PYTHONPATH=src` for your own Python process. |
| CSV schema/format error | Require `proto,sport,dport` and, for evaluation, `category`; use unique nonempty headers and equal field counts. Rename generated-column collisions. No records are silently skipped. |
| Unsupported category or undefined metric | Verify ground truth; use `--exclude-unsupported` only deliberately. Check class supports; do not turn undefined FPR or absent recall into zero. |
| Output already exists | Choose another output path or deliberately pass `--overwrite`. Raw inputs/model artifacts remain protected. |
| Reserved-test protection error | Use development fixtures or independent evaluation data. Only pass `--allow-official-test` when intentionally consuming the frozen benchmark. |
| Configuration errors | Backend reads exported `CYBERGUARD_*` variables, not YAML or `.env` automatically. Check port/batch/log-level constraints and explicitly export your trusted `.env` if used. Offline scripts retain their documented CLI options. |
| API startup fails | Check the trusted artifact path, environment, feature/class compatibility and server diagnostic. There is no dummy fallback. |
| Port already in use / bind denied | Stop the previous local server or change `CYBERGUARD_API_PORT` (launcher) / uvicorn `--port`. A sandbox may require local socket permission. |
| HTTP 422 | Check exact required field names/types, unexpected fields and configured batch limit. A string represented as invalid by preprocessing is different from an invalid JSON structure. |
| API tests hang in a restricted sandbox | TestClient needs event-loop thread wakeups; run the same tests in a normal local environment with local socket support. |
| Dashboard says backend unavailable | Start the API, check its readiness, verify exported `CYBERGUARD_API_URL`, then click **Refresh connection**. A stale green status can persist until refresh or the next failed request; there is no background poller. |
| Dashboard has no historical metrics | Restore the existing JSON/CSV validation artifacts at the documented paths. The dashboard needs neither a raw dataset nor API inference to display them. |
| Dashboard upload rejected | Use UTF-8, the required schema, consistent CSV rows, and at most 5 MiB / 20,000 records. Split larger files explicitly. Uploaded model/pickle files are never accepted. |
| Dashboard batch interrupted | No partial result is offered. Check the backend, refresh connection, then rerun the whole file explicitly. API errors are sanitized; inspect backend logs locally for diagnostics. |
| Poor predictions / high false positives | Review the linked reports and header-only limitations. Do not interpret manual probabilities or synthetic-fixture scores as a production safety assessment. |
