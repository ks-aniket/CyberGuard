# Phase 4A — FastAPI inference backend

Implemented and verified on 2026-11-15 (Asia/Kolkata). This is local inference serving for the existing header-only network model, not live packet capture, model retraining, DNS detection or a production IDS.

## Verification

- Complete suite: **111 passed**, including all prior CLI/preprocessing/training tests and new framework-independent inference/API integration tests.
- Ruff checks/format checks and Bash syntax check passed.
- Tests ran outside the restricted execution sandbox: its socket restrictions prevented TestClient event-loop thread wakeups. No tests or model protections were disabled.
- The launcher worked when called by absolute path from `/tmp`; the documented direct `uv run uvicorn ... --app-dir src` command also worked.
- Real localhost requests returned 200 for `/health`, `/health/ready`, `/api/v1/model/info`, `/docs`, `/api/v1/predict`, and `/api/v1/predict/batch`.
- `tcp,49152,80` returned DDoS with model-estimated probability 0.5732050811375292. The two-record TCP/UDP batch returned DDoS then Normal in input order. These are software demonstrations, not independent labeled evaluation.
- A boolean source port returned 422 with the sanitized validation-error structure.
- Loader spies prove one artifact load per application lifespan, while repeated requests reuse the same detector. Live startup logs showed one model load and incrementing request counts/batch sizes; health/info requests did not trigger inference.
- Default batch bound is 1,000; tests verified a configured bound and its matching OpenAPI schema. Empty/oversized batches fail before inference.
- Compatibility is checked before serving using exact exposed raw feature names/classes plus one vectorized two-record synthetic prediction probe. Nothing is fitted or recalibrated.
- Baseline artifact SHA-256 remains `93b744ada3af044e2d0e7d4dd6d5fa70870536e7a972443c806a232ce9052c6f`. The recorded training/preprocessing code hashes also remain unchanged. No raw CSV was modified and the reserved test split was not evaluated.
- Demonstration servers were stopped cleanly after verification. Start with `bash scripts/start_api.sh`; full setup and requests are in [README](../README.md).

## Created and modified files in this phase

| File | Change |
| --- | --- |
| `src/cyberguard/api/main.py` | App factory, lifespan, error handlers, route registration and Python server entry point |
| `src/cyberguard/api/dependencies.py` | App-state detector dependency and public error contract |
| `src/cyberguard/api/routes/health.py` | Liveness/readiness endpoints without inference |
| `src/cyberguard/api/routes/predictions.py` | Model info, single and vectorized batch endpoints; request-count logging |
| `src/cyberguard/inference/model_loader.py` | Shared trusted artifact loading/inspection, compatibility validation and startup diagnostics |
| `src/cyberguard/inference/network_detector.py` | Shared prediction/probability helper and framework-independent detector |
| `src/cyberguard/core/config.py` | Minimal validated environment settings with cwd-independent default model path |
| `src/cyberguard/core/schemas.py` | Strict JSON request/response schemas and configurable OpenAPI batch bound |
| `src/cyberguard/core/logging.py` | Consistently formatted logging without raw request records |
| `src/cyberguard/testing/network_model_cli.py` | Reuse shared inference/loader functions while preserving CLI behavior and loader test hook |
| `scripts/start_api.sh` | Any-cwd uv launcher, dependency checks, localhost defaults, no automatic reload |
| `.env.example` | Five supported exported settings; no automatic dotenv loading |
| `README.md` | Backend status, launcher, config, endpoints, Swagger, examples, testing and troubleshooting |
| `pyproject.toml` | Add the installed Starlette version's recommended `httpx2` development dependency for TestClient |
| `uv.lock` | Lock httpx2 and its new dependencies; existing model/runtime package versions were retained |
| `tests/conftest.py` | Shared synthetic serialized model fixtures with no-refit assertions |
| `tests/unit/test_network_inference.py` | Loader, compatibility, prediction order, metadata, optional probabilities and configuration tests |
| `tests/integration/test_api.py` | Lifespan, endpoints, validation, errors, batch limits, model reuse, no-refit and artifact-integrity tests |
| `reports/phase4a_backend.md` | This completion record and complete file list |

The pre-existing README/AGENTS and CLI work in the shared workspace was preserved. `AGENTS.md`'s permanent documentation-maintenance instruction remains in place; it was not changed again during this phase.

## Remaining boundaries

No implementation blockers remain for the requested phase. Model probabilities remain uncalibrated; Normal predictions do not establish safety, and Theft/unknown attacks remain unsupported. The service has no authentication, persistence, background workers, alerts, dashboard, replay or live monitoring. Further serving/model phases need independent evidence and their own scope. No existing validation score was recharacterized as final-test or production performance.
