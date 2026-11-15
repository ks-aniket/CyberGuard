"""Bounded HTTP-only dashboard client. No estimator or preprocessing imports."""

import json
import math
import os
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from pydantic import ValidationError

from cyberguard.core.schemas import (
    BatchPredictionResponse,
    ModelInfoResponse,
    NetworkRecord,
    PredictionResponse,
)


class APIError(ValueError):
    """A sanitized, user-facing communication/contract failure."""

    def __init__(self, message, *, status=None):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Connection:
    info: ModelInfoResponse | None = None
    batch_limit: int | None = None
    error: str | None = None
    live: bool = False

    models: tuple = ()
    selected: object | None = None
    mode: str | None = None
    batch_limits: dict | None = None

    @property
    def ready(self):
        if self.selected is not None:
            return (
                self.live
                and self.selected.readiness == "ready"
                and bool(self.batch_limit)
                and not self.error
            )
        return self.info is not None and self.batch_limit is not None and not self.error


class APIClient:
    def __init__(self, base_url=None, *, timeout=10, opener=None):
        self.base_url = (
            base_url
            if base_url is not None
            else os.getenv("CYBERGUARD_API_URL", "http://127.0.0.1:8000")
        ).rstrip("/")
        try:
            parts = urlsplit(self.base_url)
            valid = (
                parts.scheme in {"http", "https"}
                and parts.hostname
                and not parts.username
                and not parts.password
                and not parts.query
                and not parts.fragment
            )
            _ = parts.port
        except ValueError:
            valid = False
        if not valid:
            raise APIError(
                "CYBERGUARD_API_URL must be an HTTP(S) base URL without credentials, query or fragment."
            )
        if not math.isfinite(timeout) or timeout <= 0:
            raise APIError("The API timeout must be positive and finite.")
        self.timeout = timeout
        self.opener = opener or urlopen

    def _request(self, path, payload=None, *, method=None):
        data = (
            None if payload is None else json.dumps(payload, allow_nan=False).encode()
        )
        request = Request(
            self.base_url + path,
            data=data,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method=method or ("GET" if data is None else "POST"),
        )
        try:
            with self.opener(request, timeout=self.timeout) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise APIError("The API response exceeded the dashboard safety limit.")
            return json.loads(raw)
        except APIError:
            raise
        except HTTPError as exc:
            # Server response bodies can contain sensitive diagnostics. Never render them.
            messages = {
                422: "The backend rejected the input schema or batch size. Check the records and refresh connection details.",
                413: "The backend rejected the request size. Split the CSV into smaller files.",
                404: "The selected model is no longer registered. Refresh model details.",
                503: "The backend model is unavailable. Check the API and retry the connection.",
            }
            if path.startswith("/api/v1/simulations"):
                messages.update(
                    {
                        404: "Simulation no longer exists. The backend may have restarted; refresh simulation history.",
                        409: "The simulation state changed. Refresh it before trying another lifecycle action.",
                        429: "Simulation capacity reached. Stop active runs or delete finished runs.",
                        422: "Simulation configuration was rejected. Refresh API limits and check the values.",
                        413: "The simulation request exceeds the backend size limit.",
                    }
                )
            raise APIError(
                messages.get(
                    exc.code,
                    f"The API returned HTTP {exc.code}. Check the backend and retry.",
                ),
                status=exc.code,
            ) from None
        except (TimeoutError, URLError, OSError) as exc:
            timed_out = isinstance(exc, TimeoutError) or isinstance(
                getattr(exc, "reason", None), TimeoutError
            )
            raise APIError(
                "The API request timed out. Retry the connection."
                if timed_out
                else "Cannot connect to the API. Start the backend and retry the connection."
            ) from None
        except (ValueError, UnicodeError):
            raise APIError("The API returned an invalid JSON response.") from None

    def check_connection(self):
        live = False
        try:
            if self._request("/health") != {
                "status": "ok",
                "service": "cyberguard-api",
            }:
                raise APIError("The API liveness response is incompatible.")
            live = True
            ready = self._request("/health/ready")
            if ready != {"status": "ready", "model_loaded": True}:
                raise APIError("The backend model is not ready.")
            info = ModelInfoResponse.model_validate(self._request("/api/v1/model/info"))
            if (
                info.required_features != ["proto", "sport", "dport"]
                or len(info.supported_classes) != 4
                or len(set(info.supported_classes)) != 4
                or not info.model.strip()
                or not info.model_type.strip()
            ):
                raise APIError(
                    "The backend feature/class contract is incompatible with this dashboard."
                )
            spec = self._request("/openapi.json")
            schema = spec["paths"]["/api/v1/predict/batch"]["post"]["requestBody"][
                "content"
            ]["application/json"]["schema"]
            if "$ref" in schema:
                schema = self._resolve(spec, schema["$ref"])
            limit = schema["properties"]["records"]["maxItems"]
            if type(limit) is not int or limit < 1:
                raise APIError("The API did not advertise a valid batch limit.")
            return Connection(info, limit, live=True)
        except APIError as exc:
            return Connection(error=str(exc), live=live)
        except (ValidationError, KeyError, TypeError, ValueError):
            return Connection(
                error="The API metadata or OpenAPI batch contract is invalid.",
                live=live,
            )

    @staticmethod
    def _resolve(spec, ref):
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise APIError("The API schema uses an unsupported reference.")
        for part in ref[2:].split("/"):
            spec = spec[part.replace("~1", "/").replace("~0", "~")]
        return spec

    @staticmethod
    def _record(record):
        try:
            return NetworkRecord.model_validate(record).model_dump()
        except ValidationError:
            raise APIError(
                "Invalid record: require exactly proto, sport and dport as strings, integers or null."
            ) from None

    @staticmethod
    def _prediction(result):
        if not result.model.strip() or not result.warning.strip():
            raise APIError("The API returned incomplete prediction metadata.")
        if result.probabilities is not None:
            values = result.probabilities.values()
            if (
                len(result.probabilities) != 4
                or any(not math.isfinite(p) or not 0 <= p <= 1 for p in values)
                or not math.isclose(sum(values), 1, abs_tol=1e-6)
            ):
                raise APIError("The API returned an invalid probability distribution.")
        return result

    def predict(self, record):
        try:
            return self._prediction(
                PredictionResponse.model_validate(
                    self._request("/api/v1/predict", self._record(record))
                )
            )
        except ValidationError:
            raise APIError(
                "The API returned an invalid single-prediction response."
            ) from None

    def predict_batch(self, records):
        try:
            result = BatchPredictionResponse.model_validate(
                self._request(
                    "/api/v1/predict/batch",
                    {"records": [self._record(r) for r in records]},
                )
            )
            if result.count != len(records) or len(result.predictions) != len(records):
                raise APIError(
                    "The API returned an incomplete batch. No complete result is available."
                )
            return [self._prediction(p) for p in result.predictions]
        except ValidationError:
            raise APIError(
                "The API returned an invalid batch-prediction response."
            ) from None

    def predict_chunks(self, records, *, batch_limit, expected_model, progress=None):
        if type(batch_limit) is not int or batch_limit < 1 or not records:
            raise APIError(
                "A positive advertised batch limit and nonempty input are required."
            )
        size = min(batch_limit, 250)
        predictions = []
        for start in range(0, len(records), size):
            chunk = self.predict_batch(records[start : start + size])
            if any(p.model != expected_model for p in chunk):
                raise APIError(
                    "The backend model changed. Refresh the connection and rerun the entire upload."
                )
            predictions.extend(chunk)
            if progress:
                progress(len(predictions), len(records))
        # The caller receives nothing until every chunk succeeds. No automatic retries.
        return predictions

    def list_models(self):
        from cyberguard.dashboard.contracts import ModelMetadata

        try:
            result = self._request("/api/v1/models")
            models = [ModelMetadata.model_validate(v) for v in result["models"]]
            if len({m.id for m in models}) != len(models):
                raise ValueError("Duplicate IDs")
            return models
        except APIError:
            raise
        except (ValidationError, KeyError, TypeError, ValueError):
            raise APIError(
                "The model registry response is invalid or incompatible."
            ) from None

    def model_info(self, model_id):
        from urllib.parse import quote

        from cyberguard.dashboard.contracts import ModelMetadata

        try:
            model = ModelMetadata.model_validate(
                self._request("/api/v1/models/" + quote(model_id, safe=""))
            )
            if model.id != model_id:
                raise ValueError("Model mismatch")
            return model
        except APIError:
            raise
        except (ValidationError, KeyError, TypeError, ValueError):
            raise APIError(
                "The selected model metadata is invalid or incompatible."
            ) from None

    def model_ready(self, model_id):
        from urllib.parse import quote

        result = self._request("/api/v1/models/" + quote(model_id, safe="") + "/ready")
        if result != {"model_id": model_id, "status": "ready", "model_loaded": True}:
            raise APIError("The selected model readiness response is invalid.")
        return True

    def check_models(self):
        live = False
        try:
            if self._request("/health") != {
                "status": "ok",
                "service": "cyberguard-api",
            }:
                raise APIError("The API liveness response is incompatible.")
            live = True
            models = self.list_models()
            spec = self._request("/openapi.json")
            # Same typed alternatives used by both model-specific endpoints.
            schema = spec["paths"]["/api/v1/models/{model_id}/predict/batch"]["post"][
                "requestBody"
            ]["content"]["application/json"]["schema"]
            alternatives = schema.get("anyOf", schema.get("oneOf", [schema]))
            limits = {}
            for item in alternatives:
                item = self._resolve(spec, item["$ref"]) if "$ref" in item else item
                records = item["properties"]["records"]
                limit = records["maxItems"]
                if type(limit) is not int or limit < 1:
                    raise ValueError("Invalid batch bound")
                record = records["items"]
                record = (
                    self._resolve(spec, record["$ref"]) if "$ref" in record else record
                )
                for model in models:
                    if set(record["required"]) == set(model.required_features):
                        limits[model.id] = limit
            return Connection(models=tuple(models), batch_limits=limits, live=True)
        except APIError as exc:
            return Connection(error=str(exc), live=live)
        except (KeyError, TypeError, ValueError):
            return Connection(
                error="The registry or model batch schema is invalid.", live=live
            )

    def select_model(self, connection, model_id, mode=None):
        from dataclasses import replace

        try:
            model = self.model_info(model_id)
            if model.readiness != "ready":
                return replace(
                    connection,
                    selected=model,
                    mode=mode or model.default_operating_mode,
                    batch_limit=(connection.batch_limits or {}).get(model_id),
                    error="Selected model is unavailable. Choose another model or refresh after restoring it.",
                )
            self.model_ready(model_id)
            mode = mode or model.default_operating_mode
            model.threshold(mode)
            if model_id not in (connection.batch_limits or {}):
                raise APIError(
                    "No compatible advertised batch limit for the selected model."
                )
            return replace(
                connection,
                selected=model,
                mode=mode,
                batch_limit=connection.batch_limits[model_id],
                live=True,
                error=None,
            )
        except APIError as exc:
            return replace(
                connection,
                selected=next((m for m in connection.models if m.id == model_id), None),
                error=str(exc),
            )
        except ValueError:
            return replace(
                connection,
                error="The selected operating mode is unavailable. Refresh model details.",
            )

    def _model_prediction(self, body, model, mode):
        from cyberguard.dashboard.contracts import ModelPrediction

        try:
            result = ModelPrediction.model_validate(body)
            if (
                result.model_id != model.id
                or result.model_version != model.model_version
                or result.task != model.task
                or result.input_contract_version != model.input_contract_version
                or result.operating_mode != mode
                or result.applied_threshold != model.threshold(mode)
                or result.predicted_class not in model.classes
                or not result.inference_timestamp
                or not result.limitations
                or not result.score_semantics
            ):
                raise ValueError("Prediction metadata mismatch")
            if result.class_scores is not None:
                values = list(result.class_scores.values())
                if (
                    list(result.class_scores) != model.classes
                    or any(not math.isfinite(p) or not 0 <= p <= 1 for p in values)
                    or not math.isclose(sum(values), 1, abs_tol=1e-6)
                ):
                    raise ValueError("Invalid class scores")
            if result.positive_class_score is not None:
                if (
                    not math.isfinite(result.positive_class_score)
                    or not 0 <= result.positive_class_score <= 1
                    or result.class_scores is None
                    or result.positive_class_score
                    != result.class_scores[model.classes[-1]]
                ):
                    raise ValueError("Invalid positive-class score")
            elif model.task == "binary":
                raise ValueError("Missing binary score")
            return result
        except (ValidationError, ValueError, KeyError, TypeError):
            raise APIError(
                "Prediction response does not match the selected model/version/mode. Refresh connection details."
            ) from None

    def predict_model(self, model, record, mode):
        from urllib.parse import quote

        from cyberguard.dashboard.contracts import validate_record

        try:
            validate_record(model, record)
            model.threshold(mode)
        except ValueError as exc:
            raise APIError(str(exc)) from None
        return self._model_prediction(
            self._request(
                "/api/v1/models/" + quote(model.id, safe="") + "/predict",
                {"record": record, "operating_mode": mode},
            ),
            model,
            mode,
        )

    def predict_model_batch(self, model, records, mode):
        from urllib.parse import quote

        from cyberguard.dashboard.contracts import validate_record

        try:
            model.threshold(mode)
            for record in records:
                validate_record(model, record)
        except ValueError as exc:
            raise APIError(str(exc)) from None
        body = self._request(
            "/api/v1/models/" + quote(model.id, safe="") + "/predict/batch",
            {"records": records, "operating_mode": mode},
        )
        try:
            if (
                type(body["count"]) is not int
                or body["count"] != len(records)
                or len(body["predictions"]) != len(records)
            ):
                raise ValueError("Incomplete batch")
            return [self._model_prediction(p, model, mode) for p in body["predictions"]]
        except APIError:
            raise
        except (KeyError, TypeError, ValueError):
            raise APIError(
                "The API returned an incomplete or invalid batch. No complete result is available."
            ) from None

    def predict_model_chunks(self, model, records, mode, *, batch_limit, progress=None):
        from cyberguard.dashboard.contracts import validate_record

        if type(batch_limit) is not int or batch_limit < 1 or not records:
            raise APIError(
                "A positive advertised batch limit and nonempty input are required."
            )
        # Validate the entire upload before the first request, never after partial inference.
        try:
            for record in records:
                validate_record(model, record)
            model.threshold(mode)
        except ValueError as exc:
            raise APIError(str(exc)) from None
        result = []
        for start in range(0, len(records), min(batch_limit, 250)):
            result.extend(
                self.predict_model_batch(
                    model, records[start : start + min(batch_limit, 250)], mode
                )
            )
            if progress:
                progress(len(result), len(records))
        return result

    def simulation_schema(self):
        try:
            spec = self._request("/openapi.json")
            schema = spec["paths"]["/api/v1/simulations"]["post"]["requestBody"][
                "content"
            ]["application/json"]["schema"]
            schema = self._resolve(spec, schema["$ref"]) if "$ref" in schema else schema
            required = {
                "model_id",
                "mode",
                "benign_ratio",
                "attack_ratio",
                "seed",
                "generation_rate",
                "max_duration",
                "max_records",
                "batch_size",
                "queue_capacity",
                "event_capacity",
                "history_capacity",
                "operating_mode",
            }
            if not required <= schema["properties"].keys():
                raise ValueError("Missing simulation fields")
            if not {"empirical", "synthetic"} <= set(
                schema["properties"]["mode"].get("enum", [])
            ) or not {"standard", "high_sensitivity"} <= set(
                schema["properties"]["operating_mode"].get("enum", [])
            ):
                raise ValueError("Missing supported simulation modes")
            for name in (
                "seed",
                "generation_rate",
                "max_duration",
                "max_records",
                "batch_size",
                "queue_capacity",
                "event_capacity",
                "history_capacity",
            ):
                rule = schema["properties"][name]
                if type(rule.get("maximum")) not in (float, int) or not (
                    "minimum" in rule or "exclusiveMinimum" in rule
                ):
                    raise ValueError("Missing resource bounds")
            return schema
        except APIError:
            raise
        except (KeyError, ValueError, TypeError):
            raise APIError(
                "The backend simulation configuration schema is unavailable or incompatible."
            ) from None

    def _simulation_response(self, body, kind, identifier=None):
        try:
            result = kind.model_validate(body)
            if identifier is not None and result.id != identifier:
                raise ValueError("Simulation ID mismatch")
            return result.model_dump()
        except (ValidationError, ValueError, KeyError, TypeError):
            raise APIError(
                "The API returned an incompatible simulation response. Refresh simulation history."
            ) from None

    def list_simulations(self):
        from cyberguard.dashboard.simulation_contracts import Snapshot

        try:
            body = self._request("/api/v1/simulations")
            if (
                not isinstance(body["simulations"], list)
                or len(body["simulations"]) > 100
            ):
                raise ValueError("Unbounded simulation history")
            values = [
                self._simulation_response(v, Snapshot) for v in body["simulations"]
            ]
            if len({v["id"] for v in values}) != len(values):
                raise ValueError("Duplicate simulation IDs")
            return values
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, APIError):
                raise
            raise APIError("The API returned invalid simulation history.") from None

    def create_simulation(self, payload):
        from cyberguard.dashboard.simulation_contracts import Snapshot

        return self._simulation_response(
            self._request("/api/v1/simulations", payload), Snapshot
        )

    @staticmethod
    def _simulation_path(identifier):
        from cyberguard.dashboard.simulation_contracts import simulation_path

        try:
            return simulation_path(identifier)
        except ValueError:
            raise APIError(
                "Invalid simulation selection. Refresh Lab and select a current run."
            ) from None

    def get_simulation(self, identifier):
        from cyberguard.dashboard.simulation_contracts import Snapshot

        return self._simulation_response(
            self._request(self._simulation_path(identifier)), Snapshot, identifier
        )

    def _simulation_action(self, identifier, action):
        from cyberguard.dashboard.simulation_contracts import Snapshot

        return self._simulation_response(
            self._request(self._simulation_path(identifier) + "/" + action, {}),
            Snapshot,
            identifier,
        )

    def start_simulation(self, identifier):
        return self._simulation_action(identifier, "start")

    def pause_simulation(self, identifier):
        return self._simulation_action(identifier, "pause")

    def resume_simulation(self, identifier):
        return self._simulation_action(identifier, "resume")

    def stop_simulation(self, identifier):
        return self._simulation_action(identifier, "stop")

    def delete_simulation(self, identifier):

        result = self._request(self._simulation_path(identifier), method="DELETE")
        if result != {"id": identifier, "deleted": True}:
            raise APIError("The API returned an invalid simulation deletion response.")
        return result

    def simulation_metrics(self, identifier):
        from cyberguard.dashboard.simulation_contracts import Metrics

        return self._simulation_response(
            self._request(self._simulation_path(identifier) + "/metrics"),
            Metrics,
            identifier,
        )

    def simulation_events(self, identifier, *, after=-1, limit=500):
        from cyberguard.dashboard.simulation_contracts import EventPage

        if (
            type(after) is not int
            or after < -1
            or type(limit) is not int
            or not 1 <= limit <= 1000
        ):
            raise APIError("Invalid simulation cursor or page size")
        result = self._simulation_response(
            self._request(
                self._simulation_path(identifier)
                + f"/events?after={after}&limit={limit}"
            ),
            EventPage,
            identifier,
        )
        if any(e["sequence"] <= after for e in result["events"]) or (
            not result["events"] and result["next_cursor"] != after
        ):
            raise APIError("The API returned an invalid simulation cursor.")
        return result
