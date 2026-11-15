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


@dataclass(frozen=True)
class Connection:
    info: ModelInfoResponse | None = None
    batch_limit: int | None = None
    error: str | None = None
    live: bool = False

    @property
    def ready(self):
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

    def _request(self, path, payload=None):
        data = (
            None if payload is None else json.dumps(payload, allow_nan=False).encode()
        )
        request = Request(
            self.base_url + path,
            data=data,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            method="GET" if data is None else "POST",
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
                503: "The backend model is unavailable. Check the API and retry the connection.",
            }
            raise APIError(
                messages.get(
                    exc.code,
                    f"The API returned HTTP {exc.code}. Check the backend and retry.",
                )
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
