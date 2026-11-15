"""Framework-independent prediction adapter using the fitted pipeline directly."""

from dataclasses import dataclass
from threading import Lock

import numpy as np
import pandas as pd

from cyberguard.features.network import RAW_FEATURES, TARGETS

WARNING = (
    "Experimental header-only prediction; probabilities are uncalibrated. "
    "Normal does not establish safety. Theft and unknown attacks are unsupported. "
    "No live packet-level detection is performed."
)


def predict_frame(model, frame, *, probabilities=False):
    prediction = np.asarray(model.predict(frame.loc[:, RAW_FEATURES]))
    if prediction.shape != (len(frame),) or not set(prediction) <= set(TARGETS):
        raise ValueError("Model predictions must be one supported class per input row")
    added = {"prediction": prediction}
    if probabilities:
        if not callable(getattr(model, "predict_proba", None)):
            raise ValueError("This model does not expose predict_proba()")
        classes = list(map(str, getattr(model, "classes_", [])))
        values = np.asarray(
            model.predict_proba(frame.loc[:, RAW_FEATURES]), dtype=float
        )
        if (
            len(set(classes)) != len(classes)
            or not set(classes) <= set(TARGETS)
            or values.shape != (len(frame), len(classes))
            or not np.isfinite(values).all()
            or (values < 0).any()
            or (values > 1).any()
            or not np.allclose(values.sum(axis=1), 1)
        ):
            raise ValueError("Model probabilities/classes have invalid shape or values")
        for label in TARGETS:
            if label in classes:
                added[f"probability_{label}"] = values[:, classes.index(label)]
    collisions = set(frame.columns) & set(added)
    if collisions:
        raise ValueError(
            f"Output column collision; rename input columns: {sorted(collisions)}"
        )
    return frame.assign(**added)


class InferenceError(RuntimeError):
    """Inference failed without generating a placeholder prediction."""


@dataclass(frozen=True)
class Prediction:
    prediction: str
    probabilities: dict[str, float] | None
    model: str
    warning: str = WARNING


class NetworkDetector:
    def __init__(self, model, artifact_info):
        features = tuple(getattr(model, "feature_names_in_", ()))
        classes = list(getattr(model, "classes_", ()))
        if features != RAW_FEATURES:
            raise ValueError(
                "Model must expose required raw input features proto, sport, dport in that order"
            )
        if len(classes) != len(TARGETS) or set(classes) != set(TARGETS):
            raise ValueError(
                "Model must expose exactly Normal, DoS, DDoS, Reconnaissance"
            )
        if not callable(getattr(model, "predict", None)):
            raise TypeError("Model has no callable predict()")
        self._model = model
        self._lock = Lock()
        from pathlib import Path

        matched = artifact_info.get("matching_baseline_metadata") or {}
        self._metadata = {
            "model": Path(artifact_info["model_path"]).stem,
            "model_type": artifact_info["model_type"],
            "required_features": list(RAW_FEATURES),
            "supported_classes": list(TARGETS),
            "probabilities_available": callable(getattr(model, "predict_proba", None)),
            "artifact_sha256": artifact_info.get("model_sha256"),
            "preprocessing_contract_version": matched.get("preprocessing_version"),
            "warning": WARNING,
        }

    def supported_classes(self):
        return list(TARGETS)

    def metadata(self):
        # No local paths or arbitrary artifact metadata are exposed to callers.
        return {
            **self._metadata,
            "required_features": list(RAW_FEATURES),
            "supported_classes": list(TARGETS),
        }

    def predict_one(self, record):
        return self.predict_batch([record])[0]

    def predict_batch(self, records):
        if not records:
            raise ValueError("Prediction batch must not be empty")
        try:
            frame = pd.DataFrame(records)
            with self._lock:
                result = predict_frame(
                    self._model,
                    frame,
                    probabilities=self._metadata["probabilities_available"],
                )
            predictions = []
            for i in range(len(result)):
                probabilities = (
                    {
                        label: float(result[f"probability_{label}"].iloc[i])
                        for label in TARGETS
                    }
                    if self._metadata["probabilities_available"]
                    else None
                )
                predictions.append(
                    Prediction(
                        str(result.prediction.iloc[i]),
                        probabilities,
                        self._metadata["model"],
                    )
                )
            return predictions
        except Exception as exc:
            raise InferenceError("Network model inference failed") from exc
