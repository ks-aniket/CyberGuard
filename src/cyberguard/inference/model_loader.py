"""Trusted local artifact loading and inspectable metadata; no fitting."""

import hashlib
import json
import logging
from pathlib import Path

import joblib

from cyberguard.features.network import RAW_FEATURES

logger = logging.getLogger(__name__)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_model(path, *, loader=None):
    path = Path(path)
    if not path.is_file():
        raise ValueError(
            f"Model artifact not found: {path}. Obtain the existing trained model; no training is performed by this CLI."
        )
    try:
        model = (loader or joblib.load)(path)
    except Exception as exc:
        raise ValueError(f"Cannot load model artifact {path}: {exc}") from exc
    if not callable(getattr(model, "predict", None)):
        raise TypeError("Invalid model artifact: no callable predict() method")
    return model


def inspect_model(model, path, root):
    steps = getattr(model, "steps", None)
    info = {
        "model_path": str(Path(path).resolve()),
        "model_sha256": sha256(path),
        "model_type": f"{type(model).__module__}.{type(model).__name__}",
        "model_bytes": Path(path).stat().st_size,
        "required_features_exposed_by_model": list(
            map(str, getattr(model, "feature_names_in_", []))
        )
        or None,
        "cli_required_features": list(RAW_FEATURES),
        "supported_classes_exposed_by_model": list(
            map(str, getattr(model, "classes_", []))
        )
        or None,
        "pipeline_steps": [
            {"name": str(name), "type": type(step).__name__} for name, step in steps
        ]
        if isinstance(steps, list)
        else None,
        "probabilities_available": callable(getattr(model, "predict_proba", None)),
        "matching_baseline_metadata": None,
    }
    metadata_path = root / "reports/model_evaluation/bot_iot_validation_metrics.json"
    if metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text())
            if metadata.get("model_sha256") == info["model_sha256"]:
                info["matching_baseline_metadata"] = {
                    k: metadata[k]
                    for k in [
                        "preprocessing_version",
                        "source",
                        "source_sha256",
                        "sklearn",
                        "split_seed",
                        "theft_policy",
                    ]
                    if k in metadata
                }
        except (ValueError, OSError):
            pass
    return info


def load_network_detector(path, root):
    """Validate raw-input compatibility once, before serving any requests."""
    from cyberguard.inference.network_detector import NetworkDetector

    logger.info("model_loading")
    try:
        model = load_model(path)
        detector = NetworkDetector(model, inspect_model(model, path, root))
        # One small vectorized compatibility probe, not training or evaluation.
        detector.predict_batch(
            [
                {"proto": "tcp", "sport": "49152", "dport": "80"},
                {"proto": "icmp", "sport": "0x0303", "dport": "-1"},
            ]
        )
    except Exception as exc:
        logger.exception("model_loading_failed artifact=%s", path)
        raise RuntimeError(
            f"Unable to initialize network model at {path}: {exc}"
        ) from exc
    logger.info("model_loaded model=%s", detector.metadata()["model"])
    return detector
