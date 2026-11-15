"""Shared synthetic software fixtures; no raw datasets or model training."""

import joblib
import numpy as np
import pytest

from cyberguard.features.network import RAW_FEATURES


class SyntheticNetworkModel:
    feature_names_in_ = np.array(RAW_FEATURES)
    classes_ = np.array(["DDoS", "DoS", "Normal", "Reconnaissance"])

    def __init__(self):
        self.predict_calls = 0
        self.probability_calls = 0
        self.batch_lengths = []
        self.fail = False

    def fit(self, *args, **kwargs):
        raise AssertionError("Inference must not train/refit")

    def _labels(self, frame):
        assert list(frame.columns) == list(RAW_FEATURES)
        return np.array(
            [
                {"1": "Normal", "2": "DoS", "3": "DDoS", "4": "Reconnaissance"}.get(
                    str(value), "Normal"
                )
                for value in frame.sport
            ]
        )

    def predict(self, frame):
        self.predict_calls += 1
        self.batch_lengths.append(len(frame))
        if self.fail:
            raise ValueError("sensitive feature contents at /private/model.joblib")
        return self._labels(frame)

    def predict_proba(self, frame):
        self.probability_calls += 1
        return np.array(
            [
                [float(label == c) for c in self.classes_]
                for label in self._labels(frame)
            ]
        )


@pytest.fixture
def synthetic_model():
    return SyntheticNetworkModel()


@pytest.fixture
def api_model_path(tmp_path, synthetic_model):
    path = tmp_path / "fixture_network.joblib"
    joblib.dump(synthetic_model, path)
    return path
