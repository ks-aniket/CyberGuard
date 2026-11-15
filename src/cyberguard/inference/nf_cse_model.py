"""Standalone NF-CSE artifact; deliberately not registered in the BoT-only API."""

from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from cyberguard.features import nf_cse as nf

NUMERIC_INDICES = [1, 2, 3, 4, 5, 6]
CATEGORICAL_INDICES = [0, 7, 8, 9, 10, 11, 12]


class NFLinearTransform(TransformerMixin, BaseEstimator):
    """Fixed logs/categories, then multiplicity-weighted train-only numeric scaling."""

    def _numeric(self, X):
        out = np.asarray(X, dtype=np.float64)[:, NUMERIC_INDICES].copy()
        out[:, :2] /= 65535.0
        out[:, 2:] = np.log1p(out[:, 2:])
        return out

    def fit(self, X, y=None, sample_weight=None):
        self.scaler_ = StandardScaler().fit(
            self._numeric(X), sample_weight=sample_weight
        )
        categories = [
            np.arange(10),
            np.arange(6),
            np.arange(6),
            np.arange(3),
            np.arange(3),
            np.arange(3),
            np.arange(3),
        ]
        self.encoder_ = OneHotEncoder(
            categories=categories,
            handle_unknown="error",
            sparse_output=True,
            dtype=np.float64,
        )
        self.encoder_.fit(np.asarray(X)[:, CATEGORICAL_INDICES])
        return self

    def transform(self, X):
        numeric = self.scaler_.transform(self._numeric(X))
        categories = self.encoder_.transform(np.asarray(X)[:, CATEGORICAL_INDICES])
        return sparse.hstack([sparse.csr_matrix(numeric), categories], format="csr")


class NFCSEBinaryModel:
    """Saved inference adapter with its selected validation operating threshold."""

    def __init__(
        self, estimator, linear_transform=None, *, threshold=0.5, metadata=None
    ):
        self.estimator = estimator
        self.linear_transform = linear_transform
        self.threshold = float(threshold)
        self.metadata_ = metadata or {}
        self.normalizer = nf.NFCSECompletedFlowFeatures().fit(
            pd.DataFrame(columns=nf.RAW_FEATURES)
        )
        self.feature_names_in_ = np.array(nf.RAW_FEATURES, dtype=object)
        self.classes_ = np.array([0, 1], dtype=np.uint8)

    def score_encoded(self, X):
        values = (
            self.linear_transform.transform(X)
            if self.linear_transform is not None
            else X
        )
        probabilities = self.estimator.predict_proba(values)
        classes = np.asarray(self.estimator.classes_)
        if set(classes) != {0, 1} or probabilities.shape != (len(X), 2):
            raise ValueError("Expected aligned binary class probabilities")
        scores = np.asarray(
            probabilities[:, int(np.flatnonzero(classes == 1)[0])], dtype=float
        )
        if not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
            raise ValueError("Invalid prediction scores")
        return scores

    def predict_proba(self, raw):
        encoded = self.normalizer.transform(raw).to_numpy(dtype=np.float64)
        attack = self.score_encoded(encoded)
        return np.column_stack([1 - attack, attack])

    def predict(self, raw):
        return (self.predict_proba(raw)[:, 1] >= self.threshold).astype(np.uint8)

    def predict_labels(self, raw):
        return np.where(self.predict(raw) == 0, "Benign", "Attack")
