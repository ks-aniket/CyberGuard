"""Restricted BoT-IoT header representation, version 1.

No address, identifier, flow summary or target column is ever inspected here.
The output describes offline records; this module does not capture live packets.
"""

from __future__ import annotations

import math
import re
from functools import lru_cache
from numbers import Integral, Real

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.utils.validation import check_is_fitted

RAW_FEATURES = ("proto", "sport", "dport")
CATEGORICAL_FEATURES = (
    "protocol",
    "sport_status",
    "dport_status",
    "sport_range",
    "dport_range",
)
NUMERIC_FEATURES = ("sport_value", "dport_value")
NORMALIZED_FEATURES = CATEGORICAL_FEATURES + NUMERIC_FEATURES
TARGETS = ("Normal", "DoS", "DDoS", "Reconnaissance")
UNSUPPORTED_TARGETS = ("Theft",)
VERSION = "bot-iot-header-v1"
PROTOCOLS = {
    "tcp": "tcp",
    "6": "tcp",
    "udp": "udp",
    "17": "udp",
    "icmp": "icmp",
    "1": "icmp",
    "icmpv4": "icmp",
    "ipv6-icmp": "ipv6-icmp",
    "icmpv6": "ipv6-icmp",
    "58": "ipv6-icmp",
    "arp": "arp",
}
MISSING_TOKENS = frozenset(("", "nan", "na", "n/a", "none", "null", "<na>"))


def token(value) -> str:
    """Canonicalize a scalar token without accepting nonintegral port numbers."""
    if value is None or value is pd.NA:
        return ""
    if isinstance(value, Real):
        if not math.isfinite(value):
            return "nan" if math.isnan(value) else str(value).lower()
        if isinstance(value, Integral) or float(value).is_integer():
            return str(int(value))
    return str(value).strip().lower()


def normalize_protocol(value) -> str:
    value = token(value)
    if value in MISSING_TOKENS:
        return "missing"
    return PROTOCOLS.get(value, "other")


@lru_cache(maxsize=70000)
def _parse_port(value: str) -> tuple[int, str, str]:
    if value in MISSING_TOKENS:
        return 0, "missing", "none"
    if value in ("-", "-1"):
        return 0, "sentinel", "none"
    if not re.fullmatch(r"(?:[0-9]+|0x[0-9a-f]+)", value):
        return 0, "invalid", "none"
    port = int(value, 16 if value.startswith("0x") else 10)
    if port > 65535:
        return 0, "invalid", "none"
    band = (
        "well_known" if port <= 1023 else "registered" if port <= 49151 else "dynamic"
    )
    return port, "valid", band


def normalize_port(protocol: str, value) -> tuple[int, str, str]:
    """ICMP type/code, ARP sentinels and unknown transports are never real ports."""
    if protocol not in ("tcp", "udp"):
        return 0, "not_applicable", "none"
    return _parse_port(token(value))


def validate_targets(values) -> tuple[pd.Series, np.ndarray]:
    """Return labels and eligibility. Theft stays unsupported; new labels fail."""
    labels = pd.Series(values, copy=False).astype("str").str.strip()
    unknown = set(labels.unique()) - set(TARGETS) - set(UNSUPPORTED_TARGETS)
    if unknown:
        raise ValueError(f"Unrecognized network target labels: {sorted(unknown)}")
    return labels, labels.isin(TARGETS).to_numpy()


class RestrictedNetworkFeatures(TransformerMixin, BaseEstimator):
    """Allowlist-only deterministic normalizer shared by fitting and prediction."""

    def _transform(self, X):
        if not isinstance(X, pd.DataFrame):
            raise TypeError("Expected a pandas DataFrame with proto, sport, dport")
        missing = set(RAW_FEATURES) - set(X.columns)
        if missing:
            raise ValueError(f"Missing required input columns: {sorted(missing)}")
        if not X.columns.is_unique:
            raise ValueError("Duplicate column names are not allowed")
        protocols = [normalize_protocol(v) for v in X["proto"]]
        result = pd.DataFrame({"protocol": protocols}, index=X.index)
        for field in ("sport", "dport"):
            parsed = [
                normalize_port(p, value)
                for p, value in zip(protocols, X[field], strict=True)
            ]
            result[field + "_value"] = (
                np.array([v[0] for v in parsed], dtype=np.float64) / 65535
            )
            result[field + "_status"] = [v[1] for v in parsed]
            result[field + "_range"] = [v[2] for v in parsed]
        return result.loc[:, NORMALIZED_FEATURES]

    def fit(self, X, y=None):
        self._transform(X)
        self.n_features_in_ = len(RAW_FEATURES)
        self.feature_names_in_ = np.array(RAW_FEATURES, dtype=object)
        return self

    def transform(self, X):
        check_is_fitted(self, "n_features_in_")
        return self._transform(X)

    def get_feature_names_out(self, input_features=None):
        check_is_fitted(self, "n_features_in_")
        return np.array(NORMALIZED_FEATURES, dtype=object)


def canonical_keys(normalized: pd.DataFrame) -> list[str]:
    """Unambiguous model-input identities, with ports restored to exact integers."""
    keys = []
    for row in normalized.loc[:, NORMALIZED_FEATURES].itertuples(
        index=False, name=None
    ):
        # Category values are fixed internal tokens without separators.
        keys.append(
            "|".join(map(str, row[:5]))
            + f"|{round(row[5] * 65535)}|{round(row[6] * 65535)}"
        )
    return keys


def raw_from_key(key: str) -> dict[str, str]:
    """Reconstruct a canonical raw triple for a compact weighted audit record."""
    protocol, ss, ds, _sr, _dr, sport, dport = key.split("|")
    invalid = {
        "missing": "",
        "sentinel": "-1",
        "invalid": "invalid",
        "not_applicable": "-1",
    }
    return {
        "proto": "" if protocol == "missing" else protocol,
        "sport": sport if ss == "valid" else invalid[ss],
        "dport": dport if ds == "valid" else invalid[ds],
    }
