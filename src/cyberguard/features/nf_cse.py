"""Versioned, stateless completed-flow NF-CSE normalization (not BoT-IoT).

Seven canonical integer fields identify exactly the information given to future
models. Fixed value/status encoding is injective on canonical vectors. No scaler,
encoder vocabulary, imputer statistic or target-derived parameter is learned.
"""

from __future__ import annotations

import json
import math
import numbers
import re
from decimal import Decimal, InvalidOperation

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

CONTRACT_VERSION = "nf-cse-netflow-v1-completed-flow-v1"
PREPROCESSING_VERSION = "nf-cse-normalization-v1"
RAW_FEATURES = (
    "PROTOCOL",
    "L4_SRC_PORT",
    "L4_DST_PORT",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
)
PORTS = RAW_FEATURES[1:3]
COUNTERS = RAW_FEATURES[3:]
MAX_COUNTER = (
    2**53 - 1
)  # every retained integer must also survive future float64 exactly
MISSING, INVALID, NOT_APPLICABLE, SENTINEL, UNKNOWN_PROTOCOL = -1, -2, -3, -4, -5
# Fixed scope, not categories discovered from data. Other valid byte codes coalesce.
PROTOCOL_BYTES = (0, 1, 2, 6, 17, 47, 58)
PROTOCOL_CODES = (*PROTOCOL_BYTES, -3, MISSING, INVALID)
ALIASES = {
    "hopopt": 0,
    "icmp": 1,
    "icmpv4": 1,
    "igmp": 2,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "ipv6-icmp": 58,
    "icmpv6": 58,
}
NA_TOKENS = {"", "na", "n/a", "nan", "null", "none"}
STATUS_CODES = {
    0: "valid",
    MISSING: "missing",
    INVALID: "invalid",
    NOT_APPLICABLE: "not_applicable",
    SENTINEL: "sentinel",
    UNKNOWN_PROTOCOL: "unknown_protocol",
}
MODEL_FEATURES = (*RAW_FEATURES, *(c + "_status" for c in RAW_FEATURES[1:]))


def integer_token(value, maximum, *, port=False):
    """Bounded exact integer parsing; never round fractions, overflow or accept bool."""
    if value is None or value is pd.NA:
        return MISSING
    if isinstance(value, (bool, np.bool_)):
        return INVALID
    if isinstance(value, numbers.Integral):
        if port and value == -1:
            return SENTINEL
        return int(value) if 0 <= value <= maximum else INVALID
    if isinstance(value, numbers.Real) and not isinstance(value, numbers.Integral):
        if math.isnan(value):
            return MISSING
        if not math.isfinite(value):
            return INVALID
    token = str(value).strip().lower()
    if not token.isascii():
        return INVALID
    if token in NA_TOKENS:
        return MISSING
    if port and token == "-":
        return SENTINEL
    try:
        if re.fullmatch(r"[+-]?\d+", token, flags=re.ASCII):
            # Bound digit work before Python's potentially large integer conversion.
            digits = token.lstrip("+-").lstrip("0") or "0"
            if len(digits) > len(str(maximum)):
                return INVALID
            number = (
                int(token)
                if len(token) < 1000
                else int(("-" if token.startswith("-") else "") + digits)
            )
        elif port and re.fullmatch(r"0x[0-9a-f]+", token, flags=re.ASCII):
            digits = token[2:].lstrip("0") or "0"
            if len(digits) > 4:
                return INVALID
            number = int(digits, 16)
        else:
            if len(token) > 128:
                return INVALID
            decimal = Decimal(token)
            if (
                not decimal.is_finite()
                or decimal < -1
                or decimal > maximum
                or decimal != decimal.to_integral_value()
            ):
                return INVALID
            number = int(decimal)
    except (ValueError, InvalidOperation, OverflowError):
        return INVALID
    if port and number == -1:
        return SENTINEL
    return number if 0 <= number <= maximum else INVALID


def protocol_token(value):
    if isinstance(value, str) and value.strip().lower() in ALIASES:
        return ALIASES[value.strip().lower()]
    code = integer_token(value, 255)
    return code if code in (*PROTOCOL_BYTES, MISSING, INVALID) else -3


def validate_frame(frame):
    if not isinstance(frame, pd.DataFrame):
        raise TypeError("NF-CSE input must be a pandas DataFrame")
    if not frame.columns.is_unique:
        raise ValueError("Duplicate input column names")
    missing = set(RAW_FEATURES) - set(frame.columns)
    if missing:
        raise ValueError(f"Missing completed-flow fields: {sorted(missing)}")


def mapped(series, parser):
    # Each distinct token is parsed only once per bounded chunk. String dtype
    # keeps CSV tokens intact; scalar APIs retain bool/null distinctions.
    return (
        series.map(parser).astype("int64")
        if not len(series) or series.dtype == object
        else series.map({v: parser(v) for v in series.drop_duplicates()}).astype(
            "int64"
        )
    )


def normalize(frame):
    """Return seven canonical int64 fields; exclude every non-allowlisted field."""
    validate_frame(frame)
    out = pd.DataFrame(index=frame.index)
    out["PROTOCOL"] = mapped(frame.PROTOCOL, protocol_token)
    transport = out.PROTOCOL.isin([6, 17])
    unknown = out.PROTOCOL.isin([-3, MISSING, INVALID])
    for c in PORTS:
        values = mapped(frame[c], lambda v: integer_token(v, 65535, port=True))
        out[c] = values.where(
            transport, np.where(unknown, UNKNOWN_PROTOCOL, NOT_APPLICABLE)
        ).astype("int64")
    for c in COUNTERS:
        out[c] = mapped(frame[c], lambda v: integer_token(v, MAX_COUNTER))
    return out.loc[:, RAW_FEATURES]


def model_features(canonical):
    """Fixed zero fill + categorical statuses; zeros remain distinct from missing."""
    if tuple(canonical.columns) != RAW_FEATURES:
        raise ValueError("Expected seven canonical fields in contract order")
    out = canonical.copy()
    out["PROTOCOL"] = canonical.PROTOCOL.map(
        dict(zip(PROTOCOL_CODES, range(len(PROTOCOL_CODES)), strict=True))
    )
    if out.PROTOCOL.isna().any():
        raise ValueError("Unknown canonical protocol code")
    for c in RAW_FEATURES[1:]:
        status = canonical[c].where(canonical[c] < 0, 0)
        allowed = [0, MISSING, INVALID] if c in COUNTERS else list(STATUS_CODES)
        if not status.isin(allowed).all():
            raise ValueError(f"Unknown canonical status: {c}")
        out[c] = canonical[c].clip(lower=0)
        out[c + "_status"] = status.map(
            {
                0: 0,
                MISSING: 1,
                INVALID: 2,
                NOT_APPLICABLE: 3,
                SENTINEL: 4,
                UNKNOWN_PROTOCOL: 5,
            }
        )
    return out.loc[:, MODEL_FEATURES].astype("int64")


def canonical_keys(canonical):
    if tuple(canonical.columns) != RAW_FEATURES:
        raise ValueError("Canonical group columns/order do not match contract")
    return [
        json.dumps(tuple(map(int, row)), separators=(",", ":"))
        for row in canonical.itertuples(index=False, name=None)
    ]


def validate_labels(binary, attack):
    labels = []
    for b, a in zip(binary, attack, strict=True):
        if isinstance(b, (bool, np.bool_)) or str(b).strip() not in {"0", "1"}:
            raise ValueError(f"Invalid binary Label: {b!r}; expected 0 or 1")
        code = int(str(b).strip())
        if not isinstance(a, str) or not a or a != a.strip():
            raise ValueError(f"Invalid Attack metadata: {a!r}")
        if (a == "Benign") != (code == 0):
            raise ValueError(f"Binary/multiclass disagreement: {b!r}, {a!r}")
        labels.append(code)
    return np.asarray(labels, dtype=np.uint8)


def feature_contract():
    descriptions = {
        "PROTOCOL": (
            "IP protocol identifier byte",
            "IP-header byte code; categorical, not ordinal",
            0,
            255,
        ),
        "L4_SRC_PORT": ("IPv4 source port number", "TCP/UDP port identifier", 0, 65535),
        "L4_DST_PORT": (
            "IPv4 destination port number",
            "TCP/UDP port identifier",
            0,
            65535,
        ),
        "IN_BYTES": (
            "Incoming number of bytes",
            "bytes as counted by supplied exporter",
            0,
            MAX_COUNTER,
        ),
        "OUT_BYTES": (
            "Outgoing number of bytes",
            "bytes as counted by supplied exporter",
            0,
            MAX_COUNTER,
        ),
        "IN_PKTS": (
            "Incoming number of packets",
            "packets as counted by supplied exporter",
            0,
            MAX_COUNTER,
        ),
        "OUT_PKTS": (
            "Outgoing number of packets",
            "packets as counted by supplied exporter",
            0,
            MAX_COUNTER,
        ),
    }
    return {
        "schema_version": CONTRACT_VERSION,
        "preprocessing_version": PREPROCESSING_VERSION,
        "model_id": "nf_cse_binary_completed_flow",
        "task": "binary",
        "label_mapping": {"0": "Benign", "1": "Attack"},
        "observation_contract": "Finalized bidirectional NetFlow-v1 export records only; not first-packet, partial-flow or live detection.",
        "orientation_limit": "Dictionary says incoming/outgoing. Treat IN as exporter-relative forward and OUT as reverse only within this dataset; initiator/byte accounting/timeout parity with another exporter is unverified.",
        "raw_feature_order": list(RAW_FEATURES),
        "fields": [
            {
                "name": c,
                "type": "integer-valued numeric scalar or numeric/alias text; explicit null allowed",
                "description": descriptions[c][0],
                "units": descriptions[c][1],
                "minimum": descriptions[c][2],
                "maximum": descriptions[c][3],
            }
            for c in RAW_FEATURES
        ],
        "canonical_dtype": "int64",
        "canonical_status_codes": STATUS_CODES,
        "protocol_known_byte_categories": list(PROTOCOL_BYTES),
        "protocol_other": -3,
        "protocol_aliases": ALIASES,
        "protocol_model_category_order": list(PROTOCOL_CODES),
        "protocol_policy": "Known fixed bytes retained; other valid bytes -> other(-3). Missing(-1), invalid(-2). Ports are applicable only to TCP/UDP; known nontransport -> -3; unknown/missing/invalid protocol -> -5.",
        "numeric_policy": "Trim; accept exact integral decimal/exponent forms and numeric scalars. Ports also accept 0x hex. Reject bool, fractional, infinity, negative, out-of-range and >2^53-1 counters. No rounding/clamping. -/-1 ports are explicit sentinels.",
        "missing_policy": "Null, scalar NaN or empty/NA-like text -> -1; malformed/infinite/out-of-range -> -2. No row dropping. Non-applicable port fields do not retain arbitrary raw contents.",
        "model_feature_order": list(MODEL_FEATURES),
        "model_encoding": "Fixed protocol category index; unavailable numeric values filled 0 plus per-field categorical status (0 valid,1 missing,2 invalid,3 not_applicable,4 sentinel,5 unknown_protocol). This is injective on canonical vectors.",
        "categorical_model_fields": [
            "PROTOCOL",
            *(c + "_status" for c in RAW_FEATURES[1:]),
        ],
        "learned_parameters": None,
        "scaling": None,
        "excluded": "All inputs outside the seven-field allowlist, including IPs, duration, L7_PROTO, TCP_FLAGS, Label, Attack and identifiers.",
        "required_context": "All seven field names must be present. Values can be null; a header-only request is rejected. Input indexes/order preserved. Future service must enforce finalized bidirectional observation provenance, not merely field presence.",
    }


class NFCSECompletedFlowFeatures(TransformerMixin, BaseEstimator):
    """Reusable sklearn transform for future saved pipelines; no estimator fitted."""

    def fit(self, X, y=None):
        validate_frame(X)
        self.feature_names_in_ = np.array(RAW_FEATURES, dtype=object)
        self.n_features_in_ = len(RAW_FEATURES)
        return self

    def transform(self, X):
        return model_features(normalize(X))

    def get_feature_names_out(self, input_features=None):
        return np.array(MODEL_FEATURES, dtype=object)
