"""Synthetic fixtures test contracts; they are not evidence of generalization."""

import joblib
import numpy as np
import pandas as pd
import pytest

from cyberguard.features.network import (
    RAW_FEATURES,
    RestrictedNetworkFeatures,
    canonical_keys,
    normalize_port,
    normalize_protocol,
    raw_from_key,
    validate_targets,
)
from cyberguard.features.preprocessing import make_network_pipeline
from cyberguard.training.sampling import validation_group


@pytest.mark.parametrize(
    "value,expected",
    [
        (" TCP ", "tcp"),
        (6, "tcp"),
        ("17", "udp"),
        ("ICMPv6", "ipv6-icmp"),
        (None, "missing"),
        (np.nan, "missing"),
        ("SCTP", "other"),
    ],
)
def test_protocol_aliases(value, expected):
    assert normalize_protocol(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("080", (80, "valid", "well_known")),
        ("0x0050", (80, "valid", "well_known")),
        (80.0, (80, "valid", "well_known")),
        ("0", (0, "valid", "well_known")),
        ("65535", (65535, "valid", "dynamic")),
        ("1024", (1024, "valid", "registered")),
        ("65536", (0, "invalid", "none")),
        ("-2", (0, "invalid", "none")),
        ("80.1", (0, "invalid", "none")),
        (np.inf, (0, "invalid", "none")),
        ("0xgg", (0, "invalid", "none")),
        (None, (0, "missing", "none")),
        (pd.NA, (0, "missing", "none")),
        ("-1", (0, "sentinel", "none")),
        ("-", (0, "sentinel", "none")),
    ],
)
def test_port_normalization(value, expected):
    assert normalize_port("tcp", value) == expected


@pytest.mark.parametrize("protocol", ["icmp", "ipv6-icmp", "arp", "other", "missing"])
def test_nontransport_port_tokens_are_not_ports(protocol):
    assert normalize_port(protocol, "0x0303") == (0, "not_applicable", "none")
    assert normalize_port(protocol, "-1") == (0, "not_applicable", "none")


def test_excluded_features_cannot_change_transformed_output():
    raw = pd.DataFrame(
        {"proto": ["tcp", "udp"], "sport": ["80", "0080"], "dport": ["0x50", "53"]}
    )
    leaked = raw.assign(
        saddr="secret",
        daddr="secret",
        pkSeqID=999,
        seq=1,
        category="Normal",
        attack=0,
        subcategory="Normal",
        srate=1e12,
        state_number=4,
        N_IN_Conn_P_SrcIP=100,
        mean=999,
    )
    normalizer = RestrictedNetworkFeatures().fit(raw)
    pd.testing.assert_frame_equal(
        normalizer.transform(raw), normalizer.transform(leaked)
    )
    assert not any(
        "addr" in f or "category" in f for f in normalizer.get_feature_names_out()
    )


def test_targets_explicitly_exclude_theft_and_reject_unknown_labels():
    labels, mask = validate_targets(
        ["Normal", "Theft", "DDoS", "DoS", "Reconnaissance"]
    )
    assert labels.iloc[1] == "Theft"
    assert mask.tolist() == [True, False, True, True, True]
    with pytest.raises(ValueError, match="Unrecognized"):
        validate_targets(["Normal", "OtherAttack"])


def test_schema_and_canonical_identity():
    frame = pd.DataFrame(
        {
            "proto": [" TCP ", "6", "icmp", "arp", "", "tcp"],
            "sport": ["080", "0x50", "0x0303", "-1", "-1", "bad"],
            "dport": ["53", "053", "0x0000", "-1", "-1", "-"],
        }
    )
    transformer = RestrictedNetworkFeatures().fit(frame)
    normalized = transformer.transform(frame)
    keys = canonical_keys(normalized)
    assert keys[0] == keys[1]
    reconstructed = pd.DataFrame([raw_from_key(k) for k in keys])
    assert keys == canonical_keys(transformer.transform(reconstructed))
    assert validation_group(keys[0]) == validation_group(keys[1])
    with pytest.raises(ValueError, match="Missing required"):
        transformer.transform(frame.drop(columns="sport"))


def test_train_only_encoder_and_model_round_trip(tmp_path):
    train = pd.DataFrame(
        {
            "proto": ["tcp"] * 10 + ["udp"] * 10,
            "sport": range(20),
            "dport": [80] * 10 + [53] * 10,
        }
    )
    labels = ["Normal"] * 10 + ["DoS"] * 10
    pipeline = make_network_pipeline()
    pipeline.fit(train, labels)
    validation = pd.DataFrame(
        {"proto": ["ipv6-icmp"], "sport": ["0x0303"], "dport": ["-1"]}
    )
    assert pipeline.predict(validation).shape == (1,)
    assert (
        "ipv6-icmp"
        not in pipeline.named_steps["encode"]
        .named_transformers_["categories"]
        .categories_[0]
    )
    assert pipeline.feature_names_in_.tolist() == list(RAW_FEATURES)
    path = tmp_path / "network.joblib"
    joblib.dump(pipeline, path)
    assert np.array_equal(pipeline.predict(train), joblib.load(path).predict(train))
