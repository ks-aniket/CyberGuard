"""Synthetic fixtures test preparation integrity, never model generalization."""

import hashlib
import json
import sqlite3
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from pandas.testing import assert_frame_equal

from cyberguard.features import nf_cse as nf
from cyberguard.features import nf_cse_preparation as prep


def row(**updates):
    r = {
        "PROTOCOL": "6",
        "L4_SRC_PORT": "1234",
        "L4_DST_PORT": "80",
        "IN_BYTES": "100",
        "OUT_BYTES": "50",
        "IN_PKTS": "2",
        "OUT_PKTS": "1",
        "Label": "0",
        "Attack": "Benign",
        "IPV4_SRC_ADDR": "192.0.2.1",
        "IPV4_DST_ADDR": "192.0.2.2",
        "FLOW_DURATION_MILLISECONDS": "999",
        "TCP_FLAGS": "24",
        "L7_PROTO": "0.0",
    }
    r.update(updates)
    return r


def fixture(tmp_path, rows):
    root = tmp_path / "raw"
    data = root / "arbitrary-name" / "data"
    data.mkdir(parents=True)
    p = data / "NF-CSE-CIC-IDS2018.csv"
    pd.DataFrame(rows).to_csv(p, index=False)
    pd.DataFrame(
        [
            {"Feature": f["name"], "Description": f["description"]}
            for f in nf.feature_contract()["fields"]
        ]
    ).to_csv(data / "NetFlow_v1_Features.csv", index=False)
    return root, p


def supported_rows():
    return [
        row(IN_BYTES=str(i), Label=str(i % 2), Attack="Benign" if i % 2 == 0 else "Bot")
        for i in range(400)
    ]


def test_allowlist_order_stateless_transform_and_serialization(tmp_path):
    raw = pd.DataFrame([row(), row(PROTOCOL="udp", IN_BYTES="0")], index=[19, 8])
    before = nf.normalize(raw)
    shuffled = raw[list(reversed(raw.columns))].assign(
        Label="nonsense",
        Attack="leak",
        IPV4_SRC_ADDR="secret",
        FLOW_DURATION_MILLISECONDS="-1",
    )
    assert_frame_equal(before, nf.normalize(shuffled))
    assert tuple(before.columns) == nf.RAW_FEATURES
    assert list(before.index) == [19, 8]
    a = nf.NFCSECompletedFlowFeatures().fit(raw, [0, 1])
    b = nf.NFCSECompletedFlowFeatures().fit(raw.iloc[:1], [999])
    assert_frame_equal(a.transform(raw), b.transform(raw))
    assert list(a.transform(raw).columns) == list(nf.MODEL_FEATURES)
    assert a.transform(raw).isna().sum().sum() == 0
    path = tmp_path / "normalizer.joblib"
    joblib.dump(a, path)
    assert_frame_equal(a.transform(raw), joblib.load(path).transform(raw))
    with pytest.raises(ValueError, match="Missing completed-flow"):
        a.transform(raw[["PROTOCOL", "L4_SRC_PORT", "L4_DST_PORT"]])
    with pytest.raises(ValueError, match="Duplicate"):
        nf.normalize(pd.concat([raw, raw[["IN_BYTES"]]], axis=1))


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("6", 6),
        (" TCP ", 6),
        ("6.0", 6),
        ("6e0", 6),
        ("icmp", 1),
        ("icmpv6", 58),
        ("igmp", 2),
        ("47", 47),
        ("132", -3),
        (255, -3),
        (None, -1),
        ("NA", -1),
        ("256", -2),
        (True, -2),
        ("garbage", -2),
        ("6.5", -2),
    ],
)
def test_protocol(token, expected):
    assert nf.protocol_token(token) == expected


@pytest.mark.parametrize(
    ("token", "port", "expected"),
    [
        ("0", True, 0),
        ("65535", True, 65535),
        ("0x50", True, 80),
        ("080.0", True, 80),
        ("8e1", True, 80),
        ("-1", True, nf.SENTINEL),
        ("-", True, nf.SENTINEL),
        ("65536", True, nf.INVALID),
        ("1.5", True, nf.INVALID),
        ("inf", False, nf.INVALID),
        ("-1", False, nf.INVALID),
        ("", False, nf.MISSING),
        (None, False, nf.MISSING),
        (np.nan, False, nf.MISSING),
        (True, False, nf.INVALID),
        ("9007199254740991", False, nf.MAX_COUNTER),
        ("9007199254740992", False, nf.INVALID),
        pytest.param(10**5000, False, nf.INVALID, id="bounded-huge-integer"),
        ("١", False, nf.INVALID),
    ],
)
def test_exact_numeric_rules(token, port, expected):
    assert (
        nf.integer_token(token, 65535 if port else nf.MAX_COUNTER, port=port)
        == expected
    )


def test_zero_missing_invalid_nontransport_and_encoding_are_distinct():
    raw = pd.DataFrame(
        [row(IN_BYTES=v, L4_SRC_PORT=v) for v in [0, None, "garbage", True, 1]],
        dtype=object,
    )
    canonical = nf.normalize(raw)
    assert canonical.IN_BYTES.tolist() == [0, -1, -2, -2, 1]
    assert canonical.L4_SRC_PORT.tolist() == [0, -1, -2, -2, 1]
    encoded = nf.model_features(canonical)
    assert encoded.IN_BYTES_status.tolist() == [0, 1, 2, 2, 0]
    assert len(nf.canonical_keys(canonical)) == len(encoded)
    assert len(encoded.drop_duplicates()) == len(canonical.drop_duplicates())
    nontransport = nf.normalize(
        pd.DataFrame(
            [
                row(PROTOCOL="icmp", L4_SRC_PORT="0x8"),
                row(PROTOCOL="132", L4_SRC_PORT="123"),
            ]
        )
    )
    assert nontransport.L4_SRC_PORT.tolist() == [nf.NOT_APPLICABLE, nf.UNKNOWN_PROTOCOL]
    aliases = nf.normalize(
        pd.DataFrame(
            [
                row(PROTOCOL="TCP", L4_SRC_PORT="0x50"),
                row(PROTOCOL="6.0", L4_SRC_PORT="80.0"),
            ]
        )
    )
    assert len(set(nf.canonical_keys(aliases))) == 1


def test_labels_preserve_attack_metadata_and_reject_disagreement():
    assert nf.validate_labels(["0", 1], ["Benign", "Bot"]).tolist() == [0, 1]
    for labels, attacks in [
        (["0"], ["Bot"]),
        (["1"], ["Benign"]),
        (["2"], ["Bot"]),
        ([True], ["Bot"]),
        (["1"], [" Bot "]),
    ]:
        with pytest.raises(ValueError):
            nf.validate_labels(labels, attacks)


def test_ambiguity_and_counts_before_blocked_publication(tmp_path):
    rows = [
        row(),
        row(),
        row(Label="1", Attack="Bot"),
        row(Label="1", Attack="Other"),
        row(IN_BYTES="200"),
    ]
    root, source = fixture(tmp_path, rows)
    before = source.read_bytes()
    result = prep.prepare(root, tmp_path / "processed", chunk_size=2)
    a = result["plan"]["ambiguity"]
    assert result["status"] == "blocked" and not (tmp_path / "processed").exists()
    assert a["normalized_groups"] == 2 and a["groups_multiple_Attack_labels"] == 1
    assert a["binary_conflicting_groups"] == 1 and a["rows_in_binary_conflicts"] == 4
    assert (
        a["benign_rows_in_binary_conflicts"] == 2
        and a["attack_rows_in_binary_conflicts"] == 2
    )
    assert a["binary_majority_label_accuracy_ceiling"] == 0.6
    assert (
        a["compact_records"] == 4
        and a["projected_feature_label_metadata_duplicate_excess"] == 1
    )
    assert source.read_bytes() == before
    assert result["identity"]["source_sha256"] == hashlib.sha256(before).hexdigest()


def test_group_assignment_invariant_to_chunks_labels_and_order(tmp_path):
    _root, source = fixture(
        tmp_path,
        [
            *supported_rows(),
            row(IN_BYTES="1", Label="0", Attack="Benign"),
            row(IN_BYTES="1", Label="1", Attack="Other"),
        ],
    )
    outputs = []
    for size in [17, 63]:
        with sqlite3.connect(":memory:") as db:
            prep.build_index(source, db, chunk_size=size, seed=20261115)
            outputs.append(prep.summarize(db))
            assert (
                db.execute(
                    "SELECT max(n) FROM (SELECT count(DISTINCT p) n FROM examples GROUP BY k)"
                ).fetchone()[0]
                == 1
            )
    assert outputs[0] == outputs[1]
    assert outputs[0]["can_materialize"]
    key = nf.canonical_keys(nf.normalize(pd.DataFrame([row()])))[0]
    assert prep.partition_for_key(key) == prep.partition_for_key(key)
    assert outputs[0]["ambiguity"]["binary_conflicting_groups"] == 1


def test_dry_run_no_processed_writes_and_raw_read_scope(tmp_path, monkeypatch):
    root, source = fixture(tmp_path, supported_rows())
    original = pd.read_csv

    def guarded(path, *args, **kwargs):
        assert Path(path).resolve() == source.resolve(), "Unexpected dataset access"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(pd, "read_csv", guarded)
    result = prep.prepare(root, tmp_path / "not-created", chunk_size=71, dry_run=True)
    assert result["status"] == "dry_run"
    assert result["plan"]["can_materialize"]
    assert not (tmp_path / "not-created").exists()
    with pytest.raises(ValueError, match="outside raw"):
        prep.prepare(root, root / "processed")


def test_materialization_conservation_sealing_reruns_and_no_training(tmp_path):
    rows = [
        *supported_rows(),
        row(IN_BYTES="1", Label="0", Attack="Benign"),
        row(IN_BYTES="1", Label="1", Attack="Other"),
    ]
    root, source = fixture(tmp_path, rows)
    original = source.read_bytes()
    output = tmp_path / "processed"
    result = prep.prepare(root, output, chunk_size=47)
    assert result["status"] == "complete"
    assert result["plan"]["ambiguity"]["groups_crossing_partitions"] == 0
    observed = {}
    total = 0
    binary = Counter({0: 0, 1: 0})
    for partition in prep.PARTITIONS:
        for shard in prep.iter_partition(output, partition):
            assert shard["features"].dtype == np.int64
            assert shard["Label"].dtype == np.uint8
            assert shard["multiplicity"].dtype == np.uint64
            normalized = pd.DataFrame(shard["features"], columns=nf.RAW_FEATURES)
            assert nf.model_features(normalized).shape == (len(normalized), 13)
            for key, label, count in zip(
                nf.canonical_keys(normalized),
                shard["Label"],
                shard["multiplicity"],
                strict=True,
            ):
                assert observed.setdefault(key, partition) == partition
                total += int(count)
                binary[int(label)] += int(count)
    assert total == len(rows) and binary == {0: 201, 1: 201}
    assert source.read_bytes() == original
    assert (
        json.loads((output / "metadata/preprocessing_manifest.json").read_text())[
            "learned_parameters"
        ]
        is None
    )
    assert json.loads((output / "metadata/feature_contract.json").read_text())[
        "raw_feature_order"
    ] == list(nf.RAW_FEATURES)
    first = {p: p.read_bytes() for p in output.rglob("*") if p.is_file()}
    again = prep.prepare(root, output, chunk_size=53)
    assert again["identity"] == result["identity"]
    assert first == {p: p.read_bytes() for p in first}
    with pytest.raises(ValueError, match="incompatible"):
        prep.prepare(root, output, seed=9)
    artifact = next((output / "test").glob("*.npz"))
    artifact.write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="missing/changed"):
        prep.prepare(root, output)
    with pytest.raises(ValueError, match="checksum"):
        list(prep.iter_partition(output, "test"))


def test_input_row_order_does_not_change_shard_payloads(tmp_path):
    rows = supported_rows()
    root, source = fixture(tmp_path, rows)
    a = prep.prepare(root, tmp_path / "a", chunk_size=75)
    pd.DataFrame(rows[::-1]).to_csv(source, index=False)
    b = prep.prepare(root, tmp_path / "b", chunk_size=75)
    assert a["plan"] == b["plan"]
    for name, item in a["artifacts"].items():
        if name.endswith(".npz"):
            assert item["sha256"] == b["artifacts"][name]["sha256"]


def test_staging_failure_is_atomic_and_keeps_raw_data(tmp_path, monkeypatch):
    root, source = fixture(tmp_path, supported_rows())
    original = source.read_bytes()

    def fail(*args, **kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(np, "savez_compressed", fail)
    with pytest.raises(OSError, match="disk failure"):
        prep.prepare(root, tmp_path / "processed")
    assert not (tmp_path / "processed").exists()
    assert not list(tmp_path.glob(".processed-staging-*"))
    assert source.read_bytes() == original


def test_partition_reader_does_not_open_other_partition_shards(tmp_path, monkeypatch):
    root, _source = fixture(tmp_path, supported_rows())
    output = tmp_path / "processed"
    prep.prepare(root, output)
    original = np.load

    def restricted(path, *args, **kwargs):
        assert Path(path).parent.name == "train"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(np, "load", restricted)
    assert sum(len(x["Label"]) for x in prep.iter_partition(output, "train")) > 0


def test_nullable_string_inputs_and_precision_preservation():
    raw = pd.DataFrame(
        [
            row(IN_BYTES=str(nf.MAX_COUNTER)),
            row(IN_BYTES=str(nf.MAX_COUNTER - 1)),
            row(IN_BYTES=pd.NA),
        ],
        dtype="string",
    )
    canonical = nf.normalize(raw)
    assert canonical.IN_BYTES.tolist() == [
        nf.MAX_COUNTER,
        nf.MAX_COUNTER - 1,
        nf.MISSING,
    ]
    encoded = nf.model_features(canonical)
    assert encoded.IN_BYTES.tolist() == [nf.MAX_COUNTER, nf.MAX_COUNTER - 1, 0]
    assert encoded.IN_BYTES_status.tolist() == [0, 0, 1]
