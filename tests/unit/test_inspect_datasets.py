"""Small synthetic fixtures validate the EDA without reading the raw datasets."""

import importlib.util
import sqlite3
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "inspect_datasets.py"
SPEC = importlib.util.spec_from_file_location("inspect_datasets", SCRIPT)
eda = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(eda)


def test_chunked_moments_ignore_nonfinite_and_match_population():
    values = np.array([0.0, 1.0, 2.0, 3.0, 50.0, np.nan, np.inf])
    moments = eda.Moments()
    moments.add(values[:3])
    moments.add(values[3:])
    finite = values[np.isfinite(values)]
    result = moments.result()
    assert result["finite"] == len(finite)
    assert result["mean"] == pytest.approx(finite.mean())
    assert result["std"] == pytest.approx(finite.std(ddof=1))
    expected_skew = np.mean((finite - finite.mean()) ** 3) / finite.std() ** 3
    assert result["skew_population"] == pytest.approx(expected_skew)


def test_duplicate_and_conflict_audit_preserves_label_tuples(tmp_path, monkeypatch):
    monkeypatch.setattr(eda, "ROOT", tmp_path)
    fixture = tmp_path / "dns.csv"
    pd.DataFrame(
        {
            "domain": ["abc", "abc", "xyz", "abc"],
            "class": ["0", "0", "1", "1"],
        }
    ).to_csv(fixture, index=False)
    with sqlite3.connect(":memory:") as db:
        for view in ["raw", "operational"]:
            db.execute(
                f"CREATE TABLE {view}(s TEXT,x BLOB,y TEXT,n INTEGER,PRIMARY KEY(s,x,y)) WITHOUT ROWID"
            )
        train = eda.scan("dns_threats", "train", fixture, db, 2, 2)
        eda.scan("dns_threats", "test", fixture, db, 3, 2)
        audit = eda.audit(db, "raw")
    assert train["rows"] == 4
    assert train["sample_rows"] == 2
    assert audit["train_duplicate_excess"] == 1
    assert audit["train_conflicting_vectors"] == 1
    assert audit["shared_feature_label_groups"] == 3
    assert audit["test_rows_in_shared_feature_label"] == 4
    assert audit["conflicting_vectors_across_splits"] == 1


def test_record_signatures_preserve_field_boundaries():
    frame = pd.DataFrame([["a,b", "c"], ["a", "b,c"], ["a,b", "c"]])
    signatures = eda.digest_rows(frame)
    assert signatures[0] != signatures[1]
    assert signatures[0] == signatures[2]


@pytest.mark.parametrize(
    "raw,expected", [("0x0800", 2048), ("080", 80), ("65535", 65535)]
)
def test_ports_support_argus_hex_tokens(raw, expected):
    assert eda.port_number(raw) == expected


def test_bot_validation_handles_nonfinite_negative_and_special_ports(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(eda, "ROOT", tmp_path)
    rows = []
    for attack, rate, port in [
        ("0", "NaN", "-"),
        ("1", "inf", "0x0800"),
        ("1", "-2", "70000"),
    ]:
        row = dict.fromkeys(eda.NUMERIC, "1")
        row.update(
            proto="icmp",
            saddr="192.168.0.1",
            daddr="192.168.0.2",
            sport=port,
            dport="80",
            attack=attack,
            category="Normal" if attack == "0" else "DoS",
            subcategory="test",
            srate=rate,
        )
        rows.append(row)
    fixture = tmp_path / "bot.csv"
    pd.DataFrame(rows).to_csv(fixture, index=False)
    with sqlite3.connect(":memory:") as db:
        for view in ["raw", "operational"]:
            db.execute(
                f"CREATE TABLE {view}(s TEXT,x BLOB,y TEXT,n INTEGER,PRIMARY KEY(s,x,y)) WITHOUT ROWID"
            )
        result = eda.scan("bot_iot", "train", fixture, db, 2, 2)
    assert result["invalid"]["attack"] == 0
    assert result["missing"]["srate"] == 1
    assert result["infinite"]["srate"] == 1
    assert result["invalid"]["srate"] == 1
    assert result["invalid"]["sport"] == 1
    assert result["rules"]["sport: special '-' (not numeric)"] == 1
    assert result["rules"]["attack/category inconsistency"] == 0
