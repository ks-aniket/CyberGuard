"""Synthetic audit fixtures test bookkeeping, not detection generalization."""

import hashlib
import importlib.util
import json
import sqlite3
import sys
import zipfile
from pathlib import Path

import pandas as pd
import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "inspect_nf_cse", SCRIPTS / "inspect_nf_cse.py"
)
nf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nf)


def row(**changes):
    values = [
        "10.0.0.1",
        "1234",
        "10.0.0.2",
        "80",
        "6",
        "7.0",
        "100",
        "50",
        "2",
        "1",
        "24",
        "1000",
        "0",
        "Benign",
    ]
    result = dict(zip(nf.COLUMNS, values, strict=True))
    result.update(changes)
    return result


def source(tmp_path, rows):
    p = tmp_path / "NF-CSE-CIC-IDS2018.csv"
    pd.DataFrame(rows, columns=nf.COLUMNS).to_csv(p, index=False)
    return p


def scan(p, size):
    with sqlite3.connect(":memory:") as db:
        return nf.scan(p, db, size, 10)


def test_exact_views_conflicts_and_chunk_invariance(tmp_path):
    p = source(
        tmp_path,
        [
            row(),
            row(),
            row(Label="1", Attack="Bot"),
            row(IPV4_SRC_ADDR="10.1.1.1", L7_PROTO="9.2"),
            row(IN_BYTES="101"),
        ],
    )
    a, b = scan(p, 2), scan(p, 3)
    for key in [
        "duplicates",
        "binary",
        "attacks",
        "issues",
        "constants",
        "rules",
        "categories",
        "sample_rows",
    ]:
        assert a[key] == b[key]
    for c in nf.NUMERIC:
        assert a["numeric"][c]["mean"] == pytest.approx(b["numeric"][c]["mean"])
        assert (
            a["numeric"][c]["sample_quantiles"] == b["numeric"][c]["sample_quantiles"]
        )
    full = a["duplicates"]["all_predictors"]
    assert full["exact_record_duplicate_excess"] == 1
    assert full["distinct_vectors"] == 3
    assert full["conflicting_groups"] == 1
    assert full["rows_in_conflicting_groups"] == 3
    initial = a["duplicates"]["initial_completed"]
    assert initial["distinct_vectors"] == 2
    assert initial["rows_in_conflicting_groups"] == 4
    assert a["duplicates"]["header_only"]["distinct_vectors"] == 1
    assert a["label_disagreement"] == 0
    assert a["binary"] == {"0": 4, "1": 1}
    assert a["constants"]["PROTOCOL"] == "6"
    assert a["numeric"]["L7_PROTO"]["max"] == 9.2


def test_invalid_values_labels_encodings_and_ranges(tmp_path):
    p = source(
        tmp_path,
        [
            row(),
            row(
                Label="1",
                Attack="Benign",
                IN_BYTES="inf",
                OUT_BYTES="garbage",
                L4_DST_PORT="65536",
                L4_SRC_PORT="-1",
                IPV4_SRC_ADDR="not an ip",
                L7_PROTO="2.5",
            ),
            row(
                PROTOCOL="1",
                L4_SRC_PORT="8",
                TCP_FLAGS="256",
                Attack="Unknowné",
                Label="2",
                IN_PKTS="",
                OUT_PKTS="NaN",
            ),
        ],
    )
    r = scan(p, 1)
    assert r["label_disagreement"] == 2
    assert r["unknown_attacks"] == ["Unknowné"]
    assert r["issues"]["OUT_BYTES"]["invalid_numeric"] == 1
    assert r["issues"]["IN_BYTES"]["infinite"] == 1
    assert r["issues"]["IN_PKTS"]["blank"] == 1
    assert r["issues"]["OUT_PKTS"]["na_token"] == 1
    assert r["issues"]["IPV4_SRC_ADDR"]["invalid_ipv4"] == 1
    assert r["issues"]["Attack"]["non_ascii"] == 1
    assert r["rules"]["L4_SRC_PORT_nontransport_nonzero"] == 1
    assert r["rules"]["L4_DST_PORT_out_of_range"] == 1
    json.dumps(r, allow_nan=False)


def make_bag(tmp_path):
    root = tmp_path / "raw"
    bag = root / "arbitrary_bag"
    data = bag / "data"
    data.mkdir(parents=True)
    source(data, [row(), row(Label="1", Attack="Bot")])
    (data / "NetFlow_v1_Features.csv").write_text(
        "Feature,Description\nPROTOCOL,IP protocol identifier byte\n"
    )
    for name, content in [
        ("bag-info.txt", "Source-Organization: Fixture\n"),
        ("bagit.txt", "BagIt-Version: 0.96\n"),
        ("FurtherInformation.txt", "fixture\n"),
    ]:
        (bag / name).write_text(content)

    def manifest(name, paths):
        (bag / name).write_text(
            "".join(
                f"{hashlib.sha1((bag / p).read_bytes()).hexdigest()} {p}\n"
                for p in paths
            )
        )

    manifest(
        "manifest-sha1.txt",
        ["data/NF-CSE-CIC-IDS2018.csv", "data/NetFlow_v1_Features.csv"],
    )
    manifest("tagmanifest-sha1.txt", ["bag-info.txt", "bagit.txt", "manifest-sha1.txt"])
    archive = root / "download.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for p in bag.rglob("*"):
            if p.is_file():
                z.write(p, "different_archive_prefix/" + p.relative_to(bag).as_posix())
    return root, bag, archive


def test_discovery_integrity_and_complete_report_generation(tmp_path):
    root, bag, archive = make_bag(tmp_path)
    assert nf.discover(root) == (bag / "data/NF-CSE-CIC-IDS2018.csv", bag, archive)
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = nf.audit(root, tmp_path / "reports", chunk_size=1, sample_size=2)
    assert result["provenance"]["ok"]
    for name in [
        "overview",
        "feature_audit",
        "data_quality",
        "evaluation_strategy",
        "preprocessing_design",
        "integration_plan",
    ]:
        assert (tmp_path / "reports" / f"{name}.md").stat().st_size > 100
    assert (tmp_path / "reports/figures/multiclass_distribution.svg").is_file()
    assert before == {p: p.read_bytes() for p in before}
    (bag / "bag-info.txt").write_text("changed\n")
    assert not nf.integrity(bag, archive)["ok"]


def test_bad_paths_schema_and_cli(tmp_path):
    with pytest.raises(ValueError, match="exactly one"):
        nf.discover(tmp_path)
    root, _, _ = make_bag(tmp_path)
    with pytest.raises(ValueError, match="outside raw"):
        nf.audit(root, root / "reports")
    with pytest.raises(SystemExit) as exc:
        nf.main(["--chunk-size", "0"])
    assert exc.value.code == 2
    p = tmp_path / "bad.csv"
    p.write_text("Label,Label\n0,0\n")
    with pytest.raises(ValueError, match="schema"):
        scan(p, 1)


def test_json_boundaries_and_near_constant_verification(tmp_path):
    a = pd.DataFrame([["a,b", "c"], ["a", "b,c"], ["a,b", "c"]])
    k = nf.keys(a)
    assert k[0] == k[2] and k[0] != k[1]
    p = source(tmp_path, [row() for _ in range(99)] + [row(PROTOCOL="17")])
    r = scan(p, 9)
    assert r["near_constants"]["PROTOCOL"]["count"] == 99
    assert "PROTOCOL" not in r["constants"]


def test_endpoint_components_are_graphs_not_synthetic_sessions(tmp_path):
    p = source(
        tmp_path,
        [
            row(),
            row(
                IPV4_SRC_ADDR="10.0.0.2",
                IPV4_DST_ADDR="10.0.0.3",
                Label="1",
                Attack="Bot",
            ),
            row(IPV4_SRC_ADDR="192.0.2.1", IPV4_DST_ADDR="192.0.2.1"),
        ],
    )
    r = nf.host_components(p, 1)
    assert r == nf.host_components(p, 3)
    assert r["hosts"] == 4 and r["components"] == 2
    assert r["largest_component_rows"] == 2
    assert r["per_class"]["Bot"]["components"] == 1
    assert r["per_class"]["Benign"]["components"] == 2
    assert not nf.host_components(p, 2, max_hosts=2)["complete"]


def test_duration_diagnostics_preserve_counts_without_corrections(tmp_path):
    p = source(
        tmp_path,
        [
            row(FLOW_DURATION_MILLISECONDS="0"),
            row(FLOW_DURATION_MILLISECONDS="1000"),
            row(FLOW_DURATION_MILLISECONDS="995", Label="1", Attack="Bot"),
        ],
    )
    r = nf.export_patterns(p, 2, 1000)
    assert r["by_class"]["Benign"] == {
        "rows": 2,
        "zero": 1,
        "at_maximum": 1,
        "within_top_one_percent_of_range": 1,
    }
    assert r["by_class"]["Bot"]["within_top_one_percent_of_range"] == 1
