"""Validate partition boundaries and weighted reporting before fitting raw data."""

import sqlite3

import numpy as np
import pandas as pd
import pytest

from cyberguard.features.network import RestrictedNetworkFeatures, canonical_keys
from cyberguard.training.evaluate import evaluate_predictions
from cyberguard.training.sampling import validation_group
from cyberguard.training.train_network import build_training_index


def test_chunk_invariance_duplicates_conflicts_and_theft_policy(tmp_path):
    fixture = tmp_path / "train.csv"
    pd.DataFrame(
        {
            "proto": ["tcp", "6", "TCP", "udp", "arp", "tcp"],
            "sport": ["080", "0x50", "80", "53", "-1", "123"],
            "dport": ["443", "0443", "443", "0x35", "-1", "80"],
            "category": ["Normal", "Normal", "DoS", "DDoS", "Reconnaissance", "Theft"],
            "pkSeqID": [1, 2, 3, 4, 5, 6],
            "saddr": ["a", "b", "c", "d", "e", "f"],
            "N_IN_Conn_P_SrcIP": [1, 99, 0, 100, 1, 5],
        }
    ).to_csv(fixture, index=False)
    outputs = []
    for size in [1, 4]:
        with sqlite3.connect(":memory:") as db:
            counts, _normalization = build_training_index(fixture, db, chunk_size=size)
            rows = db.execute("SELECT * FROM examples ORDER BY k,y").fetchall()
            outputs.append(rows)
            assert counts["Theft"] == 1
            assert (
                db.execute("SELECT count(*) FROM examples WHERE y='Theft'").fetchone()[
                    0
                ]
                == 0
            )
            assert (
                db.execute(
                    "SELECT count(*) FROM (SELECT k FROM examples GROUP BY k HAVING count(distinct partition)>1)"
                ).fetchone()[0]
                == 0
            )
            # Equivalent TCP port spellings merge across IDs/IPs/aggregate values;
            # conflicting target counts remain separate records in the same group.
            assert (
                db.execute("SELECT n FROM examples WHERE y='Normal'").fetchone()[0] == 2
            )
            normal = db.execute(
                "SELECT k,partition FROM examples WHERE y='Normal'"
            ).fetchone()
            dos = db.execute(
                "SELECT k,partition FROM examples WHERE y='DoS'"
            ).fetchone()
            assert normal == dos
    assert outputs[0] == outputs[1]


def test_partition_is_independent_of_target_and_row_order():
    raw = pd.DataFrame(
        {
            "proto": ["tcp", "udp", "tcp"],
            "sport": ["080", "53", "0x50"],
            "dport": ["443", "53", "443"],
        }
    )
    normalize = RestrictedNetworkFeatures().fit(raw)
    keys = canonical_keys(normalize.transform(raw))
    forward = {key: validation_group(key) for key in keys}
    reverse = {key: validation_group(key) for key in reversed(keys)}
    assert forward == reverse
    assert keys[0] == keys[2]
    assert len(set(forward)) == 2


def test_metrics_match_count_expansion_and_benign_fpr_denominator():
    truth = np.array(["Normal", "Normal", "DoS", "DDoS", "Reconnaissance"])
    predictions = np.array(["Normal", "DoS", "DoS", "DDoS", "Reconnaissance"])
    counts = np.array([3, 1, 5, 2, 4])
    weighted = evaluate_predictions(truth, predictions, counts)
    expanded = evaluate_predictions(
        np.repeat(truth, counts), np.repeat(predictions, counts), np.ones(counts.sum())
    )
    assert weighted["macro_f1"] == pytest.approx(expanded["macro_f1"])
    assert weighted["confusion_matrix"] == expanded["confusion_matrix"]
    assert weighted["benign_support"] == 4
    assert weighted["benign_false_positives"] == 1
    assert weighted["benign_false_positive_rate"] == 0.25
    with pytest.raises(ValueError, match="no Normal support"):
        evaluate_predictions(["DoS"], ["DoS"], [1])


def test_training_runner_serializes_metrics_and_report_without_test_file(tmp_path):
    import json

    from cyberguard.training.evaluate import write_validation_report
    from cyberguard.training.train_network import DEFAULT_TRAIN, train_baseline

    # Software integration fixture, not measured evidence of real-world accuracy.
    path = tmp_path / DEFAULT_TRAIN
    path.parent.mkdir(parents=True)
    targets = ["Normal", "DoS", "DDoS", "Reconnaissance"]
    rows = [
        {"proto": "tcp", "sport": str(i + 1000 * j), "dport": "80", "category": target}
        for j, target in enumerate(targets)
        for i in range(100)
    ]
    rows.append({"proto": "arp", "sport": "-1", "dport": "-1", "category": "Theft"})
    pd.DataFrame(rows).to_csv(path, index=False)
    result = train_baseline(tmp_path, chunk_size=41)
    write_validation_report(result, tmp_path)
    exported = json.loads(
        (
            tmp_path / "reports/model_evaluation/bot_iot_validation_metrics.json"
        ).read_text()
    )
    assert exported["supplied_test_opened"] is False
    assert exported["raw_class_counts"]["Theft"] == 1
    assert (
        sum(exported["split_counts"]["train"].values())
        + sum(exported["split_counts"]["validation"].values())
        == 400
    )
    assert exported["cross_partition_shared_groups"] == 0
    assert (tmp_path / exported["model_path"]).is_file()
    assert (tmp_path / "reports/model_evaluation/bot_iot_validation.md").is_file()
