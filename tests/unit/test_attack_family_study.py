"""Synthetic software tests only; never read the real research populations."""

from copy import deepcopy
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from cyberguard.features import nf_cse as nf
from cyberguard.features.nf_cse_preparation import group_id, partition_for_key, sha256
from cyberguard.research.attack_family import (
    PLAN,
    abstention,
    collision_analysis,
    encode_names,
    fit_candidate,
    load_data,
    metrics,
    predict_candidate,
    route,
    run,
    svg_heatmap,
    verify_disjoint,
)
from cyberguard.training.train_nf_cse import deny_reserved


def fixture():
    vectors = np.asarray(
        [
            [6, 100, 80, 10, 0, 1, 0],
            [6, 100, 80, 10, 0, 1, 0],
            [6, 100, 80, 10, 0, 1, 0],
            [17, 53, 99, 40, 5, 2, 1],
            [17, 53, 99, 40, 5, 2, 1],
            [6, 102, 22, 100, 0, 4, 0],
        ]
    )
    groups = np.asarray(
        [
            group_id(k).encode()
            for k in nf.canonical_keys(pd.DataFrame(vectors, columns=nf.RAW_FEATURES))
        ],
        dtype="S64",
    )
    return {
        "vectors": vectors,
        "X": nf.model_features(pd.DataFrame(vectors, columns=nf.RAW_FEATURES)).to_numpy(
            dtype=float
        ),
        "y": np.array([0, 1, 2, 1, 2, 2]),
        "w": np.array([5, 3, 2, 4, 6, 1], dtype=float),
        "groups": groups,
        "names": ["Benign", "Family A", "SQL Injection"],
    }


def test_inventory_respects_original_compact_unique_and_ambiguity():
    inv, pairs, summary = collision_analysis(fixture())
    assert inv[0]["weighted_records"] == 5 and inv[0]["compact_rows"] == 1
    assert inv[2]["weighted_records"] == 9 and inv[2]["compact_rows"] == 3
    assert inv[2]["unique_feature_vectors"] == inv[2]["distinct_feature_groups"] == 3
    assert inv[1]["percent_of_attack_records"] == 100 * 7 / 16
    assert inv[0]["weighted_majority_label_proportion_in_ambiguous_groups"] == 0.5
    assert summary["unique_vectors"] == 3
    assert summary["ambiguous_groups_any_label"] == 2
    assert summary["minimum_deterministic_errors"] == 9
    assert summary["empirical_multiclass_collision_ceiling"] == pytest.approx(12 / 21)
    assert summary["attack_only_collision_ceiling"] == pytest.approx(10 / 16)
    assert summary["attack_family_conflicting_groups"] == 2
    assert summary["benign_attack_conflicting_groups"] == 1
    assert (
        next(
            p
            for p in pairs
            if p["family_a"] == "Family A" and p["family_b"] == "SQL Injection"
        )["shared_vectors"]
        == 2
    )


def test_collision_counts_do_not_depend_on_row_order_or_weight_expansion():
    d = fixture()
    original = collision_analysis(d)
    ix = np.array([4, 1, 5, 2, 0, 3])
    reordered = {k: v[ix] if isinstance(v, np.ndarray) else v for k, v in d.items()}
    assert collision_analysis(reordered) == original
    expanded = {
        k: np.repeat(v, d["w"].astype(int), axis=0) if isinstance(v, np.ndarray) else v
        for k, v in d.items()
    }
    expanded["w"] = np.ones(len(expanded["y"]))
    assert (
        collision_analysis(expanded)[2]["empirical_multiclass_collision_ceiling"]
        == original[2]["empirical_multiclass_collision_ceiling"]
    )


def test_no_collision_ceiling_is_one():
    d = fixture()
    ix = [0, 3, 5]
    d = {k: v[ix] if isinstance(v, np.ndarray) else v for k, v in d.items()}
    assert collision_analysis(d)[2]["empirical_multiclass_collision_ceiling"] == 1


def test_class_mapping_is_exact_and_rejects_unknown():
    assert encode_names(
        ["SQL Injection", "Benign", "Family A"], fixture()["names"]
    ).tolist() == [2, 0, 1]
    with pytest.raises(ValueError, match="absent"):
        encode_names(["Typo"], fixture()["names"])


def test_group_disjoint_guard():
    d = fixture()
    with pytest.raises(ValueError, match="overlap"):
        verify_disjoint(d, d)
    other = deepcopy(d)
    other["groups"] = np.asarray([b"x" * 64] * 6, dtype="S64")
    assert verify_disjoint(d, other)["overlap"] == 0


def test_metrics_include_benign_and_family_identification():
    result = metrics(
        np.array([0, 0, 1, 1, 2]),
        np.array([0, 2, 0, 2, 2]),
        np.array([8, 2, 3, 4, 1]),
        fixture()["names"],
    )
    assert result["confusion_matrix"] == [[8, 0, 2], [3, 0, 4], [0, 0, 1]]
    assert result["benign_fpr"] == pytest.approx(0.2)
    assert result["attack_detection_recall"] == pytest.approx(5 / 8)
    assert result["per_class"][1]["family_identification_recall"] == 0
    assert result["per_class"][1]["attack_detection_recall"] == pytest.approx(4 / 7)
    assert result["weighted_records"] == 18


@pytest.mark.parametrize("threshold,expected", [(0.5, [0, 1, 2]), (0.1, [2, 1, 2])])
def test_hierarchical_routing_and_end_to_end(threshold, expected):
    pred = route(np.array([0.2, 0.5, 0.9]), np.array([2, 1, 2]), threshold)
    assert pred.tolist() == expected
    result = metrics(np.array([0, 1, 2]), pred, np.ones(3), fixture()["names"])
    assert sum(map(sum, result["confusion_matrix"])) == 3


def test_hierarchy_never_changes_binary_benign_to_uncertain():
    values = abstention(
        np.array([0, 1, 2]),
        np.array([0, 0, 2]),
        np.array([0.01, 0.01, 0.6]),
        np.ones(3),
        fixture()["names"],
        eligible=np.array([False, False, True]),
    )
    strict = values[-1]
    assert strict["coverage"] == pytest.approx(2 / 3)
    assert strict["selective_accuracy"] == 0.5
    assert strict["per_family"]["Family A"]["rejection_rate"] == 0
    assert strict["per_family"]["SQL Injection"]["rejection_rate"] == 1


def test_abstention_empty_and_rare_class_counts():
    result = abstention(
        np.array([2]), np.array([1]), np.array([0.1]), np.array([7]), fixture()["names"]
    )
    assert result[0]["coverage"] == 1 and result[0]["accepted_error_rate"] == 1
    assert result[-1]["coverage"] == 0 and result[-1]["selective_accuracy"] is None
    assert result[-1]["per_family"]["SQL Injection"]["rejected"] == 7
    assert result[-1]["per_family"]["Benign"]["rejection_rate"] is None


@pytest.mark.parametrize("kind", ["linear", "histogram"])
@pytest.mark.parametrize("attack_only", [False, True])
def test_weighted_fits_predictions_and_reproducibility(kind, attack_only):
    d = fixture()
    one, cost = fit_candidate(kind, d, attack_only, 1)
    two, _ = fit_candidate(kind, d, attack_only, 1)
    p, s, _ = predict_candidate(one, d["X"], 1)
    p2, s2, _ = predict_candidate(two, d["X"], 1)
    assert np.array_equal(p, p2) and np.array_equal(s, s2)
    assert np.isfinite(s).all() and ((0 <= s) & (s <= 1)).all()
    assert set(p) <= ({1, 2} if attack_only else {0, 1, 2})
    assert cost["training_original_weight"] == (16 if attack_only else 21)


def shard_fixture(tmp_path):
    seed = PLAN["seed"]
    vector = next(
        [6, port, 80, 10, 0, 1, 0]
        for port in range(200)
        if partition_for_key(f"[6,{port},80,10,0,1,0]", seed) == "train"
    )
    x = np.asarray([vector, vector], dtype=np.int64)
    key = nf.canonical_keys(pd.DataFrame(x, columns=nf.RAW_FEATURES))[0]
    path = tmp_path / "train/part-00000.npz"
    path.parent.mkdir()
    np.savez(
        path,
        features=x,
        Label=np.array([0, 1], dtype=np.uint8),
        Attack=np.array(["Benign", "SQL Injection"]),
        multiplicity=np.array([5, 7], dtype=np.uint64),
        group_id=np.asarray([group_id(key).encode()] * 2, dtype="S64"),
    )
    manifest = {
        "identity": {"seed": seed},
        "plan": {
            "partitions": {
                "train": {
                    "compact_records": 2,
                    "rows": 12,
                    "binary_counts": {"0": 5, "1": 7},
                }
            }
        },
        "artifacts": {"train/part-00000.npz": {"sha256": sha256(path)}},
    }
    return path, manifest


def test_verified_training_lineage_labels_and_weights(tmp_path):
    _, m = shard_fixture(tmp_path)
    d = load_data(tmp_path, m, "train")
    assert d["names"] == ["Benign", "SQL Injection"] and d["w"].sum() == 12
    assert d["y"].tolist() == [0, 1]


def test_altered_shard_refused(tmp_path):
    path, m = shard_fixture(tmp_path)
    path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="modified"):
        load_data(tmp_path, m, "train")


def test_reserved_loader_and_open_guards(tmp_path):
    with pytest.raises(ValueError, match="reserved"):
        load_data(tmp_path, {}, "test")
    (tmp_path / "test").mkdir()
    p = tmp_path / "test/records.npz"
    p.write_bytes(b"reserved")
    with deny_reserved(tmp_path):
        with pytest.raises(PermissionError, match="Reserved"):
            p.read_bytes()
        with pytest.raises(PermissionError, match="immutable"):
            (tmp_path / "metadata.json").write_text("forbidden")


def test_loader_rejects_test_symlink_even_with_manifest_hash(tmp_path):
    path, m = shard_fixture(tmp_path)
    (tmp_path / "test").mkdir()
    reserved = tmp_path / "test/records.npz"
    path.rename(reserved)
    path.symlink_to(reserved)
    with deny_reserved(tmp_path), pytest.raises(ValueError, match="Unsafe"):
        load_data(tmp_path, m, "train")


def test_outputs_never_overwrite_models_or_existing_results(tmp_path):
    with pytest.raises(ValueError, match="cannot overwrite"):
        run(output=Path(__file__).resolve().parents[2] / "models/research")
    with pytest.raises(FileExistsError):
        run(output=tmp_path)


def test_svg_valid_and_deterministic(tmp_path):
    import xml.etree.ElementTree as ET

    p = tmp_path / "plot.svg"
    svg_heatmap(
        p, "test & title", [[2, 3], [0, 1]], ["A", "B"], ["A", "B"], logarithmic=True
    )
    original = p.read_bytes()
    ET.parse(p)
    svg_heatmap(
        p, "test & title", [[2, 3], [0, 1]], ["A", "B"], ["A", "B"], logarithmic=True
    )
    assert p.read_bytes() == original


@pytest.mark.parametrize("problem", ["group", "label"])
def test_checksum_valid_but_semantically_corrupt_lineage_refused(tmp_path, problem):
    path, m = shard_fixture(tmp_path)
    with np.load(path, allow_pickle=False) as shard:
        values = {k: shard[k] for k in shard.files}
    if problem == "group":
        values["group_id"][0] = b"f" * 64
    else:
        values["Attack"][0] = "SQL Injection"
    np.savez(path, **values)
    m["artifacts"]["train/part-00000.npz"]["sha256"] = sha256(path)
    with pytest.raises(ValueError, match="lineage|disagreement"):
        load_data(tmp_path, m, "train")
