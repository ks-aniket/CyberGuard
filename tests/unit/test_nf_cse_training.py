"""Small software fixtures only; no real-data fits or reserved test access."""

import io
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import average_precision_score, roc_auc_score

from cyberguard.features import nf_cse as nf
from cyberguard.features import nf_cse_preparation as prep
from cyberguard.training import nf_cse_metrics as ev
from cyberguard.training import train_nf_cse as training


def processed_fixture(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    rows = [
        {
            "PROTOCOL": "tcp" if i % 3 else "17",
            "L4_SRC_PORT": 1000 + i,
            "L4_DST_PORT": 80 if i % 2 else 443,
            "IN_BYTES": 100 + i * 3,
            "OUT_BYTES": 200 + i,
            "IN_PKTS": 1 + i % 7,
            "OUT_PKTS": i % 4,
            "Label": str(i % 2),
            "Attack": "Bot" if i % 2 else "Benign",
        }
        for i in range(400)
    ]
    pd.DataFrame(rows).to_csv(raw / "NF-CSE-CIC-IDS2018.csv", index=False)
    pd.DataFrame(
        [
            {"Feature": f["name"], "Description": f["description"]}
            for f in nf.feature_contract()["fields"]
        ]
    ).to_csv(raw / "NetFlow_v1_Features.csv", index=False)
    root = tmp_path / "processed"
    prep.prepare(raw, root, chunk_size=113)
    return root


def small_config():
    c = training.training_config()
    c["logistic"]["max_iter"] = 25
    c["hist_gradient_boosting"].update(max_iter=3, max_leaf_nodes=3, min_samples_leaf=2)
    return c


def test_weighted_metrics_match_expanded_population():
    y = np.array([0, 0, 1, 1])
    score = np.array([0.2, 0.8, 0.4, 0.9])
    w = np.array([20, 2, 3, 10])
    got = ev.metrics(y, score, w, 0.5)
    expanded_y = np.repeat(y, w)
    expanded_score = np.repeat(score, w)
    assert got["confusion_matrix"] == [[20, 2], [3, 10]]
    assert got["confusion_order"] == ["Benign", "Attack"]
    assert got["benign_fpr"] == pytest.approx(2 / 22)
    assert got["attack_detection_rate"] == pytest.approx(10 / 13)
    assert got["average_precision"] == pytest.approx(
        average_precision_score(expanded_y, expanded_score)
    )
    assert got["roc_auc"] == pytest.approx(roc_auc_score(expanded_y, expanded_score))
    assert got["false_positives_per_10000_benign"] == pytest.approx(10000 * 2 / 22)


def test_threshold_ties_boundaries_and_fpr_constraint():
    y = np.array([0, 0, 1, 1])
    score = np.array([0.8, 0.1, 0.8, 0.9])
    weight = np.array([1, 99, 1, 9])
    curve = ev.curves(y, score, weight)
    threshold, _ = ev.select_threshold(curve)
    assert threshold == 0.8
    actual = ev.metrics(y, score, weight, threshold)
    assert actual["recall"] == 1 and actual["benign_fpr"] == 0.01
    tied = ev.curves([0, 1], [0.5, 0.5], [100, 1])
    reject, _ = ev.select_threshold(tied)
    assert np.isfinite(reject) and reject > 1
    assert ev.metrics([0, 1], [0.5, 0.5], [100, 1], reject)["recall"] == 0
    with pytest.raises(ValueError):
        ev.metrics([0, 1], [0.1, np.nan], [1, 1], 0.5)


def test_shared_manifest_filters_test_objects_before_decoding(monkeypatch):
    original = json.loads

    def guarded(value, *args, **kwargs):
        assert "POISON_RESERVED_VALUE" not in value
        return original(value, *args, **kwargs)

    monkeypatch.setattr(training.json, "loads", guarded)
    text = '{"identity":{"source_sha256":"ok"},"artifacts":{"test/a.npz":{"secret":"POISON_RESERVED_VALUE"},"train/a.npz":{"sha256":"yes"}},"plan":{"partitions":{"test":{"Attack_counts":{"POISON_RESERVED_VALUE":4}},"train":{"rows":3,"Attack_counts":{"POISON_RESERVED_VALUE":4},"binary_counts":{"0":2,"1":1}}}}}'
    result = training.ManifestSubset(io.StringIO(text)).value()
    assert result["artifacts"] == {"train/a.npz": {"sha256": "yes"}}
    assert result["plan"]["partitions"] == {
        "train": {"rows": 3, "binary_counts": {"0": 2, "1": 1}}
    }


def test_reader_weights_order_sampling_and_test_denial(tmp_path):
    root = processed_fixture(tmp_path)
    with training.deny_reserved(root) as access:
        manifest, _ = training.load_manifest(root)
        assert set(manifest["plan"]["partitions"]) == {"train", "validation"}
        data = training.load_partition(root, manifest, "train")
        assert data["X"].shape[1] == 13
        assert (
            int(data["weight"].sum()) == manifest["plan"]["partitions"]["train"]["rows"]
        )
        assert data["codes"] is None and data["groups"] is None and not data["names"]
        with pytest.raises(ValueError, match="train/validation"):
            training.load_partition(root, manifest, "test")
        with pytest.raises(PermissionError, match="Reserved"):
            next((root / "test").glob("*.npz")).read_bytes()
        with pytest.raises(PermissionError):
            (root / "metadata/class_distribution.json").read_text()
        with pytest.raises(PermissionError, match="immutable"):
            (root / "train" / "bad.txt").write_text("no")
        assert all(not x.startswith("test/") for x in access["opened"])
    ids = np.array([b"group-a", b"group-a", b"group-b"], dtype="S64")
    a = training.sample_mask(ids, 0.5, 20261115)
    b = training.sample_mask(ids, 0.5, 20261115)
    assert np.array_equal(a, b) and a[0] == a[1]


def test_train_only_scaling_and_multiplicity_fit():
    from cyberguard.inference.nf_cse_model import NFLinearTransform

    X = nf.model_features(
        nf.normalize(
            pd.DataFrame(
                [
                    {
                        "PROTOCOL": "tcp",
                        "L4_SRC_PORT": 0,
                        "L4_DST_PORT": 80,
                        "IN_BYTES": 0,
                        "OUT_BYTES": 0,
                        "IN_PKTS": 0,
                        "OUT_PKTS": 0,
                    },
                    {
                        "PROTOCOL": "udp",
                        "L4_SRC_PORT": 65535,
                        "L4_DST_PORT": 53,
                        "IN_BYTES": 999,
                        "OUT_BYTES": 10,
                        "IN_PKTS": 10,
                        "OUT_PKTS": 1,
                    },
                ]
            )
        )
    ).to_numpy(dtype=float)
    transform = NFLinearTransform().fit(X, sample_weight=np.array([9, 1]))
    assert transform.scaler_.mean_[0] == pytest.approx(0.1)
    before = transform.scaler_.mean_.copy()
    transform.transform(X * 1)  # inference never fits statistics
    assert np.array_equal(before, transform.scaler_.mean_)
    expanded = NFLinearTransform().fit(np.repeat(X, [9, 1], axis=0))
    assert np.allclose(transform.scaler_.mean_, expanded.scaler_.mean_)


def test_configuration_bounded_and_no_automatic_early_stopping(tmp_path):
    path = tmp_path / "config.json"
    config = small_config()
    path.write_text(json.dumps(config))
    assert training.training_config(path) == config
    config["hist_gradient_boosting"]["early_stopping"] = True
    path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="configuration keys"):
        training.training_config(path)
    with pytest.raises(FileNotFoundError):
        training.validate_artifact(tmp_path / "missing.joblib")


def test_tiny_two_model_run_serialization_fresh_process_metadata_and_no_test_io(
    tmp_path, monkeypatch
):
    root = processed_fixture(tmp_path)
    output = tmp_path / "models"
    report = tmp_path / "reports"
    # Deny test opens independently of the training audit hook as well.
    original = Path.open

    def guarded(self, *args, **kwargs):
        assert not self.resolve().is_relative_to(root / "test")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    run = training.run_experiment(
        root, output, report, config=small_config(), threads=1, batch_size=37
    )
    assert set(run["models"]) == {"logistic", "hist_gradient_boosting"}
    assert all(d["selected"]["benign_fpr"] <= 0.01 for d in run["models"].values())
    assert not any(x.startswith("test/") for x in run["processed_files_opened"])
    path = output / "nf_cse_binary_completed_flow.joblib"
    model, metadata = training.validate_artifact(path)
    assert list(model.feature_names_in_) == list(nf.RAW_FEATURES)
    assert list(model.classes_) == [0, 1]
    assert metadata["feature_contract_version"] == nf.CONTRACT_VERSION
    assert metadata["selected_threshold"] == model.threshold

    def fail(*args, **kwargs):
        raise AssertionError("Refit during inference")

    monkeypatch.setattr(model.normalizer, "fit", fail)
    frame = training.probe_frame()
    scores = model.predict_proba(frame)
    assert np.allclose(scores.sum(axis=1), 1)
    assert np.array_equal(
        model.predict(frame), (scores[:, 1] >= model.threshold).astype(np.uint8)
    )
    with pytest.raises(ValueError, match="Missing completed-flow"):
        model.predict(frame[["PROTOCOL"]])
    assert run["fresh_process_verification"]["software_verification_only"]
    assert len(list((report / "figures").glob("*.svg"))) == 6
    for name in [
        "training_report.md",
        "model_comparison.csv",
        "validation_metrics.json",
        "classification_report.csv",
        "confusion_matrix.csv",
        "threshold_analysis.csv",
        "attack_family_recall.csv",
    ]:
        assert (report / name).is_file()
    sidecar = path.with_suffix(".metadata.json")
    payload = json.loads(sidecar.read_text())
    payload["feature_contract_version"] = "wrong"
    sidecar.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="metadata mismatch"):
        training.validate_artifact(path)


def test_fixed_seed_fit_and_class_weight_semantics_on_small_fixture():
    from threadpoolctl import threadpool_limits

    frame = pd.concat([training.probe_frame().iloc[[0]]] * 12, ignore_index=True)
    frame["IN_BYTES"] = np.arange(12) * 10
    train = {
        "X": nf.model_features(nf.normalize(frame)).to_numpy(dtype=float),
        "y": np.array([0] * 8 + [1] * 4, dtype=np.uint8),
        "weight": np.array([2] * 8 + [3] * 4, dtype=float),
    }
    config = small_config()
    config["balance_classes"] = True
    with threadpool_limits(limits=1):
        a, resources = training.fit_model(
            "hist_gradient_boosting", train, config, 20261115
        )
        b, _ = training.fit_model("hist_gradient_boosting", train, config, 20261115)
        assert np.array_equal(a.score_encoded(train["X"]), b.score_encoded(train["X"]))
    assert a.estimator.early_stopping is False
    assert a.estimator.class_weight is None
    assert resources["class_weight_factors"] == pytest.approx([28 / 32, 28 / 24])
