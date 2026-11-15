"""Final-evaluation software fixtures; never open the real reserved partition."""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import HistGradientBoostingClassifier

from cyberguard.features import nf_cse as nf
from cyberguard.features import nf_cse_preparation as prep
from cyberguard.inference.nf_cse_model import NFCSEBinaryModel
from cyberguard.training import evaluate_nf_cse as final
from cyberguard.training import nf_cse_metrics as metrics


class FrozenEstimator(HistGradientBoostingClassifier):
    """Deterministic inference-only fixture. No training involved."""

    def __init__(self):
        super().__init__()
        self.classes_ = np.array([0, 1])

    def predict_proba(self, X):
        p = (np.asarray(X)[:, 3] % 11) / 10
        return np.column_stack([1 - p, p])

    def fit(self, *args, **kwargs):
        raise AssertionError("No fitting")


@pytest.fixture
def sealed(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    pd.DataFrame(
        [
            dict(
                zip(nf.RAW_FEATURES, [6, 1000 + i, 80, 100 + i, 200, 1, 2], strict=True)
            )
            | {"Label": i % 2, "Attack": "Bot" if i % 2 else "Benign"}
            for i in range(400)
        ]
    ).to_csv(raw / "NF-CSE-CIC-IDS2018.csv", index=False)
    pd.DataFrame(
        [
            {"Feature": f["name"], "Description": f["description"]}
            for f in nf.feature_contract()["fields"]
        ]
    ).to_csv(raw / "NetFlow_v1_Features.csv", index=False)
    root = tmp_path / "processed"
    prep.prepare(raw, root, chunk_size=71)
    manifest = json.loads((root / "metadata/split_manifest.json").read_text())
    modelpath = tmp_path / "model/model.joblib"
    modelpath.parent.mkdir()
    metadata = {
        "model_id": "nf_cse_binary_completed_flow",
        "model_type": "hist_gradient_boosting",
        "feature_contract_version": nf.CONTRACT_VERSION,
        "preprocessing_version": nf.PREPROCESSING_VERSION,
        "feature_order": list(nf.RAW_FEATURES),
        "encoded_feature_order": list(nf.MODEL_FEATURES),
        "class_mapping": {"0": "Benign", "1": "Attack"},
        "selected_threshold": final.THRESHOLDS["high_sensitivity"],
        "source_dataset_sha256": manifest["identity"]["source_sha256"],
        "partition_manifest_sha256": prep.sha256(root / "metadata/split_manifest.json"),
    }
    model = NFCSEBinaryModel(
        FrozenEstimator(),
        threshold=metadata["selected_threshold"],
        metadata=metadata.copy(),
    )
    joblib.dump(model, modelpath)
    metadata["artifact_sha256"] = prep.sha256(modelpath)
    modelpath.with_suffix(".metadata.json").write_text(json.dumps(metadata))
    val = tmp_path / "validation_metrics.json"
    fake = metrics.metrics([0, 1], [0.01, 0.9], [3, 2], 0.5)
    val.write_text(
        json.dumps(
            {
                "metadata": metadata,
                "models": {
                    "hist_gradient_boosting": {
                        "selected": fake
                        | {"threshold": final.THRESHOLDS["high_sensitivity"]},
                        "fixed_0_5": fake,
                    }
                },
            }
        )
    )
    return (
        root,
        modelpath,
        val,
        tmp_path / "reports/final_test",
        manifest["plan"]["partitions"]["test"],
    )


def test_end_to_end_no_fit_no_tuning_no_mutation_or_other_partition_access(
    sealed, monkeypatch
):
    root, model, val, output, expected = sealed
    original = Path.open
    before = {p: prep.sha256(p) for p in root.rglob("*") if p.is_file()}

    def guarded(self, mode="r", *args, **kwargs):
        if self.resolve().is_relative_to(root):
            assert not any(c in mode for c in "wax+")
            assert not self.resolve().is_relative_to(root / "train")
            assert not self.resolve().is_relative_to(root / "validation")
        return original(self, mode, *args, **kwargs)

    def fail(*args, **kwargs):
        raise AssertionError("Fitting or threshold optimization")

    monkeypatch.setattr(Path, "open", guarded)
    monkeypatch.setattr(nf.NFCSECompletedFlowFeatures, "fit", fail)
    monkeypatch.setattr(metrics, "select_threshold", fail)
    result = final.run(
        root,
        model,
        val,
        output,
        allow=True,
        threads=1,
        batch_size=13,
        expected=expected,
    )
    assert result["status"] == "complete"
    assert all(v == "passed" for v in result["integrity_checks"].values())
    got = final.inspect(output)["metrics"]
    for mode, r in got["thresholds"].items():
        assert r["threshold"] == final.THRESHOLDS[mode]
        assert r["original_records"] == expected["rows"]
        assert sum(sum(row) for row in r["confusion_matrix"]) == expected["rows"]
    assert len(list((output / "figures").glob("*.svg"))) >= 8
    for path, digest in before.items():
        # Read train/val hashes only after restoring the independent access guard.
        if not path.is_relative_to(root / "train") and not path.is_relative_to(
            root / "validation"
        ):
            assert prep.sha256(path) == digest
    with pytest.raises(ValueError, match="already exist"):
        final.run(root, model, val, output, allow=True, expected=expected)
    with pytest.raises(FileExistsError):
        final.run(
            root, model, val, output.parent / "alternate", allow=True, expected=expected
        )
    # Inspection checks only report files, not data/model.
    model.unlink()
    assert final.inspect(output)["manifest"]["status"] == "complete"
    (output / "threshold_comparison.csv").write_text("tampered")
    with pytest.raises(ValueError, match="checksum"):
        final.inspect(output)


@pytest.mark.parametrize(
    "change",
    [
        "model",
        "metadata",
        "threshold",
        "mapping",
        "contract",
        "manifest",
        "shard",
        "population",
        "validation",
    ],
)
def test_preflight_refuses_critical_mismatch(sealed, change):
    root, model, val, output, expected = sealed
    if change == "model":
        with model.open("ab") as f:
            f.write(b"corruption")
    elif change == "metadata":
        model.with_suffix(".metadata.json").unlink()
    elif change in {"threshold", "mapping"}:
        p = model.with_suffix(".metadata.json")
        m = json.loads(p.read_text())
        m["selected_threshold" if change == "threshold" else "class_mapping"] = (
            0.2 if change == "threshold" else {"0": "Attack", "1": "Benign"}
        )
        p.write_text(json.dumps(m))
    elif change == "contract":
        (root / "metadata/feature_contract.json").write_text("{}")
    elif change == "manifest":
        (root / "metadata/split_manifest.sha256").write_text("bad")
    elif change == "shard":
        with next((root / "test").glob("*.npz")).open("ab") as f:
            f.write(b"bad")
    elif change == "population":
        expected = expected | {"rows": 1}
    else:
        val.write_text("{}")
    with pytest.raises((ValueError, KeyError, OSError)):
        final.preflight(root, model, val, expected)
    assert not output.exists()


def test_weighted_metrics_family_and_frozen_validation_comparison():
    y, p, w = (
        np.array([0, 0, 1, 1]),
        np.array([0.01, 0.8, 0.02, 0.9]),
        np.array([20, 2, 3, 10]),
    )
    baseline = metrics.metrics(y, p, w, 0.5)
    validation = {
        "models": {
            "hist_gradient_boosting": {"selected": baseline, "fixed_0_5": baseline}
        }
    }
    got, families, comparisons, quality = final.summarize(
        y,
        p,
        w,
        np.array([b"a", b"b", b"c", b"d"]),
        np.array([0, 0, 1, 1]),
        ["Benign", "Bot"],
        validation,
    )
    assert got["lower_false_alarm"]["confusion_matrix"] == [[20, 2], [3, 10]]
    assert got["lower_false_alarm"]["predicted_attack"] == 12
    assert got["lower_false_alarm"]["specificity"] == pytest.approx(20 / 22)
    assert families[0]["original_records"] == 13 and families[0]["true_positives"] == 10
    assert families[0]["distinct_feature_groups"] == 2
    assert all(
        r["test_minus_validation"] == 0
        for r in comparisons
        if r["mode"] == "lower_false_alarm"
    )
    assert quality["brier_score"] == pytest.approx(np.average((y - p) ** 2, weights=w))
    for bad in [
        np.array([0, 0, 0, 0]),
        np.array([1, 1, -1, 1]),
        np.array([1, 1, np.nan, 1]),
    ]:
        with pytest.raises(ValueError):
            final.summarize(
                y,
                p,
                bad,
                np.array([b"a"] * 4),
                np.array([0, 0, 1, 1]),
                ["Benign", "Bot"],
                validation,
            )


def test_consent_required_before_artifact_access(tmp_path):
    with pytest.raises(ValueError, match="allow-final-test"):
        final.run(
            tmp_path / "missing",
            tmp_path / "missing.joblib",
            tmp_path / "val",
            tmp_path / "out",
        )
    assert not (tmp_path / "out").exists()


def test_interrupted_attempt_blocks_retry_before_preflight(sealed):
    root, model, val, output, expected = sealed
    model.unlink()
    with pytest.raises(OSError):
        final.run(root, model, val, output, allow=True, threads=1, expected=expected)
    assert (output.parent / "final_test_attempt.json").exists()
    with pytest.raises(FileExistsError):
        final.run(root, model, val, output, allow=True, threads=1, expected=expected)
