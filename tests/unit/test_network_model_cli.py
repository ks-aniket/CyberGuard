"""CLI software fixtures; none use the real official test or train a model."""

import json
import os

import joblib
import numpy as np
import pandas as pd
import pytest
from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score

from cyberguard.features.network import RAW_FEATURES, TARGETS
from cyberguard.testing import network_model_cli as cli
from cyberguard.training.train_network import DEFAULT_TRAIN


class FixturePredictor:
    classes_ = np.array(["DDoS", "DoS", "Normal", "Reconnaissance"])
    feature_names_in_ = np.array(RAW_FEATURES)

    def fit(self, *args, **kwargs):
        raise AssertionError("CLI must never fit preprocessing or a model")

    def predict(self, frame):
        assert list(frame) == list(RAW_FEATURES)
        return np.array(
            [
                {"1": "Normal", "2": "DoS", "3": "DDoS", "4": "Reconnaissance"}.get(
                    str(port), "Normal"
                )
                for port in frame.sport
            ]
        )

    def predict_proba(self, frame):
        return np.array(
            [
                [float(c == label) for c in self.classes_]
                for label in self.predict(frame)
            ]
        )


@pytest.fixture
def model_path(tmp_path):
    path = tmp_path / "model.joblib"
    joblib.dump(FixturePredictor(), path)
    return path


def write_csv(path, labels=False):
    frame = pd.DataFrame(
        {
            "id": ["a", "b", "c", "d", "e"],
            "proto": ["tcp"] * 5,
            "sport": ["1", "2", "2", "3", "4"],
            "dport": ["80"] * 5,
        }
    )
    if labels:
        frame["category"] = ["Normal", "Normal", "DoS", "DDoS", "Reconnaissance"]
    frame.to_csv(path, index=False)
    return frame


def invoke(tmp_path, model_path, command, source, output, *extras):
    return cli.main(
        [
            command,
            "--model",
            str(model_path),
            "--input",
            str(source),
            "--output",
            str(output),
            *extras,
        ],
        root=tmp_path,
    )


def test_load_and_info_without_assuming_pipeline(model_path, tmp_path, capsys):
    assert callable(cli.load_model(model_path).predict)
    assert cli.main(["info", "--model", str(model_path)], root=tmp_path) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["required_features_exposed_by_model"] == list(RAW_FEATURES)
    assert info["pipeline_steps"] is None
    assert info["matching_baseline_metadata"] is None
    assert info["probabilities_available"]
    assert info["model_bytes"] == model_path.stat().st_size


@pytest.mark.parametrize("kind", ["missing", "corrupt", "wrong_type"])
def test_bad_artifacts_are_clear_errors(tmp_path, kind, capsys):
    path = tmp_path / "bad.joblib"
    if kind == "corrupt":
        path.write_bytes(b"not joblib")
    if kind == "wrong_type":
        joblib.dump({"not": "a model"}, path)
    assert cli.main(["info", "--model", str(path)], root=tmp_path) == 2
    assert "Error:" in capsys.readouterr().err


def test_interactive_repeats_load_once_and_exits(
    model_path, tmp_path, monkeypatch, capsys
):
    original = cli.joblib.load
    loaded = []

    def load(path):
        loaded.append(path)
        return original(path)

    monkeypatch.setattr(cli.joblib, "load", load)
    values = iter(["TCP", "1", "0x0050", "y", "udp", "2", "-1", "n"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    assert cli.main(["interactive", "--model", str(model_path)], root=tmp_path) == 0
    text = capsys.readouterr().out
    assert "Class: Normal" in text and "Class: DoS" in text
    assert "uncalibrated" in text
    assert len(loaded) == 1


def test_interactive_handles_eof_and_rejection(
    model_path, tmp_path, monkeypatch, capsys
):
    class RejectOnce(FixturePredictor):
        rejected = False

        def predict(self, frame):
            if not self.rejected:
                self.rejected = True
                raise ValueError("fixture contract rejection")
            return super().predict(frame)

    monkeypatch.setattr(cli, "load_model", lambda _: RejectOnce())
    values = iter(["tcp", "bad", "80", "q"])
    monkeypatch.setattr("builtins.input", lambda _: next(values))
    assert cli.main(["interactive", "--model", str(model_path)], root=tmp_path) == 0
    assert "Input rejected" in capsys.readouterr().out

    def eof(_):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert cli.main(["interactive", "--model", str(model_path)], root=tmp_path) == 0


def test_chunking_order_original_columns_probabilities_and_no_fit(
    tmp_path, model_path, monkeypatch
):
    source = tmp_path / "input.csv"
    original = write_csv(source)
    before = source.read_bytes()
    model = FixturePredictor()
    sizes = []
    predict = model.predict

    def tracked(frame):
        sizes.append(len(frame))
        return predict(frame)

    model.predict = tracked
    monkeypatch.setattr(cli, "load_model", lambda _: model)
    output = tmp_path / "predictions.csv"
    assert (
        invoke(
            tmp_path,
            model_path,
            "predict",
            source,
            output,
            "--chunk-size",
            "2",
            "--probabilities",
        )
        == 0
    )
    result = pd.read_csv(output, dtype=str, keep_default_na=False)
    pd.testing.assert_frame_equal(result[list(original)], original)
    assert result.prediction.tolist() == [
        "Normal",
        "DoS",
        "DoS",
        "DDoS",
        "Reconnaissance",
    ]
    assert result["probability_Normal"].astype(float).tolist() == [1, 0, 0, 0, 0]
    assert result["probability_DoS"].astype(float).tolist() == [0, 1, 1, 0, 0]
    assert sizes == [
        2,
        2,
        2,
        2,
        1,
        1,
    ]  # predict + probability implementation, bounded per chunk
    assert source.read_bytes() == before


@pytest.mark.parametrize(
    "content",
    [
        "",
        "proto,sport,dport\n",
        "proto,sport\ntcp,1\n",
        "proto,proto,sport,dport\ntcp,tcp,1,80\n",
        "proto,sport,dport\ntcp,1,80\ntcp,2,80,extra\n",
        "proto,sport,dport\ntcp,1\n",
        'proto,sport,dport\n"unterminated,1,80\n',
    ],
)
def test_empty_schema_and_malformed_inputs_publish_nothing(
    tmp_path, model_path, content
):
    source = tmp_path / "bad.csv"
    source.write_text(content)
    output = tmp_path / "out.csv"
    assert (
        invoke(tmp_path, model_path, "predict", source, output, "--chunk-size", "1")
        == 2
    )
    assert not output.exists()


def test_prediction_and_evaluation_overwrite_protection(tmp_path, model_path):
    source = tmp_path / "input.csv"
    write_csv(source, labels=True)
    output = tmp_path / "pred.csv"
    output.write_text("keep me")
    assert invoke(tmp_path, model_path, "predict", source, output) == 2
    assert output.read_text() == "keep me"
    assert invoke(tmp_path, model_path, "predict", source, output, "--overwrite") == 0
    directory = tmp_path / "report"
    directory.mkdir()
    (directory / "summary.md").write_text("keep me")
    assert invoke(tmp_path, model_path, "evaluate", source, directory) == 2
    assert (directory / "summary.md").read_text() == "keep me"
    assert (
        invoke(tmp_path, model_path, "evaluate", source, directory, "--overwrite") == 0
    )
    assert (directory / "metrics.json").is_file()


def test_failed_overwrite_keeps_existing_file(tmp_path, model_path):
    source = tmp_path / "input.csv"
    source.write_text("proto,sport,dport\ntcp,1,80\ntcp,2,80,extra\n")
    output = tmp_path / "out.csv"
    output.write_text("original")
    assert (
        invoke(
            tmp_path,
            model_path,
            "predict",
            source,
            output,
            "--overwrite",
            "--chunk-size",
            "1",
        )
        == 2
    )
    assert output.read_text() == "original"


def test_outputs_cannot_replace_input_model_or_raw_data(tmp_path, model_path):
    source = tmp_path / "input.csv"
    write_csv(source)
    raw = tmp_path / "data/raw/never.csv"
    for target in [source, model_path, raw]:
        assert (
            invoke(tmp_path, model_path, "predict", source, target, "--overwrite") == 2
        )
    assert callable(cli.load_model(model_path).predict)
    assert not raw.exists()


def test_evaluation_metrics_support_and_matrix_order(tmp_path, model_path):
    source = tmp_path / "input.csv"
    frame = write_csv(source, labels=True)
    output = tmp_path / "report"
    assert (
        invoke(tmp_path, model_path, "evaluate", source, output, "--chunk-size", "2")
        == 0
    )
    metrics = json.loads((output / "metrics.json").read_text())
    pred = ["Normal", "DoS", "DoS", "DDoS", "Reconnaissance"]
    assert metrics["accuracy"] == accuracy_score(frame.category, pred)
    assert metrics["balanced_accuracy"] == balanced_accuracy_score(frame.category, pred)
    assert metrics["macro_f1"] == f1_score(
        frame.category, pred, labels=list(TARGETS), average="macro"
    )
    assert metrics["weighted_f1"] == f1_score(frame.category, pred, average="weighted")
    assert metrics["class_order"] == list(TARGETS)
    assert metrics["confusion_matrix"] == [
        [1, 1, 0, 0],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 0, 1],
    ]
    assert metrics["benign_false_positive_rate"] == 0.5
    assert metrics["per_class"]["Normal"]["support"] == 2
    assert metrics["evaluated_records"] == 5
    assert metrics["prediction_throughput_records_per_second"] > 0
    assert {p.name for p in output.iterdir()} == {
        "metrics.json",
        "classification_report.csv",
        "confusion_matrix.csv",
        "predictions.csv",
        "summary.md",
    }


def test_missing_normal_undefined_fpr_and_explicit_absent_classes(tmp_path, model_path):
    source = tmp_path / "input.csv"
    pd.DataFrame(
        {"proto": ["tcp"], "sport": ["2"], "dport": ["80"], "category": ["DoS"]}
    ).to_csv(source, index=False)
    output = tmp_path / "report"
    assert invoke(tmp_path, model_path, "evaluate", source, output) == 0
    metrics = json.loads((output / "metrics.json").read_text())
    assert metrics["benign_false_positive_rate"] is None
    assert metrics["per_class"]["Normal"]["recall"] is None
    assert "Normal" in metrics["absent_classes"]
    assert metrics["macro_f1"] == 0.25
    assert metrics["balanced_accuracy"] == 1


def test_unsupported_labels_fail_or_are_counted_and_preserved(
    tmp_path, model_path, capsys
):
    source = tmp_path / "input.csv"
    pd.DataFrame(
        {
            "proto": ["tcp"] * 3,
            "sport": ["1"] * 3,
            "dport": ["80"] * 3,
            "category": ["Normal", "Theft", "NewAttack"],
        }
    ).to_csv(source, index=False)
    output = tmp_path / "report"
    assert (
        invoke(tmp_path, model_path, "evaluate", source, output, "--chunk-size", "1")
        == 2
    )
    error = capsys.readouterr().err
    assert "'Theft': 1" in error and "'NewAttack': 1" in error
    assert not output.exists()
    assert (
        invoke(
            tmp_path, model_path, "evaluate", source, output, "--exclude-unsupported"
        )
        == 0
    )
    metrics = json.loads((output / "metrics.json").read_text())
    assert metrics["evaluated_records"] == 1 and metrics["excluded_records"] == 2
    assert metrics["excluded_by_label"] == {"Theft": 1, "NewAttack": 1}
    predictions = pd.read_csv(output / "predictions.csv")
    assert len(predictions) == 3
    assert predictions.evaluation_status.tolist() == [
        "evaluated",
        "excluded_unsupported",
        "excluded_unsupported",
    ]


def test_all_excluded_metrics_are_undefined():
    metrics = cli.metrics_from_matrix(np.zeros((4, 4), dtype=np.int64))
    assert metrics["accuracy"] is None and metrics["macro_f1"] is None
    assert metrics["benign_false_positive_rate"] is None


def test_reserved_paths_symlinks_and_hardlinks_are_guarded_without_reading(
    tmp_path, model_path, monkeypatch
):
    # This is a temporary one-row file, never the real official dataset.
    source = tmp_path / cli.OFFICIAL_TEST
    source.parent.mkdir(parents=True)
    write_csv(source, labels=True)
    alias = tmp_path / "alias.csv"
    alias.symlink_to(source)
    hard = tmp_path / "hard.csv"
    os.link(source, hard)

    def forbidden(*args, **kwargs):
        raise AssertionError("protected data must not be read")

    monkeypatch.setattr(cli, "csv_chunks", forbidden)
    for path in [source, alias, hard]:
        assert invoke(tmp_path, model_path, "evaluate", path, tmp_path / "report") == 2
        assert invoke(tmp_path, model_path, "predict", path, tmp_path / "out.csv") == 2
    # Check explicit acknowledgement logic without doing an official evaluation.
    cli.protect_input(source, tmp_path, True)


def test_training_path_warning_and_false_positive_filename(
    tmp_path, model_path, capsys
):
    source = tmp_path / DEFAULT_TRAIN
    source.parent.mkdir(parents=True)
    write_csv(source, labels=True)
    assert invoke(tmp_path, model_path, "evaluate", source, tmp_path / "report") == 0
    assert "not independent" in capsys.readouterr().err
    innocent = tmp_path / "my_Testing.csv"
    write_csv(innocent)
    assert invoke(tmp_path, model_path, "predict", innocent, tmp_path / "out.csv") == 0


def test_output_column_collision_is_not_silent(tmp_path, model_path):
    source = tmp_path / "input.csv"
    frame = write_csv(source)
    frame["prediction"] = "original"
    frame.to_csv(source, index=False)
    assert invoke(tmp_path, model_path, "predict", source, tmp_path / "out.csv") == 2


def test_positive_chunk_size_required(tmp_path, model_path):
    with pytest.raises(SystemExit):
        cli.parser(tmp_path).parse_args(
            [
                "predict",
                "--model",
                str(model_path),
                "--input",
                "a",
                "--output",
                "b",
                "--chunk-size",
                "0",
            ]
        )
