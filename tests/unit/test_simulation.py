"""Synthetic sealed fixtures only. Never open real training/held-out data."""

import csv
import io
import json
import subprocess
import sys
import tracemalloc
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from cyberguard.features import nf_cse as nf
from cyberguard.features.nf_cse_preparation import sha256
from cyberguard.simulation import profiles as p
from cyberguard.simulation.diagnostics import audit_profiles
from cyberguard.simulation.generator import TrafficGenerator
from cyberguard.simulation.schemas import GeneratorConfig
from cyberguard.simulation.serialization import export, write_stream
from cyberguard.simulation.validation import canonical_vector, export_vectors


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "processed"
    (root / "train").mkdir(parents=True)
    (root / "metadata").mkdir()
    # Both labels share one vector, so novelty must ignore the source label.
    x = np.array(
        [
            [6, 1000, 80, 1000, 500, 10, 5],
            [6, 2000, 443, 2000, 0, 20, 0],
            [1, -3, -3, 100, 0, 1, 0],
            [17, -4, 53, 300, 600, 3, 6],
            [6, 1000, 80, 1000, 500, 10, 5],
            [17, 3000, 53, 10000, 20000, 100, 200],
        ],
        dtype=np.int64,
    )
    y = np.array([0, 0, 0, 0, 1, 1], dtype=np.uint8)
    w = np.array([90, 10, 5, 5, 10, 90], dtype=np.uint64)
    np.savez_compressed(
        root / "train/part-00000.npz", features=x, Label=y, multiplicity=w
    )
    p.dump_json(root / "metadata/feature_contract.json", nf.feature_contract())
    artifacts = {
        f: {"bytes": (root / f).stat().st_size, "sha256": sha256(root / f)}
        for f in ("train/part-00000.npz", "metadata/feature_contract.json")
    }
    manifest = {
        "status": "complete",
        "identity": {
            "schema_version": nf.CONTRACT_VERSION,
            "preprocessing_version": nf.PREPROCESSING_VERSION,
            "implementation_sha256": {"nf_cse.py": sha256(nf.__file__)},
        },
        "artifacts": artifacts,
        "plan": {
            "partitions": {
                "train": {
                    "rows": 210,
                    "compact_records": 6,
                    "groups": 5,
                    "binary_counts": {"0": 110, "1": 100},
                },
                "validation": {"poison": "DO_NOT_DECODE"},
                "test": {"poison": "DO_NOT_DECODE"},
            }
        },
    }
    p.dump_json(root / "metadata/split_manifest.json", manifest)
    (root / "metadata/split_manifest.sha256").write_text(
        sha256(root / "metadata/split_manifest.json")
    )
    return root


@pytest.fixture
def profiles(source, tmp_path):
    directory = tmp_path / "profiles"
    p.build_profiles(source, directory)
    return p.Profiles(directory)


def test_profile_build_train_only_weights_and_roundtrip(source, profiles):
    metadata = profiles.metadata
    assert metadata["unique_training_vectors"] == 5
    assert metadata["profile_original_rows"] == {"benign": 110, "attack": 100}
    assert all(
        f.startswith("train/")
        or f
        in {
            "metadata/split_manifest.json",
            "metadata/split_manifest.sha256",
            "metadata/feature_contract.json",
        }
        for f in metadata["opened_source_files"]
    )
    with np.load(source / "train/part-00000.npz") as shard:
        np.testing.assert_array_equal(
            nf.normalize(pd.DataFrame(profiles.vectors, columns=nf.RAW_FEATURES)),
            shard["features"],
        )
        np.testing.assert_array_equal(profiles.weights, shard["multiplicity"])
    assert isinstance(profiles.vectors, np.memmap)


def test_profile_build_is_byte_reproducible(source, profiles, tmp_path):
    second = tmp_path / "second"
    p.build_profiles(source, second)
    assert sha256(second / "metadata.json") == sha256(
        profiles.directory / "metadata.json"
    )
    with pytest.raises(FileExistsError):
        p.build_profiles(source, second)


def test_manifest_skips_heldout_values_before_decoding(monkeypatch):
    original = json.loads

    def guarded(value, *args, **kwargs):
        assert "DO_NOT_DECODE" not in value
        return original(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", guarded)
    text = '{"artifacts":{"validation/a":{"x":"DO_NOT_DECODE"},"test/a":{"x":"DO_NOT_DECODE"},"train/a":{"sha256":"ok"}},"plan":{"partitions":{"validation":{"x":"DO_NOT_DECODE"},"test":{"x":"DO_NOT_DECODE"},"train":{"rows":1}}}}'
    result = p.TrainManifest(io.StringIO(text)).value()
    assert set(result["artifacts"]) == {"train/a"}
    assert set(result["plan"]["partitions"]) == {"train"}


@pytest.mark.parametrize(
    "relative",
    [
        "validation/part.npz",
        "test/part.npz",
        "metadata/class_distribution.json",
        "metadata/preprocessing_manifest.json",
    ],
)
def test_guard_denies_nontraining_reads_even_when_missing(source, relative):
    with p.train_only(source), pytest.raises(PermissionError):
        (source / relative).read_bytes()


def test_guard_denies_raw_and_source_writes(source):
    with p.train_only(source):
        with pytest.raises(PermissionError):
            (source / "train/part-00000.npz").write_bytes(b"bad")
        with pytest.raises(PermissionError):
            (p.ROOT / "data/raw/nonexistent.csv").read_bytes()
    with pytest.raises(ValueError):
        p.check_destination(source / "new", source)


def test_manifest_and_artifact_corruption_fail(source, tmp_path):
    (source / "train/part-00000.npz").write_bytes(b"bad")
    with pytest.raises(ValueError, match="checksum"):
        p.build_profiles(source, tmp_path / "new")
    assert not (tmp_path / "new").exists()
    (source / "metadata/split_manifest.sha256").write_text("bad")
    with pytest.raises(ValueError, match="manifest checksum"):
        p.build_profiles(source, tmp_path / "other")


def test_profile_checksum_validation(profiles):
    with (profiles.directory / "vectors.npy").open("ab") as stream:
        stream.write(b"bad")
    with pytest.raises(ValueError, match="checksum"):
        p.Profiles(profiles.directory)


@pytest.mark.parametrize(
    "column,value",
    [
        (0, -3),
        (0, -1),
        (0, 99),
        (1, -1),
        (1, -2),
        (2, 65536),
        (3, -1),
        (3, nf.MAX_COUNTER + 1),
    ],
)
def test_unexportable_canonical_vectors_fail(column, value):
    x = np.array([[6, 1000, 80, 1000, 500, 10, 5]], dtype=np.int64)
    x[0, column] = value
    with pytest.raises(ValueError):
        export_vectors(x)


def test_reproducibility_seed_isolation(profiles):
    config = GeneratorConfig(count=100, seed=17, mode="synthetic")
    np.random.seed(123)
    state = np.random.get_state()
    first = list(TrafficGenerator(profiles, config))
    after = np.random.get_state()
    assert (
        state[0] == after[0]
        and np.array_equal(state[1], after[1])
        and state[2:] == after[2:]
    )
    assert first == list(TrafficGenerator(profiles, config))
    assert first != list(
        TrafficGenerator(
            profiles, GeneratorConfig(count=100, seed=18, mode="synthetic")
        )
    )


def test_multiplicity_weighted_sampling(profiles):
    records = list(
        TrafficGenerator(profiles, GeneratorConfig(count=20000, benign_ratio=1, seed=8))
    )
    # A compact-row-uniform sampler would yield .25 rather than 90/110.
    fraction = sum(r["record"]["L4_SRC_PORT"] == 1000 for r in records) / len(records)
    assert abs(fraction - 90 / 110) < 0.015


@pytest.mark.parametrize("mode", ["empirical", "synthetic"])
@pytest.mark.parametrize("ratio", [0, 1, 0.3333, 0.5])
def test_schema_composition_and_counters(profiles, mode, ratio):
    config = GeneratorConfig(count=101, benign_ratio=ratio, mode=mode)
    rows = list(TrafficGenerator(profiles, config))
    assert (
        sum(r["simulation"]["source_profile"] == "benign" for r in rows)
        == config.benign_count
    )
    assert [r["simulation"]["sequence"] for r in rows] == list(range(101))
    for item in rows:
        record = item["record"]
        assert tuple(record) == nf.RAW_FEATURES
        assert all(type(v) is int for v in record.values())
        assert all(0 <= record[c] <= nf.MAX_COUNTER for c in nf.COUNTERS)
        assert 0 <= record["PROTOCOL"] <= 255
        assert all(-1 <= record[c] <= 65535 for c in nf.PORTS)
        if mode == "empirical":
            assert any(
                np.array_equal(list(record.values()), row) for row in profiles.vectors
            )
        else:
            assert (record["OUT_BYTES"] == 0) == (record["OUT_PKTS"] == 0)
            if record["L4_SRC_PORT"] == 3000:  # UDP attack anchor only.
                assert abs(record["OUT_BYTES"] / record["IN_BYTES"] - 2) < 0.002


def test_filters_fail_closed_and_sentinel(profiles):
    config = GeneratorConfig(count=100, protocols=(17,), destination_ports=(53,))
    rows = list(TrafficGenerator(profiles, config))
    assert all(
        r["record"]["PROTOCOL"] == 17 and r["record"]["L4_DST_PORT"] == 53 for r in rows
    )
    assert any(r["record"]["L4_SRC_PORT"] == -1 for r in rows)
    for config in (
        GeneratorConfig(protocols=(58,)),
        GeneratorConfig(destination_ports=(9999,)),
        GeneratorConfig(protocols=(1,), destination_ports=(0,)),
    ):
        with pytest.raises(ValueError, match="No .* support"):
            TrafficGenerator(profiles, config)
    # No attack ICMP support is needed for a benign-only request.
    assert (
        len(
            list(
                TrafficGenerator(
                    profiles, GeneratorConfig(count=10, benign_ratio=1, protocols=(1,))
                )
            )
        )
        == 10
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"count": 0},
        {"count": -1},
        {"count": True},
        {"seed": -1},
        {"benign_ratio": float("nan")},
        {"benign_ratio": 1.1},
        {"mode": "gan"},
        {"protocols": (256,)},
        {"protocols": (True,)},
        {"destination_ports": (-1,)},
        {"perturbation": 0},
        {"perturbation": 0.3},
    ],
)
def test_invalid_configuration(kwargs):
    with pytest.raises(ValueError):
        GeneratorConfig(**kwargs)


@pytest.mark.parametrize("format", ["csv", "jsonl"])
@pytest.mark.parametrize("metadata", [False, True])
def test_streaming_serialization(profiles, tmp_path, format, metadata):
    path = tmp_path / f"records.{format}"
    export(
        TrafficGenerator(profiles, GeneratorConfig(count=20)), path, format, metadata
    )
    if format == "csv":
        with path.open() as f:
            rows = list(csv.DictReader(f))
        assert set(rows[0]) == set(nf.RAW_FEATURES) | (
            {
                "simulation_" + k
                for k in (
                    "mode",
                    "source_profile",
                    "sequence",
                    "generator_version",
                    "profile_version",
                )
            }
            if metadata
            else set()
        )
    else:
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        assert set(rows[0]) == (
            {"record", "simulation"} if metadata else set(nf.RAW_FEATURES)
        )
    assert len(rows) == 20
    assert json.loads(Path(str(path) + ".simulation.json").read_text())["records"] == 20
    with pytest.raises(FileExistsError):
        export(
            TrafficGenerator(profiles, GeneratorConfig(count=20)),
            path,
            format,
            metadata,
        )


def test_incremental_memory_does_not_scale_with_count(profiles):
    tracemalloc.start()
    generator = TrafficGenerator(profiles, GeneratorConfig(count=10**9))
    assert iter(generator) is generator
    for _ in range(100):
        next(generator)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 2_000_000

    class Sink:
        def write(self, text):
            return len(text)

    tracemalloc.start()
    assert (
        write_stream(TrafficGenerator(profiles, GeneratorConfig(count=10000)), Sink())
        == 10000
    )
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 2_000_000


def test_diagnostics_full_training_membership(profiles):
    result = audit_profiles(profiles, count=100, seed=1)
    for name in ("benign", "attack"):
        modes = result["profiles"][name]["modes"]
        assert modes["empirical"]["novel_rate_all_training"] == 0
        assert modes["synthetic"]["novel_rate_all_training"] > 0
        for mode in modes.values():
            assert mode["invalid_rate"] == 0
            assert mode["source_composition"] == {name: 100}
    with profiles.membership() as connection:
        record = dict(zip(nf.RAW_FEATURES, map(int, profiles.vectors[2]), strict=True))
        assert connection.execute(
            "SELECT 1 FROM vectors WHERE key=?", (canonical_vector(record).tobytes(),)
        ).fetchone()


def test_cli_end_to_end(source, tmp_path):
    root = Path(__file__).resolve().parents[2]
    output = tmp_path / "cli-profiles"

    def run(script, *args):
        return subprocess.run(
            [sys.executable, str(root / "scripts" / script), *map(str, args)],
            check=False,
            capture_output=True,
            text=True,
            cwd=root,
        )

    for script in ("build_traffic_profiles.py", "generate_traffic.py"):
        assert run(script, "--help").returncode == 0
    built = run(
        "build_traffic_profiles.py",
        "--processed-dir",
        source,
        "--output-dir",
        output,
        "--audit-count",
        20,
        "--audit-report",
        tmp_path / "audit.json",
    )
    assert built.returncode == 0, built.stderr
    generated = run(
        "generate_traffic.py",
        "--profiles",
        output,
        "--count",
        15,
        "--attack-ratio",
        1,
        "--mode",
        "synthetic",
        "--metadata",
        "--output",
        tmp_path / "cli.jsonl",
    )
    assert generated.returncode == 0, generated.stderr
    assert json.loads(generated.stdout)["attack_profile_records"] == 15
    rounded = run(
        "generate_traffic.py",
        "--profiles",
        output,
        "--count",
        5,
        "--attack-ratio",
        0.9,
        "--output",
        tmp_path / "rounding.jsonl",
    )
    assert rounded.returncode == 0, rounded.stderr
    assert json.loads(rounded.stdout)["benign_records"] == 1
    invalid = run("generate_traffic.py", "--attack-ratio", 1.1)
    assert invalid.returncode == 2


def test_empty_partition_fails(source, tmp_path):
    path = source / "metadata/split_manifest.json"
    # Fixture metadata only; no real partitions accessed.
    manifest = json.loads(path.read_text())
    manifest["plan"]["partitions"]["train"]["compact_records"] = 0
    p.dump_json(path, manifest)
    (source / "metadata/split_manifest.sha256").write_text(sha256(path))
    with pytest.raises(ValueError, match="Empty"):
        p.build_profiles(source, tmp_path / "empty")


def test_synthetic_counter_boundaries_and_structural_zeros():
    from types import SimpleNamespace

    profiles = SimpleNamespace(
        vectors=np.array([[6, 1, 2, nf.MAX_COUNTER, 0, 1, 0]], dtype=np.int64),
        labels=np.array([0]),
        weights=np.array([1], dtype=np.uint64),
    )
    generator = TrafficGenerator(
        profiles,
        GeneratorConfig(count=100, benign_ratio=1, mode="synthetic", perturbation=0.25),
    )
    for item in generator:
        record = item["record"]
        assert 0 < record["IN_BYTES"] <= nf.MAX_COUNTER
        assert record["IN_PKTS"] == 1
        assert record["OUT_BYTES"] == record["OUT_PKTS"] == 0


def test_weight_lookup_avoids_full_cdf_dtype_conversion(profiles, monkeypatch):
    original = np.searchsorted

    def checked(array, value, *args, **kwargs):
        assert array.dtype == np.uint64 and isinstance(value, np.uint64)
        return original(array, value, *args, **kwargs)

    monkeypatch.setattr(np, "searchsorted", checked)
    next(TrafficGenerator(profiles, GeneratorConfig()))


def test_synthetic_uses_same_conditional_anchors_and_composition(profiles):
    empirical = list(TrafficGenerator(profiles, GeneratorConfig(count=100, seed=21)))
    synthetic = list(
        TrafficGenerator(
            profiles, GeneratorConfig(count=100, seed=21, mode="synthetic")
        )
    )
    for a, b in zip(empirical, synthetic, strict=True):
        assert a["simulation"]["source_profile"] == b["simulation"]["source_profile"]
        for key in nf.RAW_FEATURES[:3]:
            assert a["record"][key] == b["record"][key]
        for key in nf.COUNTERS:
            assert (a["record"][key] == 0) == (b["record"][key] == 0)


def test_one_empty_source_profile_fails(source, tmp_path):
    shard = source / "train/part-00000.npz"
    with np.load(shard, allow_pickle=False) as data:
        x, w = data["features"], data["multiplicity"]
    np.savez_compressed(
        shard, features=x, multiplicity=w, Label=np.zeros(len(x), dtype=np.uint8)
    )
    path = source / "metadata/split_manifest.json"
    m = json.loads(path.read_text())
    m["artifacts"]["train/part-00000.npz"] = {
        "sha256": sha256(shard),
        "bytes": shard.stat().st_size,
    }
    m["plan"]["partitions"]["train"]["binary_counts"] = {"0": 210, "1": 0}
    p.dump_json(path, m)
    (source / "metadata/split_manifest.sha256").write_text(sha256(path))
    with pytest.raises(ValueError, match="Empty profile"):
        p.build_profiles(source, tmp_path / "missing-attack")


def test_large_count_composition_near_half_boundary():
    from decimal import ROUND_HALF_UP, Decimal, localcontext

    numerator, denominator = 12345678901234567, 10**17
    count = (
        (denominator // 2 - 1) * pow(numerator, -1, denominator)
    ) % denominator + 90 * denominator
    config = GeneratorConfig(count=count, benign_ratio=0.12345678901234567)
    with localcontext() as context:
        context.prec = 100
        exact = int(
            (Decimal(str(config.benign_ratio)) * count).quantize(
                Decimal(1), rounding=ROUND_HALF_UP
            )
        )
    assert config.benign_count == exact
