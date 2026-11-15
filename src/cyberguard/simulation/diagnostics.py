"""Deterministic training-only diagnostics; no inference or test metrics."""

import math
import resource
import time
from collections import Counter

import numpy as np

from cyberguard.core.model_schemas import NFCompletedFlowRecord
from cyberguard.features import nf_cse as nf
from cyberguard.simulation.generator import TrafficGenerator
from cyberguard.simulation.schemas import GeneratorConfig
from cyberguard.simulation.validation import canonical_vector


def correlation(values, weights=None):
    x = np.asarray(values, dtype=float)
    if weights is None:
        weights = np.ones(len(x))
    mean = np.average(x, axis=0, weights=weights)
    covariance = ((x - mean) * weights[:, None]).T @ (x - mean) / weights.sum()
    scales = np.sqrt(np.diag(covariance))
    with np.errstate(invalid="ignore", divide="ignore"):
        result = covariance / scales[:, None] / scales[None, :]
    return [[float(v) if np.isfinite(v) else None for v in row] for row in result]


def describe(values):
    result = {}
    for i, name in enumerate(nf.RAW_FEATURES):
        column = values[:, i]
        if i < 3:
            counts = Counter(map(int, column))
            result[name] = {"unique": len(counts), "top_10": counts.most_common(10)}
        else:
            result[name] = {
                "mean": float(column.mean()),
                "quantiles_p0_p50_p90_p99_p100": np.quantile(
                    column, [0, 0.5, 0.9, 0.99, 1]
                ).tolist(),
            }
    result["counter_correlation_order"] = list(nf.COUNTERS)
    result["counter_pearson"] = correlation(values[:, 3:])
    return result


def audit_profiles(profiles, count=5000, seed=20261115):
    if type(count) is not int or not 1 <= count <= 100000:
        raise ValueError("Diagnostic sample count must be in 1..100000 (bounded audit)")
    started = time.perf_counter()
    result = {
        "sample_count_per_mode_profile": count,
        "seed": seed,
        "reference": "Full multiplicity-weighted protocol/port histograms, counter means and Pearson correlations; separate deterministic weighted training bootstrap for counter quantiles/correlation sampling variability. Paired anchors isolate perturbation from anchor sampling variance. Novelty is exact membership against ALL training vectors, irrespective of source label.",
        "profiles": {},
    }
    with profiles.membership() as membership:
        for label, name in enumerate(("benign", "attack")):
            reference_gen = TrafficGenerator(
                profiles,
                GeneratorConfig(count=count, benign_ratio=1 - label, seed=seed),
            )
            reference = np.array(
                [list(item["record"].values()) for item in reference_gen],
                dtype=np.int64,
            )
            entry = {
                "weighted_training_reference_sample": describe(reference),
                "modes": {},
            }
            histograms = [Counter(), Counter(), Counter()]
            for start in range(0, len(profiles.labels), 50000):
                stop = start + 50000
                mask = profiles.labels[start:stop] == label
                values, weights = (
                    profiles.vectors[start:stop][mask],
                    profiles.weights[start:stop][mask],
                )
                for col in range(3):
                    keys, inverse = np.unique(values[:, col], return_inverse=True)
                    sums = np.bincount(inverse, weights=weights.astype(float))
                    histograms[col].update(
                        {int(k): int(v) for k, v in zip(keys, sums, strict=True)}
                    )
            mass = profiles.metadata["profile_original_rows"][name]
            total_weight, first_moment, second_moment = (
                0.0,
                np.zeros(4),
                np.zeros((4, 4)),
            )
            for start in range(0, len(profiles.labels), 50000):
                stop = start + 50000
                mask = profiles.labels[start:stop] == label
                counters = profiles.vectors[start:stop][mask, 3:].astype(float)
                weights = profiles.weights[start:stop][mask].astype(float)
                total_weight += weights.sum()
                first_moment += (counters * weights[:, None]).sum(axis=0)
                second_moment += counters.T @ (counters * weights[:, None])
            mean = first_moment / total_weight
            covariance = second_moment / total_weight - np.outer(mean, mean)
            scales = np.sqrt(np.maximum(0, np.diag(covariance)))
            with np.errstate(invalid="ignore", divide="ignore"):
                corr = covariance / scales[:, None] / scales[None, :]
            entry["full_weighted_counter_means"] = dict(
                zip(nf.COUNTERS, map(float, mean), strict=True)
            )
            entry["full_weighted_counter_pearson"] = [
                [float(v) if np.isfinite(v) else None for v in row] for row in corr
            ]
            paired = TrafficGenerator(
                profiles,
                GeneratorConfig(count=count, benign_ratio=1 - label, seed=seed + 1),
            )
            paired_anchors = np.array(
                [list(item["record"].values()) for item in paired], dtype=np.int64
            )
            entry["paired_anchor_reference"] = describe(paired_anchors)
            entry["full_training_discrete"] = {
                nf.RAW_FEATURES[i]: {"unique": len(h), "top_10": h.most_common(10)}
                for i, h in enumerate(histograms)
            }
            for mode in ("empirical", "synthetic"):
                generator = TrafficGenerator(
                    profiles,
                    GeneratorConfig(
                        count=count, benign_ratio=1 - label, mode=mode, seed=seed + 1
                    ),
                )
                rows, composition, invalid = [], Counter(), 0
                novel = 0
                seen = set()
                for item in generator:
                    record = item["record"]
                    try:
                        NFCompletedFlowRecord.model_validate(record)
                    except ValueError:
                        invalid += 1
                    rows.append(list(record.values()))
                    composition[item["simulation"]["source_profile"]] += 1
                    key = canonical_vector(record).tobytes()
                    novel += (
                        membership.execute(
                            "SELECT 1 FROM vectors WHERE key=?", (key,)
                        ).fetchone()
                        is None
                    )
                    seen.add(key)
                rows = np.asarray(rows, dtype=np.int64)
                detail = describe(rows)
                detail.update(
                    invalid_rate=invalid / count,
                    duplicate_rate=1 - len(seen) / count,
                    novel_rate_all_training=novel / count,
                    source_composition=dict(composition),
                )
                detail["discrete_total_variation_vs_full_training"] = {}
                for col, h in enumerate(histograms):
                    got = Counter(map(int, rows[:, col]))
                    tv = 0.5 * sum(
                        abs(got[k] / count - h[k] / mass) for k in h.keys() | got.keys()
                    )
                    detail["discrete_total_variation_vs_full_training"][
                        nf.RAW_FEATURES[col]
                    ] = tv
                # Sample-based correlation comparisons are descriptive, no realism gate.
                ref_corr = correlation(reference[:, 3:])
                gen_corr = detail["counter_pearson"]
                deltas = [
                    abs(a - b)
                    for ra, rb in zip(ref_corr, gen_corr, strict=True)
                    for a, b in zip(ra, rb, strict=True)
                    if a is not None and b is not None
                ]
                detail["max_counter_correlation_difference_vs_reference_sample"] = (
                    max(deltas) if deltas else None
                )
                anchor_corr = entry["paired_anchor_reference"]["counter_pearson"]
                detail["max_counter_correlation_difference_vs_paired_anchors"] = max(
                    (
                        abs(a - b)
                        for ra, rb in zip(anchor_corr, gen_corr, strict=True)
                        for a, b in zip(ra, rb, strict=True)
                        if a is not None and b is not None
                    ),
                    default=None,
                )
                detail["max_counter_correlation_difference_vs_full_training"] = max(
                    (
                        abs(a - b)
                        for ra, rb in zip(
                            entry["full_weighted_counter_pearson"],
                            gen_corr,
                            strict=True,
                        )
                        for a, b in zip(ra, rb, strict=True)
                        if a is not None and b is not None
                    ),
                    default=None,
                )
                entry["modes"][mode] = detail
            result["profiles"][name] = entry
    elapsed = time.perf_counter() - started
    result["audit_seconds"] = elapsed
    result["peak_rss_mib_linux"] = (
        resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    )
    if not math.isfinite(elapsed):
        raise RuntimeError("Invalid timer")
    return result
