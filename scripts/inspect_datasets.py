"""Read-only, chunked EDA. No preprocessing artifacts or models are produced.

Run: .venv/bin/python scripts/inspect_datasets.py
Only pandas/numpy and the standard library are required. Exact duplicate checks use
SQLite on disk; quantiles, histograms and outlier rates use a seeded uniform sample.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import resource
import sqlite3
import tempfile
import time
from collections import Counter, defaultdict
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "bot_iot": {
        "train": "data/raw/bot_iot/train/UNSW_2018_IoT_Botnet_Final_10_best_Training.csv",
        "test": "data/raw/bot_iot/test/UNSW_2018_IoT_Botnet_Final_10_best_Testing.csv",
    },
    "dns_threats": {
        "train": "data/raw/dns_threats/train_combined_multiclass.csv",
        "test": "data/raw/dns_threats/test_combined_multiclass.csv",
    },
}
LABELS = {"bot_iot": ["attack", "category", "subcategory"], "dns_threats": ["class"]}
NUMERIC = [
    "pkSeqID",
    "seq",
    "stddev",
    "N_IN_Conn_P_SrcIP",
    "min",
    "state_number",
    "mean",
    "N_IN_Conn_P_DstIP",
    "drate",
    "srate",
    "max",
]
PORTS = ["sport", "dport"]


def table(headers, rows):
    def cell(x):
        return str(x).replace("|", "\\|").replace("\n", " ")

    return "\n".join(
        [
            "| " + " | ".join(map(cell, headers)) + " |",
            "| " + " | ".join(["---"] * len(headers)) + " |",
        ]
        + ["| " + " | ".join(map(cell, row)) + " |" for row in rows]
    )


def fmt(x):
    if x is None or not np.isfinite(x):
        return "undefined"
    return f"{x:.6g}"


def svg_bars(path, title, names, series):
    """Dependency-free accessible SVG; bar widths are log1p(count)."""
    width, height = 1080, 100 + len(names) * 65
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" role="img">',
        f'<title>{html.escape(title)}</title><rect width="100%" height="100%" fill="white"/>',
        f'<g font-family="sans-serif" font-size="13"><text x="20" y="25">{html.escape(title)}</text>',
        '<text x="20" y="48">Width: log(1 + count). Labels: exact count (percent within split).</text>',
    ]
    largest = max((v for _, counts, _ in series for v in counts), default=1)
    for i, name in enumerate(names):
        y = 80 + i * 65
        parts.append(f'<text x="10" y="{y + 12}">{html.escape(str(name))}</text>')
        for j, (split, counts, total) in enumerate(series):
            value = counts[i]
            bar = 500 * np.log1p(value) / max(np.log1p(largest), 1)
            yy = y + j * 23
            color = ["#2563eb", "#e87924"][j]
            parts.append(
                f'<rect x="220" y="{yy}" width="{bar:.2f}" height="18" fill="{color}"/>'
            )
            parts.append(
                f'<text x="{730}" y="{yy + 14}">{split}: {value:,} ({100 * value / max(total, 1):.5f}%)</text>'
            )
    path.write_text("".join(parts) + "</g></svg>")


def hist_svg(path, title, samples, columns):
    w, panel_h = 1000, 220
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{60 + panel_h * len(columns)}" role="img">',
        f'<title>{html.escape(title)}</title><rect width="100%" height="100%" fill="white"/>',
        '<g font-family="sans-serif" font-size="12">',
        f'<text x="20" y="25">{html.escape(title)}</text>',
        '<text x="20" y="45">Uniform sampled rows; signed log1p x-axis, fraction per split y-axis. Blue=train; orange=test.</text>',
    ]
    for k, col in enumerate(columns):
        yy = 65 + k * panel_h
        vals = {
            s: pd.to_numeric(df[col], errors="coerce").to_numpy(dtype=float)
            for s, df in samples.items()
        }
        vals = {
            s: np.sign(v[np.isfinite(v)]) * np.log1p(np.abs(v[np.isfinite(v)]))
            for s, v in vals.items()
        }
        both = np.concatenate(list(vals.values()))
        if not len(both):
            continue
        edges = np.histogram_bin_edges(both, bins=35)
        counts = {
            s: np.histogram(v, edges)[0] / max(len(v), 1) for s, v in vals.items()
        }
        ymax = max(max(c) for c in counts.values()) or 1
        parts.append(
            f'<text x="20" y="{yy + 12}">{html.escape(col)} (max bin fraction={ymax:.3g})</text>'
        )
        for j, (_, c) in enumerate(counts.items()):
            for i, value in enumerate(c):
                h = 135 * value / ymax
                parts.append(
                    f'<rect x="{80 + i * 24 + j * 10}" y="{yy + 155 - h:.2f}" width="10" height="{h:.2f}" fill="{["#2563eb", "#e87924"][j]}" opacity=".8"/>'
                )
        parts.append(
            f'<text x="80" y="{yy + 177}">{edges[0]:.4g}</text><text x="820" y="{yy + 177}">{edges[-1]:.4g}</text>'
        )
    path.write_text("".join(parts) + "</g></svg>")


class Moments:
    """Merge central moments rather than subtracting large raw powers."""

    def __init__(self):
        self.n = 0
        self.mean = self.m2 = self.m3 = 0.0
        self.low, self.high = np.inf, -np.inf
        self.integer = True

    def add(self, values):
        a = values[np.isfinite(values)]
        n = len(a)
        if not n:
            return
        mean = float(a.mean())
        delta = mean - self.mean
        centered = a - mean
        m2, m3 = float(np.sum(centered**2)), float(np.sum(centered**3))
        total = self.n + n
        self.m3 += (
            m3
            + delta**3 * self.n * n * (self.n - n) / total**2
            + 3 * delta * (self.n * m2 - n * self.m2) / total
        )
        self.m2 += m2 + delta**2 * self.n * n / total
        self.mean += delta * n / total
        self.n = total
        self.low, self.high = (
            min(self.low, float(a.min())),
            max(self.high, float(a.max())),
        )
        self.integer &= bool(np.all(a == np.floor(a)))

    def result(self):
        return {
            "finite": self.n,
            "integer_valued": self.integer,
            "mean": self.mean,
            "std": np.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else None,
            "min": self.low,
            "max": self.high,
            "skew_population": np.sqrt(self.n) * self.m3 / self.m2**1.5
            if self.m2 > 0
            else None,
        }


def digest_rows(frame):
    # JSON gives unambiguous field boundaries; preserve raw CSV field strings.
    return [
        hashlib.sha256(
            json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode()
        ).digest()
        for row in frame.itertuples(index=False, name=None)
    ]


def port_number(value):
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        return np.nan


def scan(name, split, path, db, chunk_size, sample_size):
    labels = LABELS[name]
    result = {
        "path": str(path.relative_to(ROOT)),
        "file_bytes": path.stat().st_size,
        "rows": 0,
        "memory_bytes": 0,
        "peak_chunk_bytes": 0,
        "missing": Counter(),
        "infinite": Counter(),
        "invalid": Counter(),
        "invalid_examples": defaultdict(set),
        "classes": defaultdict(Counter),
        "categorical": defaultdict(Counter),
        "dtype_observations": defaultdict(set),
        "cross": defaultdict(Counter),
        "dns_structure": defaultdict(Counter),
        "dns_suffixes": defaultdict(Counter),
        "rules": Counter(),
    }
    moments = defaultdict(Moments)
    rng = np.random.default_rng(20261115 + (split == "test"))
    sample = None
    candidates, balances = {}, {}
    corr_n = corr_sum = corr_sq = corr_product = None
    started = time.monotonic()
    for chunk in pd.read_csv(
        path, chunksize=chunk_size, dtype=str, keep_default_na=False
    ):
        if "columns" not in result:
            result["columns"] = list(chunk.columns)
            if not set(labels) <= set(chunk.columns):
                raise ValueError(f"Missing labels in {path}")
            numeric = [c for c in NUMERIC if c in chunk] if name == "bot_iot" else []
            result["numeric"] = numeric
            features = [c for c in chunk if c not in labels]
            operational = [c for c in features if c not in ("pkSeqID", "seq")]
            result["features"], result["operational_features"] = features, operational
        n = len(chunk)
        result["rows"] += n
        mem = int(chunk.memory_usage(index=False, deep=True).sum())
        result["memory_bytes"] += mem
        result["peak_chunk_bytes"] = max(result["peak_chunk_bytes"], mem)
        for c in chunk:
            result["dtype_observations"][c].add(str(chunk[c].dtype))
            missing = chunk[c].str.strip().eq("")
            if c in numeric or c in labels and c in ("attack", "class"):
                missing |= (
                    chunk[c].str.lower().isin(["nan", "na", "null", "none", "n/a"])
                )
            result["missing"][c] += int(missing.sum())
            if c in labels:
                result["classes"][c].update(chunk[c])
            if (c not in numeric or c == "state_number") and c != "domain":
                result["categorical"][c].update(chunk[c])
        arrays = {}
        for c in numeric + (["sport", "dport"] if name == "bot_iot" else []):
            raw = chunk[c]
            a = (
                raw.map(port_number)
                if c in PORTS
                else pd.to_numeric(raw, errors="coerce")
            ).to_numpy(dtype=float)
            result["infinite"][c] += int(np.isinf(a).sum())
            missing = raw.str.strip().eq("") | raw.str.lower().isin(
                ["nan", "na", "null", "none", "n/a"]
            )
            bad = np.isnan(a) & ~missing.to_numpy()
            if c in PORTS:
                # Argus ICMP ports may contain type/code hex and '-' is a special token.
                special = raw.eq("-").to_numpy()
                result["rules"][f"{c}: special '-' (not numeric)"] += int(special.sum())
                bad &= ~special
                range_bad = np.isfinite(a) & ((a < 0) | (a > 65535))
            else:
                range_bad = np.isfinite(a) & (a < 0)
            bad |= range_bad
            result["invalid"][c] += int(bad.sum())
            result["invalid_examples"][c].update(raw[bad].unique()[:5])
            moments[c].add(a)
            if c in numeric:
                arrays[c] = a
            # Weighted Boyer-Moore finds any >50% majority exactly; count in second pass.
            counts = raw.value_counts()
            candidate, balance = candidates.get(c), balances.get(c, 0)
            for value, count in counts.items():
                if value == candidate:
                    balance += count
                elif count > balance:
                    candidate, balance = value, count - balance
                else:
                    balance -= count
            candidates[c], balances[c] = candidate, balance
        if name == "bot_iot":
            for c in ["saddr", "daddr"]:
                invalid_ips = []
                for value in chunk[c].unique():
                    try:
                        ipaddress.ip_address(value)
                    except ValueError:
                        invalid_ips.append(value)
                result["invalid"][c] += int(chunk[c].isin(invalid_ips).sum())
                result["invalid_examples"][c].update(invalid_ips[:5])
            for c in PORTS:
                for token in ["-1", "-"]:
                    for proto, count in (
                        chunk.loc[chunk[c].eq(token), "proto"].value_counts().items()
                    ):
                        result["rules"][f"{c}: token {token} with proto={proto}"] += (
                            int(count)
                        )
                result["rules"][f"{c}: hexadecimal tokens"] += int(
                    chunk[c].str.startswith("0x").sum()
                )
            result["invalid"]["attack"] += int((~chunk.attack.isin(["0", "1"])).sum())
            result["rules"]["min > mean"] += int(
                (arrays["min"] > arrays["mean"] + 1e-6).sum()
            )
            result["rules"]["mean > max"] += int(
                (arrays["mean"] > arrays["max"] + 1e-6).sum()
            )
            result["rules"]["attack/category inconsistency"] += int(
                (chunk.attack.eq("0") != chunk.category.str.lower().eq("normal")).sum()
            )
            for c in ["proto", "saddr", "daddr", "state_number"]:
                result["cross"][c].update(zip(chunk[c], chunk.category))
            x = np.column_stack([arrays[c] for c in numeric])
            valid = np.isfinite(x).astype(float)
            z = np.where(np.isfinite(x), x, 0.0)
            if corr_n is None:
                p = len(numeric)
                corr_n, corr_sum, corr_sq, corr_product = [
                    np.zeros((p, p)) for _ in range(4)
                ]
            corr_n += valid.T @ valid
            corr_sum += z.T @ valid
            corr_sq += (z * z).T @ valid
            corr_product += z.T @ z
        else:
            domain = chunk.domain
            rules = {
                "domain: empty": domain.eq(""),
                "domain: whitespace": domain.str.contains(r"\s", regex=True),
                "domain: non-ASCII": domain.map(lambda s: not s.isascii()),
                "domain: outside ASCII letters/digits/dot/hyphen/underscore": domain.str.contains(
                    r"[^A-Za-z0-9._-]", regex=True
                ),
                "domain: >253 characters": domain.str.len() > 253,
                "domain: any label >63 characters": domain.map(
                    lambda s: any(len(v) > 63 for v in s.rstrip(".").split("."))
                ),
                "domain: no dot (single label / possibly stripped name)": ~domain.str.contains(
                    ".", regex=False
                ),
                "domain: uppercase": domain.str.contains(r"[A-Z]", regex=True),
                "domain: empty interior label": domain.str.contains("..", regex=False)
                | domain.str.startswith("."),
                "class: not nonnegative integer": ~chunk["class"].str.fullmatch(r"\d+"),
            }
            for rule, mask in rules.items():
                result["rules"][rule] += int(mask.sum())
            result["invalid"]["class"] += int(
                rules["class: not nonnegative integer"].sum()
            )
            for label, group in chunk.groupby("class", sort=False):
                names = group.domain
                structure = result["dns_structure"][label]
                structure["rows"] += len(group)
                structure["no_dot"] += int(
                    (~names.str.contains(".", regex=False)).sum()
                )
                structure["length_sum"] += int(names.str.len().sum())
                structure["overlong_label"] += int(
                    names.map(
                        lambda value: any(
                            len(v) > 63 for v in value.rstrip(".").split(".")
                        )
                    ).sum()
                )
                result["dns_suffixes"][label].update(
                    names.map(
                        lambda value: (
                            value.rsplit(".", 1)[-1]
                            if "." in value
                            else "<single label>"
                        )
                    )
                )
            moments["domain_length (EDA only)"].add(
                domain.str.len().to_numpy(dtype=float)
            )
        y = [
            json.dumps(row, separators=(",", ":"))
            for row in chunk[labels].itertuples(index=False, name=None)
        ]
        for view, cols in [("raw", features), ("operational", operational)]:
            if view == "operational" and features == operational:
                continue
            keys = (
                chunk.domain.tolist()
                if name == "dns_threats"
                else digest_rows(chunk[cols])
            )
            grouped = Counter(zip(keys, y))
            db.executemany(
                f"INSERT INTO {view} VALUES (?,?,?,?) ON CONFLICT(s,x,y) DO UPDATE SET n=n+excluded.n",
                [(split, key, label, count) for (key, label), count in grouped.items()],
            )
        db.commit()
        # Keep globally smallest random priorities: uniform sample without replacement.
        part = chunk.copy()
        part["__priority"] = rng.random(n)
        sample = (
            part if sample is None else pd.concat([sample, part], ignore_index=True)
        )
        sample = sample.nsmallest(sample_size, "__priority")
        if result["rows"] % (chunk_size * 10) == 0:
            print(f"  {name}/{split}: {result['rows']:,} rows", flush=True)
    if sample is None:
        raise ValueError(f"Empty dataset: {path}")
    majority_counts = Counter()
    # Exact second pass for near-constant numerical token frequency.
    if candidates:
        for chunk in pd.read_csv(
            path,
            chunksize=chunk_size,
            dtype=str,
            keep_default_na=False,
            usecols=list(candidates),
        ):
            for c, value in candidates.items():
                majority_counts[c] += int(chunk[c].eq(value).sum())
    result["near_constant_numeric"] = {
        c: {"value": candidates[c], "count": v, "percent": 100 * v / result["rows"]}
        for c, v in majority_counts.items()
        if v / result["rows"] >= 0.99
    }
    result["statistics"] = {c: m.result() for c, m in moments.items()}
    result["sample_rows"] = len(sample)
    for c, stats in result["statistics"].items():
        a = (
            sample.domain.str.len().to_numpy(dtype=float)
            if c.startswith("domain_length")
            else (
                sample[c].map(port_number).to_numpy(dtype=float)
                if c in PORTS
                else pd.to_numeric(sample[c], errors="coerce").to_numpy(dtype=float)
            )
        )
        a = a[np.isfinite(a)]
        if len(a):
            q = np.quantile(a, [0.01, 0.25, 0.5, 0.75, 0.99])
            iqr = q[3] - q[1]
            stats.update(
                dict(
                    zip(
                        [
                            "p01_sample",
                            "q25_sample",
                            "median_sample",
                            "q75_sample",
                            "p99_sample",
                        ],
                        map(float, q),
                    )
                )
            )
            stats["extreme_3iqr_sample_percent"] = (
                float(100 * np.mean((a < q[1] - 3 * iqr) | (a > q[3] + 3 * iqr)))
                if iqr > 0
                else None
            )
    if corr_n is not None:
        with np.errstate(divide="ignore", invalid="ignore"):
            cov = corr_product - corr_sum * corr_sum.T / corr_n
            variance = corr_sq - corr_sum**2 / corr_n
            corr = cov / np.sqrt(np.maximum(variance, 0) * np.maximum(variance.T, 0))
        result["correlation"] = pd.DataFrame(corr, index=numeric, columns=numeric)
    result["seconds"] = time.monotonic() - started
    result["sample"] = sample.drop(columns="__priority")
    print(
        f"  {name}/{split}: finished {result['rows']:,} rows in {result['seconds']:.1f}s",
        flush=True,
    )
    return result


def audit(db, view):
    """Never join raw train/test rows: only aggregate feature/label signatures."""
    r = {}
    for split in ["train", "test"]:
        r[f"{split}_duplicate_excess"] = db.execute(
            f"SELECT coalesce(sum(n-1),0) FROM {view} WHERE s=?", (split,)
        ).fetchone()[0]
        r[f"{split}_duplicate_groups"] = db.execute(
            f"SELECT count(*) FROM {view} WHERE s=? AND n>1", (split,)
        ).fetchone()[0]
        r[f"{split}_conflicting_vectors"] = db.execute(
            f"SELECT count(*) FROM (SELECT x FROM {view} WHERE s=? GROUP BY x HAVING count(*)>1)",
            (split,),
        ).fetchone()[0]
    (
        r["shared_feature_label_groups"],
        r["train_rows_in_shared_feature_label"],
        r["test_rows_in_shared_feature_label"],
    ) = db.execute(
        f"SELECT count(*),coalesce(sum(a.n),0),coalesce(sum(b.n),0) FROM {view} a JOIN {view} b ON a.x=b.x AND a.y=b.y WHERE a.s='train' AND b.s='test'"
    ).fetchone()
    r["shared_feature_vectors"] = db.execute(
        f"SELECT count(*) FROM (SELECT x FROM {view} GROUP BY x HAVING count(distinct s)=2)"
    ).fetchone()[0]
    r["conflicting_vectors_across_splits"] = db.execute(
        f"SELECT count(*) FROM (SELECT a.x FROM {view} a JOIN {view} b ON a.x=b.x WHERE a.s='train' AND b.s='test' AND a.y<>b.y GROUP BY a.x)"
    ).fetchone()[0]
    r["conflicting_vectors_any_split"] = db.execute(
        f"SELECT count(*) FROM (SELECT x FROM {view} GROUP BY x HAVING count(distinct y)>1)"
    ).fetchone()[0]
    return r


STREAMING = [
    (
        "pkSeqID",
        "No",
        "Dataset/export row identifier; unavailable as a stable live feature. Exclude.",
    ),
    ("proto", "Yes", "Packet header; passive, one direction."),
    (
        "saddr, daddr",
        "Yes, with caution",
        "Packet header; identities can encode testbed roles. Prefer excluding from first model.",
    ),
    (
        "sport, dport",
        "Yes, conditional",
        "Transport header; ICMP has type/code semantics and no TCP/UDP ports. Handle explicitly.",
    ),
    (
        "seq",
        "No as stored",
        "Argus record sequence/export metadata, not a portable TCP sequence feature. Exclude.",
    ),
    (
        "stddev, min, mean, max",
        "Conditional; not packet-time ready",
        "Aggregate duration statistics need a defined completed/trailing window and flow timeouts; final record can use future packets. Exact CSV extraction/window semantics unavailable here. Recompute causally before live use.",
    ),
    (
        "N_IN_Conn_P_SrcIP, N_IN_Conn_P_DstIP",
        "Conditional",
        "Endpoint connection aggregates need multiple flows, bounded state and a past-only window. Capture-wide or look-ahead counts leak future observations; do not assume CSV values are causal.",
    ),
    (
        "srate",
        "Conditional",
        "Source rate can be measured one way over elapsed time; final Argus rate requires record completion/timeout. A running rate differs from this offline feature.",
    ),
    (
        "drate",
        "Requires reverse traffic",
        "Destination rate needs the other direction of the flow. Not available from strictly one-way source observations; final value also needs completion/timeout.",
    ),
    (
        "state_number",
        "Requires validation / often bidirectional",
        "Argus state encoding can depend on responses, handshake, teardown or timeout. Final state may require reverse/future traffic; no numeric codebook supplied. Omit until causal mapping is established.",
    ),
    (
        "attack, category, subcategory",
        "No",
        "Ground truth labels; exclude every label from all predictors, including the other classification tasks.",
    ),
]


def write_report(name, splits, audits, out):
    bot = name == "bot_iot"
    lines = [
        f"# {'BoT-IoT' if bot else 'DNS Threats'} dataset analysis",
        "",
        f"Generated {datetime.now(UTC).isoformat()} (UTC).",
        "",
        "## Method and limits",
        "",
        "Full-file counts, finite-value moments and Pearson correlations are computed in chunks. Quantiles, histograms and 3×IQR outlier rates use a deterministic uniform priority sample per split (seed 20261115, test +1); they are estimates, not exact population quantiles. Unparseable, missing and infinite values are excluded from finite statistics; finite range violations remain visible in those statistics and are separately flagged. Sample outlier rates are undefined when IQR is zero. Near-constant means ≥99% of all rows have one value. Numerical majority counts use a second exact pass; categorical counts are exact. No rows are modified, dropped, merged into a training dataset, or used to fit a model.",
        "",
        "SQLite compares parsed field strings (CSV quoting differences are immaterial), preserving case, whitespace and numeric spelling. BoT-IoT feature vectors use SHA-256 signatures of unambiguous JSON tuples; hash collision risk is negligible but these are signature checks rather than byte-by-byte collision verification. DNS feature keys are exact domain strings. Label conflicts compare the entire label tuple. These checks do not detect near-duplicates, semantically equivalent numeric spellings, or DNS case/trailing-dot equivalence. Cross-split queries join signatures only, not raw datasets.",
        "",
        "## Dataset inspection",
        "",
    ]
    lines += [
        table(
            [
                "Split",
                "Rows",
                "Columns",
                "CSV MiB",
                "String-column memory MiB¹",
                "Peak chunk MiB¹",
                "Sample rows",
            ],
            [
                (
                    s,
                    f"{r['rows']:,}",
                    len(r["columns"]),
                    f"{r['file_bytes'] / 2**20:.2f}",
                    f"{r['memory_bytes'] / 2**20:.2f}",
                    f"{r['peak_chunk_bytes'] / 2**20:.2f}",
                    r["sample_rows"],
                )
                for s, r in splits.items()
            ],
        ),
        "",
        "¹Deep pandas column bytes summed over chunks estimate full string-table memory; peak is one raw chunk only. Excludes Python counters, numeric arrays, sample copies and SQLite cache. Actual process peak RSS is in summary.md.",
        "",
    ]
    for split, r in splits.items():
        lines += [
            f"### {split}",
            "",
            f"Source: `{r['path']}`. Labels: {', '.join('`' + c + '`' for c in LABELS[name])}.",
            "",
            table(
                [
                    "Column",
                    "Observed read dtype",
                    "Role / semantic type",
                    "Missing",
                    "+/−infinity",
                    "Invalid¹",
                ],
                [
                    (
                        c,
                        ", ".join(sorted(r["dtype_observations"][c])),
                        "label (categorical)"
                        if c in LABELS[name]
                        else "numeric (integer-valued)"
                        if c in r["numeric"]
                        and r["statistics"][c]["finite"]
                        and r["statistics"][c]["integer_valued"]
                        else "numeric (floating point)"
                        if c in r["numeric"]
                        else "categorical port token / numeric semantics"
                        if c in PORTS
                        else "categorical / string",
                        r["missing"][c],
                        r["infinite"][c],
                        r["invalid"][c],
                    )
                    for c in r["columns"]
                ],
            ),
            "",
            "CSV has no intrinsic stored dtypes; integer/floating semantics above are inferred across all finite numerical values. All fields are deliberately read as strings to preserve mixed port tokens and duplicate identity. Semantic numerical/categorical roles are above; labels and encoded state/protocol are categorical even when integer-valued. Missing means empty/whitespace; numeric fields also recognize NA/nan/null/none/n/a. Literal domain strings such as 'nan' are not automatically missing.",
            "",
            "¹Invalid checks: expected numeric parsing and nonnegative values, IP syntax, port range 0–65535 (hex allowed), and attack∈{0,1}. DNS class codes are only checked as nonnegative integers; their meaning is unverified. DNS lexical flags below are screening observations, not definitive invalidity judgments. No protocol/state dictionary is supplied, so unknown codes cannot be validated. Empty categories are counted as missing.",
            "",
            "Validation observations:",
            "",
            table(["Check", "Rows"], sorted(r["rules"].items())),
            "",
        ]
        examples = [
            (c, ", ".join(sorted(v)[:5])) for c, v in r["invalid_examples"].items() if v
        ]
        if examples:
            lines += [table(["Column", "Invalid token examples"], examples), ""]
        const = [
            c
            for c, v in r["statistics"].items()
            if v["finite"] and v["min"] == v["max"]
        ]
        cat_const = [c for c, counts in r["categorical"].items() if len(counts) == 1]
        near = [
            (c, v["value"], v["count"], f"{v['percent']:.5f}%")
            for c, v in r["near_constant_numeric"].items()
        ]
        near += [
            (
                c,
                counts.most_common(1)[0][0],
                counts.most_common(1)[0][1],
                f"{100 * counts.most_common(1)[0][1] / r['rows']:.5f}%",
            )
            for c, counts in r["categorical"].items()
            if counts and counts.most_common(1)[0][1] / r["rows"] >= 0.99
        ]
        lines += [
            f"Constant columns: {', '.join(const + cat_const) or 'none'} (numeric constants use finite values; see missing counts).",
            "",
            table(
                [
                    "Near-constant column (labels included for diagnosis)",
                    "Dominant value",
                    "Count",
                    "Share",
                ],
                near,
            )
            if near
            else "No near-constant columns at the 99% threshold.",
            "",
        ]
    if not bot:
        lines += [
            "## Domain representation and source-artifact risks",
            "",
            "Compare domain structure before treating the supplied splits as interchangeable. The last dot-separated token below is a diagnostic suffix, not a public-suffix/registrable-domain parse. Counts are full-file and grouped by observed code without assigning class meanings.",
            "",
        ]
        for split, r in splits.items():
            lines += [
                f"### {split}",
                "",
                table(
                    [
                        "Class",
                        "Rows",
                        "No dot %",
                        "Mean length",
                        "Label >63 chars",
                        "Top final tokens",
                    ],
                    [
                        (
                            label,
                            v["rows"],
                            f"{100 * v['no_dot'] / v['rows']:.6f}",
                            f"{v['length_sum'] / v['rows']:.4f}",
                            v["overlong_label"],
                            str(r["dns_suffixes"][label].most_common(5)),
                        )
                        for label, v in sorted(r["dns_structure"].items())
                    ],
                ),
                "",
            ]
        lines += [
            "A single-label/FQDN mismatch can alter length, dot counts and suffix features while hiding shared underlying names from exact-string overlap checks. Suffixes concentrated in one class may encode collection/generation sources. Verify provenance and define the intended prediction unit before any feature design or trustworthy train/test evaluation. Do not infer independent underlying domains from zero raw-string overlap.",
            "",
        ]
    lines += ["## Class distributions and split comparison", ""]
    for label in LABELS[name]:
        keys = sorted(
            set(splits["train"]["classes"][label])
            | set(splits["test"]["classes"][label])
        )
        rows = []
        for value in keys:
            counts = [splits[s]["classes"][label][value] for s in ["train", "test"]]
            pct = [
                100 * counts[i] / splits[s]["rows"]
                for i, s in enumerate(["train", "test"])
            ]
            rows.append(
                (
                    value,
                    f"{counts[0]:,}",
                    f"{pct[0]:.6f}",
                    f"{counts[1]:,}",
                    f"{pct[1]:.6f}",
                    f"{pct[1] - pct[0]:+.6f}",
                )
            )
        filename = f"{name}_{label}_classes.svg"
        svg_bars(
            out / filename,
            f"{name}: {label}",
            keys,
            [
                (s, [splits[s]["classes"][label][k] for k in keys], splits[s]["rows"])
                for s in ["train", "test"]
            ],
        )
        lines += [
            f"### `{label}`",
            "",
            table(
                ["Class", "Train n", "Train %", "Test n", "Test %", "Test−train pp"],
                rows,
            ),
            "",
            f"![{label} distribution]({filename})",
            "",
        ]
        train_only = sorted(
            set(splits["train"]["classes"][label])
            - set(splits["test"]["classes"][label])
        )
        test_only = sorted(
            set(splits["test"]["classes"][label])
            - set(splits["train"]["classes"][label])
        )
        lines += [
            f"Classes absent from test: {', '.join(train_only) or 'none'}; absent from train: {', '.join(test_only) or 'none'}. Recall is not measurable for a class with zero test support.",
            "",
        ]
        for s, r in splits.items():
            counts = r["classes"][label]
            smallest = min(counts, key=counts.get)
            lines += [
                f"{s}: minority `{smallest}` = {counts[smallest]:,} ({100 * counts[smallest] / r['rows']:.6f}%); majority/minority ratio = {max(counts.values()) / counts[smallest]:.2f}:1. Classes under 1%: {', '.join(k for k, v in counts.items() if v / r['rows'] < 0.01) or 'none'}.",
                "",
            ]
    if not bot:
        lines += [
            "The filename says multiclass, but the actual observed code inventory above defines the available task. No local label dictionary establishes that 0=benign or identifies threat families. Do not invent a binary collapse or code meanings. A binary analysis becomes meaningful only after that mapping is verified.",
            "",
        ]
    lines += [
        "## Feature distributions and descriptive statistics",
        "",
        "Moments below cover every finite value; skew is the population standardized third central moment. Ports are parsed numerically for diagnostics only, while preserving their categorical tokens. Domain length is an analysis-only measurement, not an implemented preprocessing pipeline.",
        "",
    ]
    for s, r in splits.items():
        lines += [
            f"### {s}",
            "",
            table(
                [
                    "Column",
                    "Finite n",
                    "Mean",
                    "SD",
                    "Min",
                    "Max",
                    "Skew",
                    "Sample p01 / p25 / p50 / p75 / p99",
                    "Sample extreme % (3×IQR)",
                ],
                [
                    (
                        c,
                        v["finite"],
                        fmt(v["mean"]),
                        fmt(v["std"]),
                        fmt(v["min"]),
                        fmt(v["max"]),
                        fmt(v["skew_population"]),
                        " / ".join(
                            fmt(v.get(k))
                            for k in [
                                "p01_sample",
                                "q25_sample",
                                "median_sample",
                                "q75_sample",
                                "p99_sample",
                            ]
                        ),
                        fmt(v.get("extreme_3iqr_sample_percent")),
                    )
                    for c, v in r["statistics"].items()
                ],
            ),
            "",
        ]
        skewed = [
            c
            for c, v in r["statistics"].items()
            if v["skew_population"] is not None and abs(v["skew_population"]) > 2
        ]
        lines += [
            f"Features with |population skew| >2: {', '.join(skewed) or 'none'}. Extreme values are investigation candidates, not automatic removal criteria; attacks may produce legitimate extremes.",
            "",
        ]
    plot_cols = splits["train"]["numeric"] if bot else ["domain_length"]
    samples = {s: r["sample"].copy() for s, r in splits.items()}
    if not bot:
        for df in samples.values():
            df["domain_length"] = df.domain.str.len()
    hist_svg(
        out / f"{name}_distributions.svg",
        f"{name}: numerical distribution comparison",
        samples,
        plot_cols,
    )
    lines += [
        f"![Feature distributions]({name}_distributions.svg)",
        "",
        "## Correlations and redundancy",
        "",
    ]
    if bot:
        for s, r in splits.items():
            corr = r["correlation"]
            corr.to_csv(out / f"{name}_{s}_correlations.csv")
            pairs = [
                (a, b, fmt(corr.loc[a, b]))
                for i, a in enumerate(corr.columns)
                for b in corr.columns[i + 1 :]
                if abs(corr.loc[a, b]) >= 0.9
            ]
            lines += [
                f"{s}: pairwise-complete Pearson correlations; high-correlation candidates |r|≥0.90. Constant columns yield undefined correlations. IDs are included diagnostically; port tokens are excluded from Pearson correlation because their magnitude is not a meaningful continuous measurement.",
                "",
                table(["Feature A", "Feature B", "Pearson r"], pairs)
                if pairs
                else "No pairs at this threshold.",
                "",
                f"[Complete correlation matrix]({name}_{s}_correlations.csv). Correlation is association, not a feature-removal instruction.",
                "",
            ]
        lines += [
            "Duration aggregates may be redundant even below this threshold. Evaluate removing one of each strongly correlated pair inside training validation only; never use test performance to select predictors.",
            "",
        ]
    else:
        lines += [
            "No numerical input columns exist, so input-feature Pearson correlation and numerical feature redundancy are not applicable. Numeric class codes are labels, not predictors. Domain length is only a diagnostic; repeated domain strings are evaluated below.",
            "",
        ]
    lines += ["## Categorical cardinality", ""]
    for s, r in splits.items():
        rows = [
            (
                c,
                len(counts),
                f"{100 * len(counts) / r['rows']:.4f}",
                "; ".join(f"{k}: {v:,}" for k, v in counts.most_common(5)),
            )
            for c, counts in r["categorical"].items()
        ]
        if not bot:
            rows.append(
                (
                    "domain",
                    r["domain_cardinality"],
                    f"{100 * r['domain_cardinality'] / r['rows']:.4f}",
                    str(r["domain_top"]),
                )
            )
        lines += [
            f"### {s}",
            "",
            table(
                ["Column", "Distinct", "Distinct / rows %", "Top values: counts"], rows
            ),
            "",
        ]
        if bot:
            for c, counts in r["cross"].items():
                groups = defaultdict(Counter)
                for (value, label), n in counts.items():
                    groups[value][label] += n
                purity = sum(max(v.values()) for v in groups.values()) / r["rows"]
                lines += [
                    f"`{c}` → category weighted majority purity: {100 * purity:.4f}% (diagnostic association, not a validation score).",
                    "",
                    table(
                        [c, "Category counts"],
                        [(k, dict(v)) for k, v in sorted(groups.items())],
                    ),
                    "",
                ]
    lines += [
        "## Duplicate, overlap and conflicting-label audit",
        "",
        "Duplicate excess is sum(group size−1); duplicate groups have size>1. Shared groups count distinct (feature vector, complete label tuple) pairs; affected rows are reported separately. Conflicting vectors have more than one complete label tuple. Both splits retain all their rows.",
        "",
    ]
    for view, values in audits.items():
        cols = (
            splits["train"]["features"]
            if view == "raw"
            else splits["train"]["operational_features"]
        )
        lines += [
            f"### {view} feature view",
            "",
            f"Features: `{', '.join(cols)}`. Labels: `{', '.join(LABELS[name])}`.",
            "",
            table(["Measure", "Count"], [(k, f"{v:,}") for k, v in values.items()]),
            "",
        ]
    if bot:
        lines += [
            "Raw identities can conceal operational duplicates: the second view excludes both `pkSeqID` and `seq`. This is a diagnostic projection, not a transformed dataset. Dropping IPs or other future predictors can expose additional overlap; repeat group audits after feature design.",
            "",
        ]
    if not bot:
        examples = splits["train"].get("conflict_examples", [])
        lines += [
            "### Example conflicting domain labels across the supplied splits",
            "",
            table(["Domain", "Split: label tuple (row count)"], examples)
            if examples
            else "No exact domain label conflicts found.",
            "",
        ]
    lines += ["## Passive unidirectional streaming compatibility", ""]
    if bot:
        lines += [
            table(["Feature(s)", "Available?", "Reason / necessary action"], STREAMING),
            "",
            "This is a conservative inference from feature names and flow-export context. CSV files have no packet timestamps, exporter configuration, state codebook or window provenance. Causality, flow/session independence and exact feature reconstruction cannot be proved from these files. Live MVP should use header fields and explicitly defined past-only summaries; evaluate completed-flow detection separately.",
            "",
            "Dataset provenance: [UNSW BoT-IoT page](https://research.unsw.edu.au/projects/bot-iot-dataset) describes PCAP/Argus/CSV exports and simulated attack traffic; [authors' paper](https://arxiv.org/abs/1811.00701) documents the testbed. Availability judgments above are engineering inferences, not measurements of the capture pipeline.",
            "",
        ]
    else:
        lines += [
            table(
                ["Feature", "Available?", "Constraints"],
                [
                    (
                        "domain",
                        "Yes, conditional",
                        "Plaintext DNS question contains a name in one request direction; no reply, completed connection or future packet needed. TCP DNS may require past-byte reassembly; truncation/fragmentation limits visibility. Encrypted DNS payload names are unavailable to a passive observer without decryption. These files often contain name tokens rather than verified full QNAMEs; representation parity must be established.",
                    ),
                    (
                        "class",
                        "No",
                        "Ground truth available only offline; never a live predictor.",
                    ),
                ],
            ),
            "",
            "No timestamps, client identities, query types, response codes, TTLs, packet sizes, or response timings are supplied. Do not assume these features can be recovered from this CSV. Absence of capture provenance prevents temporal/family leakage audits.",
            "",
        ]
    lines += ["## Recommended next steps (not implemented)", ""]
    if bot:
        lines += [
            "Port -1 is outside the transport-port range; inspect its protocol counts above as a possible not-applicable sentinel (e.g. ARP), rather than coercing it to a real port. Hex ICMP fields need a type/code policy. Subcategory names such as TCP/UDP occur under multiple attack categories; use category/subcategory pairs if the goal is hierarchical attack identification. Extremely rare classes and absent test classes require explicit support counts and limit what metrics can establish.",
            "",
        ]
    if bot:
        lines += [
            "Exclude all label columns from predictors; drop dataset identifiers `pkSeqID` and `seq`. Treat IP identity as a leakage ablation, state as an encoded category, protocol as categorical, and ports with protocol-aware special-token handling. Validate codebooks and aggregate timing before selecting live-compatible predictors. Fit imputation/encoding/scaling and any clipping only on training folds. Consider log1p for nonnegative skewed rates/durations and robust scaling for linear baselines; preserve attack tails until validated.",
            "",
            "Retain the supplied test split as an explicitly potentially contaminated benchmark. For future evaluation, group validation by feature-vector/flow/session/host or capture period as available, using training data only. Investigate conflicts rather than choosing a label by frequency. Begin with class-weighted linear and small histogram/tree baselines on CPU; separate binary attack detection from category/subcategory tasks, report macro-F1, balanced accuracy, per-class precision/recall and confusion matrices. For binary work include PR-AUC and false positives on benign traffic. Extremely scarce normal/theft examples mean uncertainty must be reported. Do not oversample before splitting; avoid large synthetic sampling and deep models initially.",
            "",
        ]
    else:
        lines += [
            "Resolve the observed train/test domain representation mismatch before model evaluation; do not simply strip suffixes without confirming the target unit and source provenance. Verify the label-code dictionary and source provenance before defining benign/malicious or family tasks. Investigate label conflicts and cross-split domain reuse before considering deduplication; preserve originals. Define a domain normalization policy (IDNA, case, trailing dot, QNAME vs stripped label) based on observed capture representation, then repeat overlap checks. Prefer inexpensive lexical statistics or bounded sparse character n-grams rather than one-hot encoding each domain; all vocabulary/normalization decisions must be fitted or selected using training folds only.",
            "",
            "Use domain-grouped training validation; if source/family/time metadata becomes available, add family-held-out and temporal tests. A supplied test score may be inflated by repeated domains or shared generation patterns. Begin with class-weighted sparse linear baselines or small trees on lexical summaries on CPU, after the audit is resolved. Report macro-F1, per-class recall/precision, confusion matrices and uncertainty for rare classes; use PR-AUC only after binary mapping is verified. Sampling/resampling belongs inside training folds, never before validation splitting.",
            "",
        ]
    (out / f"{name}_report.md").write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chunk-size", type=int, default=50000)
    parser.add_argument("--sample-size", type=int, default=30000)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "reports/dataset_analysis"
    )
    parser.add_argument(
        "--temp-dir",
        type=Path,
        help="Directory for temporary SQLite databases (several GB free recommended)",
    )
    args = parser.parse_args()
    if args.chunk_size < 1 or args.sample_size < 1:
        parser.error("chunk and sample sizes must be positive")
    out = args.output_dir.resolve()
    raw = (ROOT / "data/raw").resolve()
    if out == raw or raw in out.parents:
        parser.error("output-dir must not be inside data/raw")
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    results, all_audits = {}, {}
    snapshots = {
        str(p): (p.stat().st_size, p.stat().st_mtime_ns)
        for source in SOURCES.values()
        for rel in source.values()
        for p in [ROOT / rel]
    }
    for name, paths in SOURCES.items():
        print(f"Analyzing {name}", flush=True)
        with (
            tempfile.TemporaryDirectory(
                prefix=f"cyberguard_eda_{name}_", dir=args.temp_dir
            ) as temp,
            closing(sqlite3.connect(str(Path(temp) / "audit.sqlite"))) as db,
        ):
            db.execute("PRAGMA journal_mode=OFF")  # disposable analysis index only
            db.execute("PRAGMA synchronous=OFF")
            db.execute("PRAGMA temp_store=FILE")
            db.execute("PRAGMA cache_size=-65536")
            for view in ["raw", "operational"]:
                db.execute(
                    f"CREATE TABLE {view}(s TEXT,x BLOB,y TEXT,n INTEGER,PRIMARY KEY(s,x,y)) WITHOUT ROWID"
                )
            splits = {
                s: scan(name, s, ROOT / rel, db, args.chunk_size, args.sample_size)
                for s, rel in paths.items()
            }
            if splits["train"]["columns"] != splits["test"]["columns"]:
                raise ValueError(f"Schema mismatch for {name}")
            print(f"  {name}: auditing split overlap and conflicts", flush=True)
            views = ["raw", "operational"] if name == "bot_iot" else ["raw"]
            for view in views:
                db.execute(f"CREATE INDEX {view}_features ON {view}(x,y,s,n)")
            audits = {view: audit(db, view) for view in views}
            if name == "dns_threats":
                for s, r in splits.items():
                    r["domain_cardinality"] = db.execute(
                        "SELECT count(distinct x) FROM raw WHERE s=?", (s,)
                    ).fetchone()[0]
                    r["domain_top"] = db.execute(
                        "SELECT x,sum(n) AS total FROM raw WHERE s=? GROUP BY x ORDER BY total DESC,x LIMIT 5",
                        (s,),
                    ).fetchall()
                splits["train"]["conflict_examples"] = db.execute(
                    "SELECT x,group_concat(s || ':' || y || ' (' || n || ')', '; ') FROM raw GROUP BY x HAVING count(distinct y)>1 LIMIT 5"
                ).fetchall()
            write_report(name, splits, audits, out)
            results[name], all_audits[name] = splits, audits
            print(
                f"  {name}: reports written; temporary index {sum(p.stat().st_size for p in Path(temp).iterdir()) / 2**20:.1f} MiB",
                flush=True,
            )
    for path, state in snapshots.items():
        p = Path(path)
        if (p.stat().st_size, p.stat().st_mtime_ns) != state:
            raise RuntimeError(f"Raw input changed during analysis: {p}")
    elapsed = time.monotonic() - started
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # Linux KiB -> MiB
    lines = [
        "# CyberGuard dataset analysis summary",
        "",
        f"Generated {datetime.now(UTC).isoformat()} (UTC).",
        "",
        "## Dataset characteristics",
        "",
        table(
            ["Dataset", "Train rows", "Test rows", "Columns", "Labels"],
            [
                (
                    name,
                    f"{r['train']['rows']:,}",
                    f"{r['test']['rows']:,}",
                    len(r["train"]["columns"]),
                    ", ".join(LABELS[name]),
                )
                for name, r in results.items()
            ],
        ),
        "",
        "BoT-IoT supplies network flow/export features; DNS supplies a single raw string feature. Analyze and evaluate them separately; there is no supported cross-dataset join.",
        "",
        "## Class imbalance findings",
        "",
    ]
    for name, splits in results.items():
        for label in LABELS[name]:
            for s, r in splits.items():
                counts = r["classes"][label]
                lo = min(counts, key=counts.get)
                lines += [
                    f"- {name}/{s} `{label}`: {len(counts)} classes; minority `{lo}` {counts[lo]:,}/{r['rows']:,} ({100 * counts[lo] / r['rows']:.6f}%); majority/minority {max(counts.values()) / counts[lo]:.2f}:1."
                ]
    for name, splits in results.items():
        for label in LABELS[name]:
            train_only = set(splits["train"]["classes"][label]) - set(
                splits["test"]["classes"][label]
            )
            if train_only:
                lines += [
                    f"- {name}/{label}: classes absent from test: {', '.join(sorted(train_only))}; their recall cannot be evaluated on this test split."
                ]
    lines += [
        "",
        "DNS numeric label meanings are unverified: do not assume a benign code or fabricate a binary grouping. Full split percentages and shifts are in each dataset report.",
        "",
        "## Data quality problems and potential leakage",
        "",
    ]
    for name, splits in results.items():
        for s, r in splits.items():
            lines += [
                f"- {name}/{s}: {sum(r['missing'].values()):,} missing cells; {sum(r['infinite'].values()):,} infinite cells; {sum(r['invalid'].values()):,} invalid cells under documented numeric/IP rules. DNS lexical screening flags are separate in its report."
            ]
        for view, a in all_audits[name].items():
            lines += [
                f"- {name}/{view}: train/test duplicate excess {a['train_duplicate_excess']:,}/{a['test_duplicate_excess']:,}; shared feature+label groups {a['shared_feature_label_groups']:,}, affecting {a['train_rows_in_shared_feature_label']:,} train and {a['test_rows_in_shared_feature_label']:,} test rows; within-split conflicting vectors {a['train_conflicting_vectors']:,}/{a['test_conflicting_vectors']:,}; cross-split conflicting vectors {a['conflicting_vectors_across_splits']:,}."
            ]
    dns = results["dns_threats"]
    for split, r in dns.items():
        lines += [
            f"- DNS/{split}: {r['domain_cardinality']:,} distinct domain strings; {100 * r['rules']['domain: no dot (single label / possibly stripped name)'] / r['rows']:.4f}% have no dot. Confirm whether these are stripped labels rather than full query names."
        ]
    lines += [
        "",
        "BoT-IoT identifiers can conceal matching traffic vectors; all labels must be excluded from predictors. Strong endpoint/protocol associations can encode scenario roles. Final flow state, reverse rate and aggregate windows can leak unavailable reverse/future traffic into a live detector. DNS repeated strings may permit memorization. Raw string checks omit case/numeric canonicalization and near-duplicates. No timestamps/session/family provenance are supplied, so temporal leakage and causal extraction cannot be ruled out. Neither dataset alone establishes real-world performance.",
        "",
        "## Recommended preprocessing (not implemented)",
        "",
        "BoT-IoT: exclude pkSeqID/seq and all three labels; validate port specials and state codebooks, ablate IP identities, encode categories with unknown-value handling, and assess log1p/robust scaling on highly skewed numeric inputs. Fit imputation/scaling/encoding only in training folds. Design past-only windows and establish train/live feature parity; drate and final state are unsuitable without reverse visibility and completion rules.",
        "",
        "DNS: resolve the observed train/test single-label versus dotted-name mismatch before evaluating models; zero raw-string overlap is not evidence of underlying domain independence. Verify code meanings and domain representation; investigate conflicting labels and repetitions before proposing a deduplication policy. Consider IDNA/case/trailing-dot policy, lightweight lexical summaries or bounded sparse character n-grams, with group-safe train validation. Do not one-hot every unique domain. All changes require a later implementation task; this run preserves every raw row.",
        "",
        "## Recommended model training strategy (no training performed)",
        "",
        "Use train-only grouped validation with leakage groups, leaving supplied test splits untouched and reporting observed contamination. Obtain session/time/family metadata for stronger evaluation. Start with CPU-friendly class-weighted linear baselines and bounded tree/histogram models; use sparse linear models for character n-grams. Tune on training folds only, keep sampling inside folds, and avoid large oversampled copies. Evaluate binary and multiclass tasks separately where verified, using macro-F1, balanced accuracy, per-class precision/recall, confusion matrices and rare-class uncertainty; add PR-AUC/false-positive rates for verified binary targets. Scarce benign and minority samples require more representative data rather than confidence from accuracy alone.",
        "",
        "## CPU, memory and reproducibility",
        "",
        f"Command: `.venv/bin/python scripts/inspect_datasets.py --chunk-size {args.chunk_size} --sample-size {args.sample_size}`. Python analysis uses pandas {pd.__version__}, NumPy {np.__version__}, SQLite {sqlite3.sqlite_version}. No GPU or plotting dependency is required. SVG plots are self-contained.",
        "",
        f"Measured wall time: {elapsed:.1f} seconds; process peak RSS: {rss:.1f} MiB (Linux getrusage, includes native arrays/caches). Each split keeps at most {args.sample_size:,} sampled rows plus a {args.chunk_size:,}-row chunk and bounded numerical accumulators. BoT categorical counts scale with token cardinality; high-cardinality DNS domains and duplicate signatures stay in SQLite. SQLite has a 64 MiB page cache and disk-backed sorting; temporary indexes are deleted after each dataset. Budget several GB of free temporary disk and single-process CPU time. Limit BLAS threads externally if needed; this script does not spawn workers.",
        "",
        "Counts/moments/correlations and categorical cardinalities are full-file results; quantiles/distribution plots/outlier percentages are seeded sample estimates. SHA-256 fingerprints are used for BoT-IoT identity comparisons. Full pairwise Pearson matrices are CSV artifacts. Input size and modification time are verified unchanged at completion; inputs are opened read-only. No model or preprocessing artifacts were created.",
        "",
        "## Reports",
        "",
        "- [BoT-IoT report](bot_iot_report.md)",
        "- [DNS Threats report](dns_threats_report.md)",
        "",
        "Provenance reference: [UNSW dataset page](https://research.unsw.edu.au/projects/bot-iot-dataset). All dataset statistics in these reports come from the local CSV files; streaming availability judgments are conservative engineering assessments.",
    ]
    (out / "summary.md").write_text("\n".join(lines) + "\n")
    required = [out / f"{name}_report.md" for name in SOURCES] + [out / "summary.md"]
    if not all(p.is_file() and p.stat().st_size > 0 for p in required):
        raise RuntimeError("Missing/empty report")
    print(
        f"Verified all reports in {out}; {elapsed:.1f}s, peak RSS {rss:.1f} MiB",
        flush=True,
    )


if __name__ == "__main__":
    main()
