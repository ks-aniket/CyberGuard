"""Read-only NF-CSE-CIC-IDS2018 audit; no fitting, preprocessing or partitioning.

Exact duplicate keys retain CSV token strings with JSON field boundaries, not hashes.
Numeric summaries are separate from those identity comparisons. SQLite bounds memory.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import platform
import resource
import sqlite3
import tempfile
import time
import zipfile
from collections import Counter
from contextlib import closing
from pathlib import Path

import numpy as np
import pandas as pd
from inspect_datasets import Moments, svg_bars, table

ROOT = Path(__file__).resolve().parents[1]
IPS = ["IPV4_SRC_ADDR", "IPV4_DST_ADDR"]
HEADER = ["PROTOCOL", "L4_SRC_PORT", "L4_DST_PORT"]
FLOW = [
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
]
LABELS = ["Label", "Attack"]
COLUMNS = [
    "IPV4_SRC_ADDR",
    "L4_SRC_PORT",
    "IPV4_DST_ADDR",
    "L4_DST_PORT",
    "PROTOCOL",
    "L7_PROTO",
    *FLOW,
    *LABELS,
]
NUMERIC = [c for c in COLUMNS if c not in [*IPS, "Attack"]]
VIEWS = {
    "all_predictors": [c for c in COLUMNS if c not in LABELS],
    "no_ip_completed": [*HEADER, "L7_PROTO", *FLOW],
    "duration_inclusive": [*HEADER, *[c for c in FLOW if c != "TCP_FLAGS"]],
    "initial_completed": [*HEADER, "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS"],
    "header_only": HEADER,
}
KNOWN_ATTACKS = {
    "Benign",
    "Bot",
    "Brute Force -Web",
    "Brute Force -XSS",
    "DDoS attacks-LOIC-HTTP",
    "DDOS attack-HOIC",
    "DDOS attack-LOIC-UDP",
    "DoS attacks-GoldenEye",
    "DoS attacks-Hulk",
    "DoS attacks-SlowHTTPTest",
    "DoS attacks-Slowloris",
    "FTP-BruteForce",
    "Infilteration",
    "SQL Injection",
    "SSH-Bruteforce",
}


def hashes(stream):
    sha1, sha256 = hashlib.sha1(), hashlib.sha256()
    while block := stream.read(1024 * 1024):
        sha1.update(block)
        sha256.update(block)
    return {"sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def discover(directory):
    directory = Path(directory).resolve()
    matches = sorted(directory.rglob("NF-CSE-CIC-IDS2018.csv"))
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one NF-CSE-CIC-IDS2018.csv under {directory}; found {len(matches)}"
        )
    source = matches[0]
    bag = source.parent.parent
    required = [
        "bag-info.txt",
        "bagit.txt",
        "FurtherInformation.txt",
        "manifest-sha1.txt",
        "tagmanifest-sha1.txt",
        "data/NetFlow_v1_Features.csv",
    ]
    for name in required:
        if not (bag / name).is_file():
            raise ValueError(f"Missing required BagIt file: {bag / name}")
    archives = sorted(directory.rglob("*.zip"))
    if len(archives) != 1:
        raise ValueError(
            f"Expected exactly one ZIP under {directory}; found {len(archives)}"
        )
    return source, bag, archives[0]


def integrity(bag, archive):
    files = {}
    for path in sorted(bag.rglob("*")):
        if path.is_file():
            with path.open("rb") as stream:
                files[path.relative_to(bag).as_posix()] = {
                    "bytes": path.stat().st_size,
                    **hashes(stream),
                }
    checks = []
    for manifest in ["manifest-sha1.txt", "tagmanifest-sha1.txt"]:
        for line in (bag / manifest).read_text(encoding="utf-8").splitlines():
            digest, name = line.split(maxsplit=1)
            path = (bag / name).resolve()
            if not path.is_relative_to(bag.resolve()) or name not in files:
                raise ValueError(f"Unsafe or missing manifest entry: {name}")
            checks.append(
                {
                    "manifest": manifest,
                    "path": name,
                    "expected": digest,
                    "actual": files[name]["sha1"],
                    "ok": digest == files[name]["sha1"],
                }
            )
    payload = {
        line.split(maxsplit=1)[1]
        for line in (bag / "manifest-sha1.txt").read_text().splitlines()
    }
    actual_payload = {name for name in files if name.startswith("data/")}
    if payload != actual_payload:
        raise ValueError(
            "Payload manifest does not cover exactly the supplied data files"
        )
    comparisons, seen = [], set()
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            if item.is_dir():
                continue
            # Match by bag-relative suffix, allowing an arbitrary outer directory.
            matches = [
                name
                for name in files
                if item.filename == name or item.filename.endswith("/" + name)
            ]
            if len(matches) != 1 or matches[0] in seen:
                raise ValueError(
                    f"Unmatched/ambiguous/duplicate ZIP member: {item.filename}"
                )
            name = matches[0]
            seen.add(name)
            with z.open(item) as stream:  # full read also validates ZIP CRC
                result = hashes(stream)
            comparisons.append(
                {
                    "path": name,
                    "ok": result["sha256"] == files[name]["sha256"]
                    and item.file_size == files[name]["bytes"],
                }
            )
    if seen != set(files):
        raise ValueError("ZIP and extracted file inventories differ")
    with archive.open("rb") as stream:
        archive_hash = hashes(stream)
    return {
        "files": files,
        "manifests": checks,
        "archive_comparisons": comparisons,
        "archive_bytes": archive.stat().st_size,
        "archive_hash": archive_hash,
        "ok": all(c["ok"] for c in checks + comparisons),
    }


def keys(frame):
    return [
        json.dumps(row, ensure_ascii=False, separators=(",", ":"))
        for row in frame.itertuples(index=False, name=None)
    ]


def host_components(source, chunk_size, max_hosts=200000):
    """Bounded endpoint-connectivity diagnostic, never a session reconstruction.

    Both addresses of every row are connected. More hosts than the explicit memory
    budget stops this diagnostic rather than silently truncating the graph.
    """
    parent, size = {}, {}

    def find(host):
        if host not in parent:
            if len(parent) >= max_hosts:
                raise OverflowError
            parent[host], size[host] = host, 1
        while host != parent[host]:
            parent[host] = parent[parent[host]]
            host = parent[host]
        return host

    try:
        for chunk in pd.read_csv(
            source, usecols=IPS, dtype=str, keep_default_na=False, chunksize=chunk_size
        ):
            for left, right in chunk.drop_duplicates().itertuples(
                index=False, name=None
            ):
                a, b = find(left), find(right)
                if a != b:
                    if size[a] < size[b]:
                        a, b = b, a
                    parent[b] = a
                    size[a] += size.pop(b)
    except OverflowError:
        return {
            "complete": False,
            "max_hosts": max_hosts,
            "reason": "Host cardinality exceeds bounded diagnostic budget; disk-backed graph required",
        }
    per_class, totals = {}, Counter()
    for chunk in pd.read_csv(
        source,
        usecols=[IPS[0], "Attack"],
        dtype=str,
        keep_default_na=False,
        chunksize=chunk_size,
    ):
        for (host, attack), count in chunk.value_counts(sort=False).items():
            root = find(host)
            totals[root] += int(count)
            per_class.setdefault(attack, Counter())[root] += int(count)
    return {
        "complete": True,
        "max_hosts": max_hosts,
        "hosts": len(parent),
        "components": len(totals),
        "largest_component_rows": max(totals.values(), default=0),
        "largest_component_hosts": max(size.values(), default=0),
        "per_class": {
            label: {
                "components": len(counts),
                "largest_component_rows": max(counts.values()),
                "rows": sum(counts.values()),
            }
            for label, counts in sorted(per_class.items())
        },
    }


def export_patterns(source, chunk_size, observed_max):
    """Count duration-boundary patterns; does not infer or correct their cause."""
    by_class = {}
    cols = ["Attack", "FLOW_DURATION_MILLISECONDS"]
    for chunk in pd.read_csv(
        source, usecols=cols, dtype=str, keep_default_na=False, chunksize=chunk_size
    ):
        duration = pd.to_numeric(chunk.FLOW_DURATION_MILLISECONDS, errors="coerce")
        for label in sorted(chunk.Attack.unique()):
            values = duration[chunk.Attack.eq(label)]
            counts = by_class.setdefault(label, Counter())
            counts["rows"] += len(values)
            counts["zero"] += int(values.eq(0).sum())
            counts["at_maximum"] += int(values.eq(observed_max).sum())
            counts["within_top_one_percent_of_range"] += int(
                (values.ge(0.99 * observed_max) & values.gt(0)).sum()
            )
    return {
        "observed_duration_max": observed_max,
        "by_class": {label: dict(counts) for label, counts in sorted(by_class.items())},
    }


def weighted_candidate(candidate, balance, counts):
    """Boyer-Moore majority candidate; second pass proves its exact frequency."""
    for token, count in counts.items():
        count = int(count)
        if balance == 0:
            candidate, balance = token, count
        elif candidate == token:
            balance += count
        elif count > balance:
            candidate, balance = token, count - balance
        else:
            balance -= count
    return candidate, balance


def duplicate_summary(db, name):
    distinct_pairs, row_count = db.execute(
        f"SELECT count(*), coalesce(sum(n),0) FROM {name}"
    ).fetchone()
    vector_count, dup_groups, dup_rows, conflicts, conflict_rows, max_group = (
        db.execute(f"""
        SELECT count(*),coalesce(sum(n>1),0),coalesce(sum(CASE WHEN n>1 THEN n ELSE 0 END),0),
        coalesce(sum(labels>1),0),coalesce(sum(CASE WHEN labels>1 THEN n ELSE 0 END),0),coalesce(max(n),0)
        FROM (SELECT k,sum(n) n,count(*) labels FROM {name} GROUP BY k)""").fetchone()
    )
    per_class = list(
        db.execute(
            f"SELECT a,sum(n),count(DISTINCT k) FROM {name} GROUP BY a ORDER BY a"
        )
    )
    examples = []
    for (key,) in db.execute(
        f"SELECT k FROM {name} GROUP BY k HAVING count(*)>1 ORDER BY k LIMIT 5"
    ):
        labels = list(
            db.execute(f"SELECT b,a,n FROM {name} WHERE k=? ORDER BY b,a", (key,))
        )
        examples.append({"vector": json.loads(key), "labels": labels})
    return {
        "rows": row_count,
        "distinct_feature_label_records": distinct_pairs,
        "exact_record_duplicate_excess": row_count - distinct_pairs,
        "distinct_vectors": vector_count,
        "vector_duplicate_excess": row_count - vector_count,
        "repeated_vector_groups": dup_groups,
        "rows_in_repeated_vectors": dup_rows,
        "conflicting_groups": conflicts,
        "rows_in_conflicting_groups": conflict_rows,
        "largest_group_rows": max_group,
        "per_class_groups": per_class,
        "conflict_examples": examples,
    }


def scan(source, db, chunk_size, sample_size):
    with source.open(newline="", encoding="utf-8", errors="strict") as f:
        header = next(csv.reader(f))
    if len(header) != len(set(header)) or header != COLUMNS:
        raise ValueError(
            f"Unsupported schema (including order/duplicate columns): {header}"
        )
    result = {
        "rows": 0,
        "columns": header,
        "string_memory_bytes": 0,
        "peak_chunk_bytes": 0,
        "binary": Counter(),
        "attacks": Counter(),
        "cross": Counter(),
        "rules": Counter(),
        "numeric": {},
        "tokens": {},
        "dtype_observations": {},
    }
    moments = {c: Moments() for c in NUMERIC}
    candidates = {c: (None, 0) for c in header}
    pair_equal = {(a, b): True for i, a in enumerate(header) for b in header[i + 1 :]}
    issues = {c: Counter() for c in header}
    examples = {c: {} for c in header}
    dtype_sets = {c: set() for c in header}
    sample = None
    rng = np.random.default_rng(20261115)
    for name in VIEWS:
        db.execute(
            f"CREATE TABLE {name}(k TEXT,b TEXT,a TEXT,n INTEGER,PRIMARY KEY(k,b,a)) WITHOUT ROWID"
        )
    db.execute(
        "CREATE TABLE categories(c TEXT,v TEXT,n INTEGER,PRIMARY KEY(c,v)) WITHOUT ROWID"
    )
    for chunk in pd.read_csv(
        source,
        dtype=str,
        keep_default_na=False,
        encoding="utf-8",
        encoding_errors="strict",
        chunksize=chunk_size,
    ):
        n = len(chunk)
        result["rows"] += n
        mem = int(chunk.memory_usage(index=False, deep=True).sum())
        result["string_memory_bytes"] += mem
        result["peak_chunk_bytes"] = max(result["peak_chunk_bytes"], mem)
        result["binary"].update(chunk.Label)
        result["attacks"].update(chunk.Attack)
        result["cross"].update(zip(chunk.Label, chunk.Attack))
        numeric = {}
        for col in header:
            s = chunk[col]
            counts = s.value_counts(dropna=False)
            candidates[col] = weighted_candidate(*candidates[col], counts)
            flags = {
                "blank": s.eq(""),
                "na_token": s.str.lower().isin(["na", "nan", "null", "none", "n/a"]),
                "whitespace": s.ne(s.str.strip()),
                "non_ascii": s.str.contains(r"[^\x00-\x7f]", regex=True),
                "control": s.str.contains(r"[\x00-\x1f\x7f]", regex=True),
            }
            if col in NUMERIC:
                values = pd.to_numeric(s, errors="coerce").to_numpy(dtype=float)
                numeric[col] = values
                flags.update(
                    {
                        "invalid_numeric": np.isnan(values)
                        & ~flags["blank"]
                        & ~flags["na_token"],
                        "infinite": np.isinf(values),
                        "fractional": np.isfinite(values)
                        & (values != np.floor(values)),
                        "negative": values < 0,
                    }
                )
                moments[col].add(values)
                dtype_sets[col].add(
                    "float64"
                    if np.isnan(values).any()
                    or np.isinf(values).any()
                    or np.any(values != np.floor(values))
                    else "int64"
                )
            else:
                dtype_sets[col].add("string")
            if col in IPS:
                invalid = set()
                for token in counts.index:
                    try:
                        ipaddress.IPv4Address(token)
                    except ipaddress.AddressValueError:
                        invalid.add(token)
                flags["invalid_ipv4"] = s.isin(invalid)
            for rule, mask in flags.items():
                issues[col][rule] += int(np.sum(mask))
                if np.any(mask) and rule not in examples[col]:
                    examples[col][rule] = s.loc[mask].iloc[:3].tolist()
            if col in [*IPS, "PROTOCOL", "L7_PROTO", "Attack", "Label"]:
                db.executemany(
                    "INSERT INTO categories VALUES(?,?,?) ON CONFLICT(c,v) DO UPDATE SET n=n+excluded.n",
                    [(col, str(v), int(count)) for v, count in counts.items()],
                )
        for pair, equal in list(pair_equal.items()):
            if equal and not chunk[pair[0]].equals(chunk[pair[1]]):
                pair_equal[pair] = False
        for col in ["L4_SRC_PORT", "L4_DST_PORT"]:
            v = numeric[col]
            result["rules"][col + "_out_of_range"] += int(np.sum((v < 0) | (v > 65535)))
            result["rules"][col + "_zero"] += int(np.sum(v == 0))
            result["rules"][col + "_nontransport_nonzero"] += int(
                np.sum(~np.isin(numeric["PROTOCOL"], [6, 17]) & (v != 0))
            )
        result["rules"]["PROTOCOL_out_of_range"] += int(
            np.sum((numeric["PROTOCOL"] < 0) | (numeric["PROTOCOL"] > 255))
        )
        result["rules"]["TCP_FLAGS_out_of_range"] += int(
            np.sum((numeric["TCP_FLAGS"] < 0) | (numeric["TCP_FLAGS"] > 255))
        )
        result["rules"]["non_tcp_nonzero_flags"] += int(
            np.sum((numeric["PROTOCOL"] != 6) & (numeric["TCP_FLAGS"] != 0))
        )
        result["rules"]["zero_duration"] += int(
            np.sum(numeric["FLOW_DURATION_MILLISECONDS"] == 0)
        )
        result["rules"]["zero_in_packets"] += int(np.sum(numeric["IN_PKTS"] == 0))
        result["rules"]["zero_out_packets"] += int(np.sum(numeric["OUT_PKTS"] == 0))
        result["rules"]["in_bytes_without_packets"] += int(
            np.sum((numeric["IN_BYTES"] > 0) & (numeric["IN_PKTS"] == 0))
        )
        result["rules"]["out_bytes_without_packets"] += int(
            np.sum((numeric["OUT_BYTES"] > 0) & (numeric["OUT_PKTS"] == 0))
        )
        for name, cols in VIEWS.items():
            pairs = Counter(
                zip(keys(chunk[cols]), chunk.Label, chunk.Attack, strict=True)
            )
            db.executemany(
                f"INSERT INTO {name} VALUES(?,?,?,?) ON CONFLICT(k,b,a) DO UPDATE SET n=n+excluded.n",
                [(k, b, a, count) for (k, b, a), count in pairs.items()],
            )
        db.commit()
        # Seeded priority reservoir: O(chunk + fixed sample), independent of chunk boundaries.
        selected = chunk.copy()
        selected["_priority"] = rng.random(n)
        if sample is not None:
            selected = pd.concat([sample, selected], ignore_index=True)
        sample = selected.nsmallest(sample_size, "_priority")
        if result["rows"] % (chunk_size * 10) == 0:
            print(
                f"Scanned {result['rows']:,} rows; SQLite {Path(db.execute('PRAGMA database_list').fetchone()[2]).stat().st_size / 2**20:.1f} MiB",
                flush=True,
            )
    if not result["rows"]:
        raise ValueError("Dataset contains no records")
    # Exact verification of majority candidates (includes every possible >=99% mode).
    verified = Counter()
    for chunk in pd.read_csv(
        source, dtype=str, keep_default_na=False, chunksize=chunk_size, encoding="utf-8"
    ):
        for c, (candidate, _) in candidates.items():
            verified[c] += int(chunk[c].eq(candidate).sum())
    result["issues"] = {c: dict(v) for c, v in issues.items()}
    result["issue_examples"] = examples
    result["dtype_observations"] = {c: sorted(v) for c, v in dtype_sets.items()}
    result["duplicate_columns"] = [list(k) for k, v in pair_equal.items() if v]
    result["constants"] = {
        c: candidates[c][0] for c, n in verified.items() if n == result["rows"]
    }
    result["near_constants"] = {
        c: {"token": candidates[c][0], "count": n, "fraction": n / result["rows"]}
        for c, n in verified.items()
        if 0.99 <= n / result["rows"] < 1
    }
    for c, m in moments.items():
        r = m.result()
        for k, v in r.items():
            if isinstance(v, np.generic):
                r[k] = v.item()
            if isinstance(r[k], float) and not np.isfinite(r[k]):
                r[k] = None
        vals = pd.to_numeric(sample[c], errors="coerce").to_numpy(dtype=float)
        vals = vals[np.isfinite(vals)]
        r["sample_quantiles"] = (
            dict(
                zip(
                    ["p01", "p50", "p95", "p99"],
                    map(float, np.quantile(vals, [0.01, 0.5, 0.95, 0.99])),
                )
            )
            if len(vals)
            else {}
        )
        result["numeric"][c] = r
    result["categories"] = {}
    for c in [*IPS, "PROTOCOL", "L7_PROTO", "Attack", "Label"]:
        cardinality = db.execute(
            "SELECT count(*) FROM categories WHERE c=?", (c,)
        ).fetchone()[0]
        top = list(
            db.execute(
                "SELECT v,n FROM categories WHERE c=? ORDER BY n DESC,v LIMIT 10", (c,)
            )
        )
        result["categories"][c] = {"cardinality": cardinality, "top": top}
    result["duplicates"] = {}
    for name in VIEWS:
        print(f"Summarizing exact duplicate view: {name}", flush=True)
        result["duplicates"][name] = duplicate_summary(db, name)
    result["label_disagreement"] = sum(
        n
        for (b, a), n in result["cross"].items()
        if b not in {"0", "1"} or (a == "Benign") != (b == "0")
    )
    result["unknown_attacks"] = sorted(set(result["attacks"]) - KNOWN_ATTACKS)
    result["cross"] = [
        {"binary": b, "attack": a, "rows": n}
        for (b, a), n in sorted(result["cross"].items())
    ]
    result["correlation_sample"] = (
        sample[NUMERIC]
        .apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .corr()
        .to_dict()
    )
    result["correlation_sample"] = {
        a: {b: v if np.isfinite(v) else None for b, v in values.items()}
        for a, values in result["correlation_sample"].items()
    }
    result["sample_rows"] = len(sample)
    return result


def audit(input_dir, output_dir, *, chunk_size=50000, sample_size=30000, temp_dir=None):
    if chunk_size <= 0 or sample_size <= 0:
        raise ValueError("chunk_size and sample_size must be positive")
    start = time.monotonic()
    source, bag, archive = discover(input_dir)
    output_dir = Path(output_dir).resolve()
    raw = (ROOT / "data/raw").resolve()
    for dest in [
        output_dir,
        Path(temp_dir).resolve() if temp_dir else Path(tempfile.gettempdir()).resolve(),
    ]:
        if dest.is_relative_to(Path(input_dir).resolve()) or dest.is_relative_to(raw):
            raise ValueError(
                "Output and temporary directories must be outside raw input directories"
            )
        if dest == source or dest == archive:
            raise ValueError("Output path would overwrite a source")
    # Snapshot all inputs before hashing; stat guard plus final full rehash below.
    paths = [p for p in bag.rglob("*") if p.is_file()] + [archive]
    before = {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in paths}
    print(f"Validating extracted BagIt files and ZIP (read-only): {source}", flush=True)
    provenance = integrity(bag, archive)
    print(
        f"Integrity {'PASS' if provenance['ok'] else 'FAIL'}; indexing exact token vectors",
        flush=True,
    )
    with (
        tempfile.TemporaryDirectory(prefix="cyberguard_nf_", dir=temp_dir) as temp,
        closing(sqlite3.connect(str(Path(temp) / "audit.sqlite"))) as db,
    ):
        db.execute("PRAGMA cache_size=-65536")
        db.execute("PRAGMA temp_store=FILE")
        db.execute("PRAGMA journal_mode=OFF")
        result = scan(source, db, chunk_size, sample_size)
        result["sqlite_bytes"] = (Path(temp) / "audit.sqlite").stat().st_size
    print("Checking endpoint-connected components (diagnostic only)", flush=True)
    result["host_components"] = host_components(source, chunk_size)
    result["export_patterns"] = export_patterns(
        source, chunk_size, result["numeric"]["FLOW_DURATION_MILLISECONDS"]["max"]
    )
    if before != {p: (p.stat().st_size, p.stat().st_mtime_ns) for p in paths}:
        raise ValueError("Input files changed during analysis; refusing reports")
    for p in paths:
        with p.open("rb") as stream:
            digest = hashes(stream)["sha256"]
        expected = (
            provenance["archive_hash"]["sha256"]
            if p == archive
            else provenance["files"][p.relative_to(bag).as_posix()]["sha256"]
        )
        if digest != expected:
            raise ValueError("Input checksum changed during analysis; refusing reports")
    with (bag / "data/NetFlow_v1_Features.csv").open(
        newline="", encoding="utf-8"
    ) as feature_stream:
        feature_dictionary = list(csv.DictReader(feature_stream))
    result.update(
        {
            "source": str(source.relative_to(ROOT))
            if source.is_relative_to(ROOT)
            else str(source),
            "provenance": provenance,
            "versions": {
                "python": platform.python_version(),
                "pandas": pd.__version__,
                "numpy": np.__version__,
                "sqlite": sqlite3.sqlite_version,
            },
            "chunk_size": chunk_size,
            "sample_size": sample_size,
            "seconds": round(time.monotonic() - start, 2),
            "peak_rss_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
            "bag_metadata": (bag / "bag-info.txt").read_text(),
            "further_information": (bag / "FurtherInformation.txt").read_text(),
            "feature_dictionary": feature_dictionary,
            "feature_views": VIEWS,
        }
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "audit.json").write_text(
        json.dumps(result, indent=2, allow_nan=False) + "\n"
    )
    write_reports(result, output_dir)
    print(
        f"Audit complete: {result['rows']:,} rows, {result['seconds']:.1f}s, {result['peak_rss_mib']:.1f} MiB RSS; {output_dir}",
        flush=True,
    )
    return result


def write_reports(r, out):
    # Numerical evidence is regenerated from the full scan; design text never fits data.
    n = r["rows"]
    fig = out / "figures"
    fig.mkdir(exist_ok=True)
    for label, key in [("multiclass", "attacks"), ("binary", "binary")]:
        names = sorted(r[key])
        counts = [r[key][x] for x in names]
        svg_bars(
            fig / f"{label}_distribution.svg",
            f"NF-CSE-CIC-IDS2018 {label} distribution",
            names,
            [("full downloaded CSV", counts, n)],
        )
    provenance = r["provenance"]
    classes = table(
        ["Attack (verbatim)", "Rows", "Percent"],
        [
            (a, f"{v:,}", f"{100 * v / n:.6f}%")
            for a, v in sorted(r["attacks"].items(), key=lambda p: (-p[1], p[0]))
        ],
    )
    checksum_table = table(
        ["Extracted relative file", "Bytes", "SHA-1", "SHA-256"],
        [
            (p, x["bytes"], x["sha1"], x["sha256"])
            for p, x in provenance["files"].items()
        ],
    )
    binary_table = table(
        ["Label (verbatim)", "Rows", "Percent"],
        [(a, v, f"{100 * v / n:.6f}%") for a, v in sorted(r["binary"].items())],
    )
    decision = (
        "Conditional offline design candidate"
        if provenance["ok"] and not r["label_disagreement"] and not r["unknown_attacks"]
        else "NO-GO: resolve integrity/label failures"
    )
    overview = f"""# NF-CSE-CIC-IDS2018: overview

Audit scope: one downloaded CSV, read-only. No model training, preprocessing implementation, partitions, BoT-IoT test access or API/dashboard changes. All numerical counts below come from this download. [Machine-readable evidence](audit.json) includes cross-tabs, examples, run settings and checksums.

## Provenance and integrity

Source: `{r["source"]}`. The supplied `bag-info.txt` attributes the bag to the University of Queensland, School of Information Technology and Electrical Engineering, contact/creator Mohanad Sarhan; Bagging-Date 2023-05-11, BagIt 0.96, UTF-8. This is a packaging date, **not capture time**. `FurtherInformation.txt` directs readers to [UQ metadata/licensing](https://espace.library.uq.edu.au/view/UQ:b9ed88b). That page returned HTTP 403 during this audit; licensing and upstream exporter configuration were not independently verified. Local metadata and feature definitions are the evidence used here. No published row counts were substituted.

Manifest validation: **{"PASS" if provenance["ok"] else "FAIL"}**. {len(provenance["manifests"])} declared payload/tag SHA-1 comparisons checked, with exact payload inventory coverage. {len(provenance["archive_comparisons"])} ZIP files were streamed without extraction; CRC checking and SHA-256/byte-size comparisons against the extracted bag passed: {all(x["ok"] for x in provenance["archive_comparisons"])}. Archive bytes: {provenance["archive_bytes"]:,}; SHA-256 `{provenance["archive_hash"]["sha256"]}`. The ZIP inventory exactly matches the bag. The supplied tag manifest does not list `FurtherInformation.txt`; its recorded SHA-256 and archive match are additional local consistency evidence, not a supplied manifest check. SHA-1 validates the supplied manifest but is not an authenticity signature. Matching local files cannot prove origin, licensing or label truth. All input SHA-256 hashes were rechecked after the scan; inputs remained unchanged.

{checksum_table}

## Shape and labels

**{n:,} rows × {len(r["columns"])} columns**, including two labels and 12 candidate predictors (two IP identifiers). CSV bytes: {provenance["files"]["data/NF-CSE-CIC-IDS2018.csv"]["bytes"]:,}. `Label` and `Attack` are excluded from every predictor view. Both are observed labels, not predictors. The feature dictionary documents only predictors; label meaning is supported by the observed full-file cross-tab: Benign ↔ 0, every other observed Attack ↔ 1. Binary/multiclass disagreement or invalid binary rows: **{r["label_disagreement"]:,}**. This verifies internal agreement, not independent ground-truth correctness. Unexpected spellings against the explicit known-name inventory: {r["unknown_attacks"]}. Preserve original names, including `Infilteration`; do not merge or silently fix names.

{binary_table}

{classes}

![Binary counts, logarithmic widths](figures/binary_distribution.svg)
![Multiclass counts, logarithmic widths](figures/multiclass_distribution.svg)

Smallest classes need group-support checks before multiclass claims. These are raw record supports, not independent episodes. The benign population here must not be confused with the 370 benign BoT-IoT training rows; cross-dataset schemas and label meanings differ.

## Resources and reproducibility

Executed with Python 3.13 and existing pandas/NumPy/SQLite, CPU only, no new ML library. Versions: `{r.get("versions", {})}`. `uv run python scripts/inspect_nf_cse.py --chunk-size {r["chunk_size"]} --sample-size {r["sample_size"]}`. Main audit command took {r["seconds"]:.2f} seconds before report rendering; supplementary diagnostics (if run separately) took {r.get("supplemental_diagnostics_seconds", 0):.2f} seconds; Measured main-process peak RSS {r["peak_rss_mib"]:.1f} MiB (Linux); supplemental-process peaks were not separately recorded. Measured deep string-column footprint summed over chunks: {r["string_memory_bytes"] / 2**30:.3f} GiB (projection of retaining all token columns, excludes whole-frame/index/allocator overhead). Largest raw chunk {r["peak_chunk_bytes"] / 2**20:.1f} MiB. Measured SQLite index {r["sqlite_bytes"] / 2**30:.3f} GiB before cleanup. Measurement scope: {r.get("measurement_notes", "All declared views indexed in one run.")} Numeric float64 matrix upper estimate for all 10 non-IP predictors: {n * 10 * 8 / 2**30:.3f} GiB; additional encoder/binning/training copies can multiply this. The proposed seven-input float64 matrix alone would require {n * 7 * 8 / 2**30:.3f} GiB before categorical/status fields and fit copies. Labels are not added to that predictor matrix.

Use 25k–50k chunks and at most 30k sampled rows. SQLite has a 64 MiB page cache and disk-backed sorts; budget at least 8 GiB free temporary disk for the combined views/sorts, plus source/archive storage for a rerun (sorts may require extra disk). Temporary DB is removed on success/failure. Full-file moments/counts/duplicate results are exact under the documented token identity; quantiles and correlations use the seeded {r["sample_rows"]:,}-row priority sample and are descriptive only. Sample seed 20261115, independent of chunk boundaries. Runtime/RSS vary; analytical evidence is deterministic. No worker pool/GPU.

16 GB is adequate for this audit. For later training, materialize only selected typed numeric arrays/compact groups, one fit at a time with bounded threads, and measure peak RSS including fit copies; do not keep raw string frames, expanded duplicates and multiple model matrices simultaneously. Initial recommendation: bounded `HistGradientBoostingClassifier` with early stopping disabled unless given a predeclared group-safe inner validation. Scikit-learn is already installed. No LightGBM dependency is installed by this task; a bounded-depth/leaf RandomForest with limited trees and `n_jobs` is a secondary option, likely costlier. No fit has been attempted or timed.

## Status and next steps

**{decision}. NO-GO for live/partial-flow claims or independent deployment-performance claims.** Confirm exporter timing/orientation/units and collect source-session provenance. If integrity failed, unknown labels or schema violations are present, resolve them before training. Freeze the feature and label contract, evaluate group-support feasibility, then authorize preprocessing/splitting/training as a later phase. See [feature audit](feature_audit.md), [quality](data_quality.md), [evaluation design](evaluation_strategy.md), [preprocessing](preprocessing_design.md) and [integration](integration_plan.md). NF-CSE model **not trained**.
"""
    (out / "overview.md").write_text(overview)
    quality_reports(r, out)
    design_reports(r, out)


def quality_reports(r, out):
    rows = []
    for c in r["columns"]:
        x = r["issues"][c]
        s = r["numeric"].get(c, {})
        rows.append(
            (
                c,
                ",".join(r["dtype_observations"][c]),
                x.get("blank", 0),
                x.get("na_token", 0),
                x.get("infinite", 0),
                x.get("invalid_numeric", 0),
                x.get("invalid_ipv4", 0),
                x.get("fractional", 0),
                s.get("min", "—"),
                s.get("max", "—"),
            )
        )
    stats = table(
        [
            "Column",
            "Observed semantic types",
            "Blank",
            "NA token",
            "Inf",
            "Invalid number",
            "Invalid IPv4",
            "Fractional",
            "Min",
            "Max",
        ],
        rows,
    )
    moments = table(
        [
            "Numeric column",
            "Finite N",
            "Mean",
            "Sample std",
            "Population skew",
            "Sample p01/p50/p95/p99",
        ],
        [
            (
                c,
                s["finite"],
                s["mean"],
                s["std"],
                s["skew_population"],
                s["sample_quantiles"],
            )
            for c, s in r["numeric"].items()
        ],
    )
    dups = table(
        [
            "View",
            "Distinct vectors",
            "Repeated vector groups",
            "Rows in repeated vectors",
            "Vector excess",
            "Exact record excess",
            "Conflicting groups",
            "Rows in conflicts",
            "Largest group",
        ],
        [
            (
                v,
                d["distinct_vectors"],
                d["repeated_vector_groups"],
                d["rows_in_repeated_vectors"],
                d["vector_duplicate_excess"],
                d["exact_record_duplicate_excess"],
                d["conflicting_groups"],
                d["rows_in_conflicting_groups"],
                d["largest_group_rows"],
            )
            for v, d in r["duplicates"].items()
        ],
    )
    cats = table(
        ["Column", "Exact token cardinality", "Most frequent tokens/counts (up to 10)"],
        [(c, d["cardinality"], d["top"]) for c, d in r["categories"].items()],
    )
    support = table(
        [
            "Attack",
            "Full predictor groups",
            "No-IP completed groups",
            "Duration-inclusive groups",
            "Initial completed groups",
            "Header-only groups",
        ],
        [
            (
                a,
                *[
                    {
                        row[0]: row[2] for row in r["duplicates"][v]["per_class_groups"]
                    }.get(a, 0)
                    for v in VIEWS
                ],
            )
            for a in sorted(r["attacks"])
        ],
    )
    (out / "data_quality.md").write_text(f"""# NF-CSE-CIC-IDS2018: data quality

## Schema and values

All CSV fields are read as UTF-8 strings to preserve token identities and avoid chunk-dependent coercion. Semantic types below describe numeric convertibility in every chunk, not a pandas whole-file guessed dtype. `L7_PROTO` is a numeric-looking categorical code; fractional values do not establish measurement semantics. NA-like tokens are audited separately from truly blank fields; numeric infinities and invalid tokens are separate. Fractional ports/counts/flags would need rejection; fractional L7 IDs are retained for semantic investigation. Negative totals are invalid candidates, not silently clamped. Exact issue examples/counts are in [audit.json](audit.json).

{stats}

Full-file negative-value counts: { {c: x.get("negative", 0) for c, x in r["issues"].items() if x.get("negative", 0)} }.

Exact constants: {r["constants"]}. Near constants (>=99% one exact token but not constant): {r["near_constants"]}. These are verified by a second full-file pass after bounded majority-candidate tracking; no high-cardinality numeric frequency table is held in RAM. No claim is made about the mode when below 50%. Globally identical token columns: {r["duplicate_columns"]}. This tests every pair over every row, independently of numeric correlations.

Whitespace/non-ASCII/control-character occurrences: { {c: {k: v for k, v in x.items() if k in ["whitespace", "non_ascii", "control"] and v} for c, x in r["issues"].items() if any(x.get(k, 0) for k in ["whitespace", "non_ascii", "control"])} }. Strict UTF-8 decode errors abort rather than replacing bytes. No Unicode repair is applied.

## Magnitudes and artifacts

{moments}

Header/flow rule counts (full file):

{table(["Rule", "Rows"], sorted(r["rules"].items()))}

Port zero is legal and is not automatically missing. Nontransport port tokens, absent reverse packets and zero duration need exporter semantics; zero reverse totals do not prove absence of reverse visibility in capture. Large durations and totals may reflect units, timeout/counter/export behavior. The supplied dictionary says milliseconds but does not define timestamp origin, timeout, counter width or sampling. Do not infer a correction factor, clip tails or diagnose overflow from extremes alone. Obtain exporter configuration or source traces. Cumulative TCP flags are not per-packet flags.

{cats}

Categorical L7 values are kept as exact tokens, including composite-looking decimal IDs; do not round or treat their numeric distance as meaningful. IPs are syntactically audited but endpoint roles cannot be inferred reliably from address strings alone. Top IPs may reveal testbed concentration; raw addresses must not be predictors.

## Export-duration boundary investigation

The full-file maximum duration is {r["numeric"]["FLOW_DURATION_MILLISECONDS"]["max"]} in the dictionary's stated milliseconds; sample quantiles are above. Counts below are a separate full-file check at exactly the maximum, zero and >=99% of the observed maximum (a diagnostic range, not a clipping rule):

{table(["Attack", "Rows", "Zero duration", "Exactly maximum", ">=99% of observed maximum"], [(a, x["rows"], x["zero"], x["at_maximum"], x["within_top_one_percent_of_range"]) for a, x in r.get("export_patterns", {}).get("by_class", {}).items()])}

A concentration near a numeric ceiling can be an exporter/timer artifact or a property of the observations. The measured maximum 4,294,967, when present, is also floor((2^32−1)/1000), an arithmetic pattern only; **no overflow, unit-conversion bug or causal explanation is established**. Source exporter configuration and original timing are needed. Do not invert, rescale, clip or learn an attack rule from this pattern without verification. Compare duration-free sensitivity later using validation only.

## Exact duplicates and ambiguity

{dups}

Views (ordered column lists): {json.dumps(VIEWS)}.

Keys are exact JSON arrays of **parsed CSV token strings**, compared directly in SQLite B-trees, without probabilistic hashes. Quoting or newline-format differences in the CSV serialization are not different record values. `all_predictors` plus both labels represents exact full records. Other exact-record-excess columns mean records projected onto that view plus both labels. Vector excess = rows − distinct vectors; exact-record excess = rows − distinct (vector, binary, attack) tuples; repeated-vector rows include the first occurrence. A conflict means >1 distinct label pair for identical retained tokens. It need not imply annotation error: removal of context creates irreducible ambiguity. No record is dropped, no majority relabeling performed. Alias/number normalization may create additional collisions; these counts are **not yet canonical preprocessing keys**. Future canonical retained keys require a new group audit before partitioning.

{support}

These counts are overlapping class supports: a mixed-label group contributes to each affected class, so they cannot be summed as disjoint episodes. Audit JSON retains five deterministic conflict examples per view with label counts. Representative first examples (vectors in the view order listed above):

{table(["View", "Retained vector (exact tokens)", "Binary / Attack / row multiplicities"], [(v, e["vector"], e["labels"]) for v, d in r["duplicates"].items() for e in d["conflict_examples"][:2]])}

The observed examples include `Brute Force -Web` and `Brute Force -XSS` sharing UDP port-500 flow vectors, and a header-only UDP/123 vector shared by Benign and Infilteration. This raises label-granularity/background-traffic and scenario-generation questions: an attack-labelled record need not contain evidence of that attack in the retained fields. The examples do not prove which source annotation, if any, is wrong. Full-feature conflicts cannot be repaired from these features; no timestamp/session mapping is available to distinguish repeated similar events. An example can contain raw addresses for audit only, never for serving/training. Identical retained vectors must stay together; random-row splits can copy them into evaluation and amplify repeated scenario signatures. Report both original-row-weighted and equal-vector diagnostics later; weighting does not create independent sessions. Exact-key separation also cannot eliminate correlated neighboring flows or repeated campaigns.

## Correlations

Sampled Pearson correlation matrix, numeric-coded columns including `Label`, is saved only as diagnostics in `audit.json` (`correlation_sample`). Labels are never predictors; protocol/L7 numeric-code correlation has no ordinal interpretation. Correlation is not evidence of causal feature availability, redundancy or leakage-free behavior. Global identical-column test above is stronger for exact duplication. Quantiles/correlations use a seeded priority sample; very rare classes may be absent, so they cannot support rare-class distribution conclusions. No target-driven feature selection is performed.
""")


def design_reports(r, out):
    definitions = {
        row["Feature"]: row["Description"] for row in r["feature_dictionary"]
    }
    decisions = {
        "IPV4_SRC_ADDR": (
            "A/E",
            "One IPv4 header; raw host identity / scenario memorization. Exclude; retain privately for split diagnostics.",
        ),
        "IPV4_DST_ADDR": (
            "A/E",
            "One IPv4 header; raw endpoint identity. Exclude; host split may use both endpoints conservatively.",
        ),
        "L4_SRC_PORT": (
            "A/E",
            "TCP/UDP header where available; service/tool artifact risk. Include with protocol-aware validity/status; direction must match exporter.",
        ),
        "L4_DST_PORT": (
            "A/E",
            "TCP/UDP header; service/scenario proxy risk. Include, assess service sensitivity later.",
        ),
        "PROTOCOL": (
            "A/E",
            "IP header identifier; include categorically; protocol mix can encode scenario.",
        ),
        "L7_PROTO": (
            "F/E",
            "Layer-7 numeric code; classifier/version/codebook and number of packets needed unknown. Exclude initial fit, including decimal sub-IDs; may proxy traffic generator or exporter.",
        ),
        "IN_BYTES": (
            "B/C/F",
            "Running forward bytes possible, but CSV is an exported total; byte accounting and orientation unverified. Include only for offline finalized-record baseline, never substitute partial bytes.",
        ),
        "OUT_BYTES": (
            "B/C/D/F",
            "Reverse/outgoing total; use only with compatible two-direction exporter and finalization. Zero is not missing by default.",
        ),
        "IN_PKTS": (
            "B/C/F",
            "Running forward count possible; current record total requires end/timeout. Include only finalized records.",
        ),
        "OUT_PKTS": (
            "B/C/D/F",
            "Reverse count requires reverse visibility; include only finalized records with verified orientation.",
        ),
        "TCP_FLAGS": (
            "A/B/C/F",
            "Individual flags are headers, but supplied cumulative flags include later packets. Reverse-direction aggregation and bit semantics unspecified; exclude first fit pending specification.",
        ),
        "FLOW_DURATION_MILLISECONDS": (
            "B/C/F",
            "Elapsed duration possible causally, but final exported duration is available at termination/timeout. Quarantine from initial fit: class-aligned zeros and ceiling concentration require exporter/timing evidence.",
        ),
        "Label": ("E", "Binary target only. Never input or imputation feature."),
        "Attack": ("E", "Multiclass target only. Preserve exact labels; never input."),
    }
    feature_table = table(
        [
            "Column",
            "Supplied description",
            "Categories",
            "Initial decision / observation boundary",
        ],
        [
            (c, definitions.get(c, "Not in supplied feature dictionary"), *decisions[c])
            for c in r["columns"]
        ],
    )
    (
        out / "feature_audit.md"
    ).write_text(f"""# NF-CSE-CIC-IDS2018: feature availability and leakage

Evidence: local `data/NetFlow_v1_Features.csv`, actual CSV schema and value audits. The dictionary does not specify exporter software/version, direction, counter accounting, timeouts, packet sampling, L7 codebook or exact flag aggregation. Availability classifications are conservative design judgments, not a validated packet extractor.

A = packet header; B = possible causal running feature **with a specified cutoff**; C = final/exported flow value; D = reverse/bidirectional observation; E = identifier/label or scenario leakage risk; F = undocumented/ambiguous semantics. Multiple categories distinguish what could be derived from packets from what this exported column represents.

{feature_table}

## Initial feature contract

Recommend an **offline finalized-flow CSV experiment** with seven non-IP inputs: `PROTOCOL`, `L4_SRC_PORT`, `L4_DST_PORT`, `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`. Three header fields plus four final counters are proposed. Exclude both IPs, both labels, `L7_PROTO`, `TCP_FLAGS` and duration. The duration audit shows class-aligned zeros and a strong concentration near a numerical ceiling, so duration is quarantined from the initial fit until its export semantics are verified; do not silently correct it. Final values and reverse totals are allowed only under this explicitly completed-flow task. Counter accounting and direction verification are gates before using the four flow counters in any inference adapter. If those gates cannot be satisfied, restrict to the three header fields as an offline comparison and disclose its ambiguity counts in [quality](data_quality.md).

Packet-level classification: only the protocol/port subview is potentially header-accessible, subject to fragmentation, TCP/UDP availability and orientation; a flow-export classifier is not packet-validated. Partial-flow classification: **not supported by these final-record labels/features alone**; requires source captures, a defined cutoff, causal counters and a separate train/evaluation dataset matching that cutoff. Completed-flow classification: plausible offline use of the seven-input contract, with unknown exporter semantics explicitly gated; predictions wait for termination or configured timeout. No capture, replay, exporter, flow finalizer or live detection is implemented.

IP exclusion does not remove service/tool/host fingerprints in ports, protocol, zero counters or duration artifacts. Cumulative flags may encode teardown/outcome and L7 detection may need future packets; do not reintroduce them as a performance shortcut. No capture-wide historical aggregates are present in this 12-predictor schema, but upstream generation/sampling artifacts remain unverified. High correlations alone cannot clear a feature for deployment.
""")
    (
        out / "evaluation_strategy.md"
    ).write_text(f"""# NF-CSE-CIC-IDS2018: proposed evaluation strategy (not executed)

## Independence evidence

The 14-column CSV has IPv4 source/destination, ports, protocol, L7 code, totals, flags, duration and labels. There are **no capture IDs, absolute timestamps, session IDs, campaign IDs, flow IDs or original capture-day fields**. Flow duration is not an absolute timestamp. Bagging date is packaging metadata. Row order and the five-tuple must not be manufactured into temporal/capture/session IDs; repeated endpoint/port pairs can be many flows. Attack names describe categories/tools, not distinct episode identities. Feature dictionary/BagIt metadata supply no per-row mapping back to captures.

Distinct observed source IP tokens: {r["categories"]["IPV4_SRC_ADDR"]["cardinality"]:,}; destination IP tokens: {r["categories"]["IPV4_DST_ADDR"]["cardinality"]:,}. IPs make endpoint-held-out experiments technically possible but do not establish stable device identities (NAT, address reuse), balanced class support or campaign independence. Shared endpoints can connect many rows into one component. A bounded two-pass diagnostic joins every row's two endpoint tokens into connected components (up to 200,000 distinct hosts; stops explicitly if exceeded). These graph components are **not sessions or devices**; malformed IPv4 tokens are retained as tokens, not repaired or interpreted as real host identities. A host-based design would need a declared invalid-address policy and a new graph audit, while keeping every excluded-from-diagnostic row visible. Actual diagnostic: {r.get("host_components", {}).get("components", "not established")} components across {r.get("host_components", {}).get("hosts", "not established")} endpoint tokens; largest component has {r.get("host_components", {}).get("largest_component_rows", "not established")} rows and {r.get("host_components", {}).get("largest_component_hosts", "not established")} hosts. Full completion/budget status is in audit JSON.

{table(["Attack", "Endpoint components", "Rows in largest supporting component", "Total rows"], [(a, x["components"], x["largest_component_rows"], x["rows"]) for a, x in r.get("host_components", {}).get("per_class", {}).items()])}

On this download, fewer than three components overall and one component per attack class make a three-way, both-endpoint-disjoint split retaining all classes infeasible without dropping/reassigning observations. This is a graph constraint, not proof of a single campaign. Three-way host-disjoint splitting requires at least three supported components per class; a single shared component cannot be divided while preserving both endpoints disjoint. No host partition was created. Even feasible graph separation would need independent capture evidence.

## Priority and gates

1. Obtain original capture/session mappings and exporter settings. Prefer sessions/captures held out across fit/validation/test; inspect independent class/benign support per unit before freezing. If timestamps become available, hold later periods out and keep sessions/duplicates from crossing boundaries. Avoid label-aware searches for an advantageous partition.
2. Otherwise use the endpoint graph diagnostic above to assess whether further host-held-out work is feasible; consider both endpoints (not only source), class counts and dominant shared infrastructure. A host-disjoint split requires no source/destination host overlap, enough independent components and all target classes. If common servers collapse components or rare classes reside on one host, report infeasibility and seek new captures; do not silently fall back while claiming host independence.
3. Current-file fallback: deterministic exact **canonical retained-feature group** partition, nominal 60/20/20 fit/validation/reserved test. Freeze schema, canonicalization, seed and label vocabulary before assigning; proposed fixed seed 20261115, SHA-256 of the schema-version/seed/unlabelled canonical JSON key, first 64 bits mapped uniformly to [0,1): <0.6 fit, [0.6,0.8) validation, >=0.8 reserved test. This is a proposed rule, not executed; no repeated seed search. Keep every label/count for a mixed group together. Full raw-vector grouping alone is insufficient after removing identifiers or rounding/collapsing tokens. The seven-input view is audited as `initial_completed`; `duration_inclusive` adds duration, and the ten-input no-IP view also includes L7/flags. These exact-token counts still need a canonical-key audit after protocol/port and missingness rules are frozen. Header-only counts show the stricter restriction.

## Support and conflict feasibility

{table(["Attack", "Full groups", "No-IP completed groups", "Duration-inclusive groups", "Initial completed groups", "Header groups"], [(a, *[{row[0]: row[2] for row in r["duplicates"][v]["per_class_groups"]}.get(a, 0) for v in VIEWS]) for a in sorted(r["attacks"])])}

Counts above are exact token vector groups with at least one record of that class, not independent sessions. Mixed-label groups count for multiple classes. Current conflicts: { {v: d["conflicting_groups"] for v, d in r["duplicates"].items()} }. They cannot be separated by label without leaking identical inputs. A rare class with fewer than three groups cannot support all three partitions at all; more than three is necessary but not sufficient under a fixed assignment. Even hundreds of header groups could all belong to one attack episode. Before training, verify each frozen partition has every promised class and enough independent benign/minority groups. If not, stop the multiclass claim, report unsupported labels explicitly and obtain data or justify a separate binary experiment; never relabel to Benign, silently merge/drop a class or reshuffle until scores look good. No partitions or split manifest have been created here.

## Fitting and reporting boundaries

All learned imputation, encoding, scaling/clip thresholds, constant removal and class weights use **fit only**. Validation supports model/configuration choice and probability-threshold decisions; it is not included in final fitting in the proposed experiment. Any early-stopping subdivision must also respect groups; disable automatic random-row early stopping for the initial HistGradientBoosting fit. Reserve the test once in a manifest with input SHA-256, feature/schema version, seed, groups, labels/counts and code versions. Freeze the model and all thresholds before one test evaluation; no repeated test-based tuning. If capture/time boundaries conflict with exact-key separation, purge/quarantine overlapping earlier groups by a predeclared rule and report counts; do not move future data backwards to optimize support.

Preserve original multiplicities and conflicts; no silent deduplication or majority vote. Future compact representation can weight original counts, but bounded estimator support for weights and leaf semantics must be checked. Balancing/reweighting only in fit, no synthetic benign examples or oversampled validation/test. Report original-row metrics plus equal-vector diagnostics; neither proves event independence.

Report macro-F1, balanced accuracy, per-class precision/recall/F1/support (including zero-support definitions), fixed-order raw and normalized confusion matrices, binary benign FPR = benign predicted attack / all benign, and malicious detection recall. For multiclass, any non-Benign prediction counts toward benign FPR. Include precision-recall metrics when probability scores are available; probabilities require calibration evidence before being called confidence. Report minority group/host/session support and group-based uncertainty where defensible. Accuracy and raw-row support alone can conceal near-duplicate domination.

This fallback measures held-out input combinations within one exported environment, **not independent capture, future traffic or deployment performance**. It is stronger than a random-row split but cannot repair missing provenance. The supplied BoT-IoT official test remains untouched and has no role in this dataset's split or model selection. NF-CSE is one file with no supplied official split; the proposed reserved test is new and has not been created.
""")
    (
        out / "preprocessing_design.md"
    ).write_text(f"""# NF-CSE-CIC-IDS2018: preprocessing design only

Nothing in this document is a fitted or implemented inference pipeline. The audit's string/numeric parsing and exact-token keys serve measurement only. Raw data remain unchanged. Initial task is offline finalized-flow prediction; see [feature boundary](feature_audit.md).

| Proposed operation | Rationale / policy | Deterministic vs learned | Inference parity / fit scope |
| --- | --- | --- | --- |
| Explicit allowlist | Seven inputs: PROTOCOL, L4_SRC_PORT, L4_DST_PORT, IN_BYTES, OUT_BYTES, IN_PKTS, OUT_PKTS. Exclude IPs, labels, L7, flags and duration; quarantine duration pending exporter evidence. Keep originals for audit only. | Fixed schema, no fit | Version/order/types in artifact; reject missing fields and ambiguous aliases. Never derive an input from target. |
| Strict numeric parsing | Validate finite whole nonnegative counts/duration, protocol byte range, TCP/UDP integer ports 0–65535. Do not infer duration corrections from distribution. | Fixed rules, no fit | Same parser/units at inference; invalid values explicit, count/reason surfaced, no clamping to valid service IDs. Use adequate integer widths before optional float conversion. |
| Protocol | Canonical numeric byte / fixed known protocol aliases, categorical semantics. Unknown/out-of-range/missing distinct. Avoid assuming all protocols have ports. | Fixed canonical rules; one-hot categories learned if used | Fit encoder only on fit, unknown category safe; freeze mapping. HistGradientBoosting may use predeclared native categories if bound satisfied. Never apply ordinal numeric distance to protocol codes casually. |
| Ports and sentinels | TCP/UDP only; valid zero retained. Missing, sentinel (-1/-), invalid and not-applicable separate; nontransport fields not decoded as TCP/UDP ports. Preserve offending raw tokens in diagnostics. | Fixed rule/status/range derivations | Reuse design principles, not silently the BoT parser: NF exporter contract needs its own tests. Numeric port plus status and optional fixed service range; validate orientation. |
| Missing / infinite / invalid | Distinguish source blank/NA-like, parse errors and infinity. Reject structural schema/invalid label rows; no silent exclusions. For feature missingness, either explicit supported native NaN or median + status indicators. | Fixed detection; medians learned only if chosen | Learned statistics fit-only, serialized with model; fail if a required feature is entirely missing. Expose invalid counts. Native NaN handling must be checked in selected estimator. |
| Final counters; duration quarantined | Nonnegative finite values; reverse visibility and exporter counters/timeout must match. Heavy tails investigated; do not declare zero invalid automatically. | Fixed checks, optional log1p fixed | No partial counters substituted for final totals. Log1p only after range validation. Obtain unit evidence; reject incompatible units. |
| Scaling / outliers | Histogram trees usually need no scaling. No automatic tail deletion, winsorization or rare attack suppression. Investigate extreme durations/bytes with source provenance. | No scaling initially; any later thresholds/scalers learned fit-only | Freeze any later transformation; retain original diagnostics. Do not select thresholds using validation/test class separation. |
| Constants / redundancy | Audit-wide constants are descriptive, not final feature selection. Fit-only constant detection; near constants may encode rare classes. Exclude by semantic availability first. | Learned on fit only | Frozen column mask; do not fit/drop based on reserved test. Correlation alone is not a drop rule. |
| Group identity | Build canonical retained feature/status vector key before assignment; no labels/IPs/row numbers in key. Fixed precision/unit rules; count new collisions. | Fixed deterministic normalization; no learned imputation in grouping | Group key must also cover inputs made equal by chosen transform. For learned imputation collapse, audit cross-partition transformed overlaps without choosing on test performance; predeclare quarantine/failure rule. |
| Labels / imbalance | Preserve all exact Attack names; binary 0/1 verified by cross-tab. Benign distinct from every attack. Separate binary and full multiclass experiments; explicitly report unsupported classes if support fails. | Frozen label vocabulary; weights learned from fit counts only | No class merging, vote relabeling, synthetic benign data or resampling validation/test. Inverse-frequency weights may be extreme; cap only by predeclared policy evaluated on validation. |

Recommended first task: the supplied binary `Label` target, explicitly retaining all {len(r["attacks"])} original `Attack` names for support/error analysis; this uses the provided binary definition, not a new silent category merge. A separate full {len(r["attacks"])}-class task is gated on per-partition minority support and disclosed ambiguity; SQL Injection has {r["attacks"].get("SQL Injection", 0)} records in this download; record count does not establish independent episodes. Recommended first estimator: a fixed, CPU-only bounded HistGradientBoostingClassifier (modest max_iter/max_leaf_nodes, explicit random_state and early_stopping=False); no parameter search initially. Persist complete schema + deterministic normalizer + fit-only transforms + estimator + vocabulary + source/group manifest hashes. Check installed scikit-learn categorical/weight support before implementation. Keep model artifact separate from BoT-IoT. Do not infer timing, memory or performance from algorithm reputation: benchmark one bounded fit only after pipeline tests and authorization.

Required implementation tests later: schema aliases/order/extra-field policy; malformed, negative, fractional and infinite numeric values; zeros and sentinels; protocol-dependent port semantics; IPv4/label exclusion invariance; canonical group equality and conflicts; no groups crossing any partition; train-only learned statistics/weights; serialization/inference parity; native NaN and unknown categories; all class supports and metric denominators. Synthetic fixtures test software only, not generalization.

Open gates: exporter direction/orientation, byte accounting, duration units/extreme values, timeout behavior, capture mappings, L7 codebook, TCP flag bit semantics, licensing and independent benign/attack support. Current values are not evidence that these are resolved.
""")
    (
        out / "integration_plan.md"
    ).write_text("""# NF-CSE-CIC-IDS2018: CyberGuard integration proposal

No serving/UI changes or model switching are implemented. NF-CSE has no trained artifact. Existing BoT-IoT behavior and artifacts are preserved.

## Actual constraints in current code

- `src/cyberguard/core/schemas.py`: NetworkRecord requires exactly proto/sport/dport (strict string/integer/null, extras forbidden); response labels are Literal Normal/DoS/DDoS/Reconnaissance.
- `src/cyberguard/inference/network_detector.py`: constructor and predict_frame require the three-feature order and fixed four classes, select those inputs, validate probability columns and emit BoT-specific warning. A differently shaped artifact cannot be swapped in safely.
- `src/cyberguard/inference/model_loader.py`, API lifespan/dependencies/config: trusted joblib loading and per-app startup ownership currently serve one detector. A different file path does not provide a different schema or class contract automatically.
- `src/cyberguard/dashboard/api_client.py`: metadata and OpenAPI validation enforce the three inputs/four classes; it imports strict shared response schemas. `dashboard/batch.py` and test_lab form/labels/colors are also tied to the BoT contract. Existing metadata fields are a useful starting point, not a general registry.
- `src/cyberguard/testing/network_model_cli.py` likewise uses fixed BoT features/labels and protected test/data paths. NF-CSE must not be routed through it by renaming columns and assuming equivalence.

## Later implementation design

Create an allowlisted registry keyed by stable model ID, e.g. `bot-iot-restricted-v1` and a future `nf-cse-finalized-v1` (examples, not runnable IDs). Each entry owns a trusted artifact/hash, input schema/version, feature order/type/unit/range/status rules, finalized versus header observation contract, preprocessing version, label vocabulary, probability support/calibration warning, dataset/group provenance and validation limitations. Binary and multiclass fits need separate model IDs and vocabularies. Do not collapse NF attack names to BoT classes without a separately reviewed taxonomy.

Keep existing endpoints/backward compatibility during a future versioned extension. Add explicit registry discovery and model-specific prediction routes/request types in a later task; never let a caller provide arbitrary artifact filesystem paths. Validate against the selected schema before calling its detector. Keep normalization inside the saved model-specific pipeline, fit nothing at startup/request time, load trusted artifacts once, and return model ID/schema/version/warnings with each result. Probability keys and response validation must derive from the selected vocabulary, not the current four-class Literal. Readiness/errors and per-model limits must be explicit if one registered artifact is unavailable.

Extend safe metadata with bounded declarative fields for frontend rendering: display name, exact feature schema, enum/range/unit/help, requiredness, observation boundary, schema and normalization versions, class labels/colors, supported task and probability status. Validate advertised fields against the loaded model. No arbitrary executable frontend code in metadata.

Dashboard model selection should fetch a compatible schema and clear model-specific input/results/session state on change. Render separate finalized-flow inputs explaining forward/reverse counters and observation boundaries; expose duration units only for a later verified duration-inclusive contract; retain current three-field BoT form for its model. CSV upload must require the selected exact columns, reject duplicate/missing headers and invalid values, preserve row order, enforce size/batch limits, and display model-specific labels/status. Labeled offline evaluation belongs to a separately extended CLI with explicit vocabulary/support policy. Do not imply a finalized-flow form captures live traffic.

Tests before integration: registry unknown ID/path rejection; model/schema/hash mismatch; independent detector lifecycles; old BoT API compatibility; NF units/types/nonfinite handling; class/probability alignment; per-model batch limits; frontend/CSV switching and stale-state clearing; no fit on requests; local trusted artifact and diagnostic sanitization. Update root README alongside every implemented command/route/workflow. Keep the current API and dashboard unchanged until explicitly authorized.
""")


def positive(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--input-dir", type=Path, default=ROOT / "data/raw/nf-cse-cic-ids2018"
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "reports/dataset_analysis/nf_cse_cic_ids2018",
    )
    p.add_argument("--chunk-size", type=positive, default=50000)
    p.add_argument("--sample-size", type=positive, default=30000)
    p.add_argument("--temp-dir", type=Path, default=None)
    args = p.parse_args(argv)
    try:
        audit(
            args.input_dir,
            args.output_dir,
            chunk_size=args.chunk_size,
            sample_size=args.sample_size,
            temp_dir=args.temp_dir,
        )
    except (
        ValueError,
        OSError,
        UnicodeError,
        sqlite3.Error,
        zipfile.BadZipFile,
        StopIteration,
    ) as exc:
        p.exit(2, f"Audit error: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
