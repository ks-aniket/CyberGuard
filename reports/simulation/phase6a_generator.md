# Phase 6A — training-derived NF feature-record generator

Completed 2026-11-15. This phase implements offline feature-record generation only. There is no packet transmission, inference, classifier fitting, background engine, FastAPI change or dashboard integration. Both classifier artifact hashes still match their frozen values. No validation/test records or raw datasets were opened.

## Architecture and source isolation

`src/cyberguard/simulation/` separates immutable configuration (`schemas.py`), train-only profile construction/loading (`profiles.py`), incremental random sampling (`generator.py`), canonical/API validation (`validation.py`), streaming output (`serialization.py`) and descriptive diagnostics (`diagnostics.py`). Both CLI scripts inject the existing `src` path and run without services or model loading. No dependencies were added. `AGENTS.md` already contains the permanent README maintenance instruction; it was preserved.

The builder accepts the sealed processed root and reads only training NPZ shards plus `metadata/split_manifest.json`, its SHA-256 sidecar, and `metadata/feature_contract.json`. The shared manifest must be streamed to verify its common checksum and delimiters; a train-only subclass of the existing manifest parser skips validation/test objects **before decoding**. A context-local Python audit hook denies raw dataset reads, non-allowlisted processed file opens and all processed writes during construction. Paths are resolved, shard filenames constrained, checksums/byte sizes validated, and common feature/preprocessing/source identity checked. Poisoned synthetic held-out metadata and denied-read tests exercise these boundaries. The guard is an application error barrier, not an OS sandbox against arbitrary malicious Python.

The original `multiplicity` weights are retained, including compact rows whose canonical vector occurs under multiple original attack families. No multiplicity expansion, row exclusion, label repair, balancing, feature fitting or partition modification occurs. A complete second build from real **training only**, in a temporary directory, produced byte-identical arrays, SQLite membership index and metadata; the temporary copy was removed.

Verified source manifest SHA-256: `1eda7639ceb8e37ab4da75c80c7d209557a9bfb35cb8ccbaea8f7a49299201ce`.

| Source profile | Original-row weight | Fraction of training population |
| --- | ---: | ---: |
| attack | 612,207 | 12.1507% |
| benign | 4,426,247 | 87.8493% |

Total: **5,038,454 original rows**, **2,855,997 compact rows**, **2,836,328 exact canonical vectors**. All 58 training shards were verified. `source_profile` is a training-distribution label, never independently verified attack/benign behavior.

## Artifacts and representation

Profile version `nf-training-profiles-v1`; generator version `nf-simulation-v1`; input contract `nf-cse-netflow-v1-completed-flow-v1`. Runtime: Python 3.13.12, NumPy 2.5.4, CPU only.

Profiles live at `models/simulation/nf_cse/` (Git-ignored, separate from `models/network/`). `vectors.npy` is a read-only memory-mapped int64 seven-column API representation, `weights.npy` holds uint64 original multiplicities, `labels.npy` holds uint8 source labels. `membership.sqlite` contains all unique canonical vectors as exact 56-byte little-endian keys, without using labels. `metadata.json` records every training-shard hash, source identity, file-open inventory, version, method, feature order and artifact hashes. Checksum verification occurs once per reusable `Profiles` instance.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `labels.npy` | 2,856,125 | `170e1beef34f2e43cc9daa49e0370c19c4ac6baed79deea6cbdac180717b4521` |
| `membership.sqlite` | 192,937,984 | `9940ac47fe942b83c02a3c8eebbefd56a7817307ffa0b92ea0d04578a6d8600d` |
| `vectors.npy` | 159,935,960 | `ad3bee38e91845d2a4947af0e66361669e40bd7e6374d58d234cdf9a30fcf032` |
| `weights.npy` | 22,848,104 | `ce2ff516865670d6dc82f6b3fd300012e3a9015faf7c71b5595726a517f74751` |

Total array/index storage: 361.04 MiB, plus small metadata. These files are statistical simulation inputs, not classifiers.

The processed partition has already discarded raw tokens and nontransport port contents. Complete canonical vectors are exported faithfully: known nontransport canonical ports −3 become raw 0 (which re-normalizes to not-applicable); TCP/UDP sentinel −4 becomes raw −1. Known protocol bytes and valid counters are retained. Missing/invalid counters, missing/invalid/coalesced protocols and unrepresentable port statuses fail the entire build, with no silent filtering or invented protocol identity. The observed training data passed without exclusions. **Empirical replay is exact for normalized model information, not for unrecoverable original CSV strings/ports.** Unit tests check round-trip normalization.

Output fields, in order, are `PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS`, all Python integers. Every generated record passes the existing `NFCompletedFlowRecord` validation. Protocols are integral bytes; transport ports are 0..65535 or −1 sentinel; counters are 0..9007199254740991. Extra simulation metadata is outside the record.

## Sampling methodology and reproducibility

For each requested profile, filter anchors by optional protocol and TCP/UDP destination-port restrictions, retain their original weights, build uint64 cumulative weights, and sample with a matching unsigned scalar plus binary search. This avoids both multiplicity expansion and hidden full-array dtype conversion per draw. If a requested profile has no support, fail; never substitute another distribution. Sampling with replacement requires only one supported anchor, regardless of requested output count.

A private NumPy RNG selects weighted anchors and randomized source-profile order. Benign count is decimal `count * benign_ratio` rounded half up; attack count is the remainder. Remaining-count sampling gives an exact composition without materializing a shuffled output schedule. CLI attack ratio is converted with decimal subtraction to avoid a binary floating-point complement changing half-up boundaries. A second private RNG, derived using `SeedSequence(seed, spawn_key=(1,))`, controls perturbations, leaving anchor/source sequences identical between modes for a given configuration and seed. Global NumPy state is untouched. Count is bounded to 1..2^63−1.

**Empirical:** resample complete weighted vectors, preserving all seven-feature dependencies exactly in the sampling distribution. Finite samples need not match full-population marginals or tail correlations. This is training replay/bootstrap.

**Synthetic:** condition on the complete weighted empirical anchor (source profile, protocol, source/destination ports, joint counters); retain protocol/ports and apply a single uniform scale in [0.9,1.1] to all four counters by default. Round counts to nearest integer, preserve structural zeros and positive values, and cap within the existing schema bound. Near the maximum, reduce the shared scale's upper endpoint to avoid overflow. `--perturbation` supports (0,0.25]. This is a heuristic local joint perturbation, not independent column sampling or a learned network-process/packet-size model.

Verified constraints: scalar types/ranges, applicability/sentinel round trips, nonnegative integral bounded counters, structural-zero/positive preservation, anchor protocol/ports, exact requested source composition. Heuristic claims: approximate directional/byte-packet coupling and local distribution fidelity. No MTU, packet-size bound, bytes≥packets rule, timeout, orientation parity or causal attack behavior is invented. Small counts can remain unchanged after rounding. Synthetic records may equal training vectors and are not forced to be novel.

Given identical profile bytes, configuration, generator/software versions and seed, record sequences are identical. A real 10,000-record reproduction was byte-identical, including comparison with the initial empirical export after the performance fix. A repeated deterministic audit reproduced all serialized statistical results exactly. No timestamps are inserted; timing measurements live in reports, not records.

## Deterministic statistical validation

See [complete machine-readable diagnostics](statistical_validation.json). Audit seed 20261115; **5,000 records per mode/profile**, 20,000 audited outputs. An independent weighted reference bootstrap uses the audit seed; generated and paired-anchor reference sequences use seed+1. Full training protocol/port histograms and counter means/Pearson correlations use all original-row weights. Counter quantiles are descriptive sample quantiles, not exact population quantiles. Novelty checks exact canonical membership against **all training vectors across both labels**, with no hashing approximation or held-out access. Duplicate rate is excess identical canonical vectors / sample count.

| Profile | Mode | Invalid | Duplicate | Novel vs all training | Source composition |
| --- | --- | ---: | ---: | ---: | --- |
| attack | empirical | 0.00% | 4.60% | 0.00% | 5,000 attack |
| attack | synthetic | 0.00% | 0.16% | 95.16% | 5,000 attack |
| benign | empirical | 0.00% | 2.40% | 0.00% | 5,000 benign |
| benign | synthetic | 0.00% | 0.28% | 95.64% | 5,000 benign |

All four audit cells have the requested source composition. The mixed CLI check produced exactly 9,000 benign-profile and 1,000 attack-profile records; the 100,000-record synthetic CSV check produced 90,000/10,000.

Full training protocol weights:

| Profile | Protocol byte | Original-row weight | Percentage within profile |
| --- | ---: | ---: | ---: |
| attack | 6 | 587,743 | 96.0040% |
| attack | 17 | 24,464 | 3.9960% |
| benign | 1 | 6,448 | 0.1457% |
| benign | 2 | 5,569 | 0.1258% |
| benign | 6 | 3,123,877 | 70.5762% |
| benign | 17 | 1,284,997 | 29.0313% |
| benign | 47 | 5 | 0.0001% |
| benign | 58 | 5,351 | 0.1209% |

Total variation distance (0 identical, 1 disjoint) between generated discrete marginals and the **full weighted training population**:

| Profile | Mode | Protocol TV | Source-port TV | Destination-port TV |
| --- | --- | ---: | ---: | ---: |
| attack | empirical | 0.00196 | 0.76182 | 0.02165 |
| attack | synthetic | 0.00196 | 0.76182 | 0.02165 |
| benign | empirical | 0.00823 | 0.62894 | 0.22306 |
| benign | synthetic | 0.00823 | 0.62894 | 0.22306 |

The two modes have identical categorical draws because perturbation randomness is isolated. High source-port TV shows that 5,000 samples do not cover a large-cardinality marginal; it is also present in exact empirical replay. Benign destination-port TV is about 0.223. These observations do **not** establish full marginal fidelity. Rare benign GRE has only five training rows and may be absent from a finite sample. Nontransport raw-zero port placeholders are included as representation values, not interpreted as TCP/UDP services.

Byte/packet summaries (quantile entries are sample median / p99):

| Profile | Feature | Full weighted train mean | Empirical mean | Synthetic mean | Empirical median / p99 | Synthetic median / p99 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| attack | IN_BYTES | 16559.076 | 14276.620 | 14301.664 | 192.00 / 19054.05 | 203.00 / 19722.02 |
| attack | OUT_BYTES | 147.231 | 170.219 | 167.450 | 0.00 / 1873.00 | 0.00 / 1819.16 |
| attack | IN_PKTS | 262.132 | 223.994 | 224.405 | 4.00 / 148.00 | 4.00 / 153.01 |
| attack | OUT_PKTS | 0.358 | 0.395 | 0.392 | 0.00 / 7.01 | 0.00 / 8.00 |
| benign | IN_BYTES | 1940.629 | 2244.188 | 2238.728 | 148.00 / 16849.27 | 145.00 / 16302.35 |
| benign | OUT_BYTES | 4845.536 | 10559.473 | 10675.200 | 132.00 / 28887.85 | 138.00 / 29155.29 |
| benign | IN_PKTS | 8.063 | 8.630 | 8.637 | 2.00 / 91.02 | 2.00 / 95.00 |
| benign | OUT_PKTS | 6.603 | 10.483 | 10.575 | 1.00 / 35.00 | 1.00 / 36.01 |

| Profile | Reference/mode | IN_BYTES–IN_PKTS Pearson | OUT_BYTES–OUT_PKTS Pearson |
| --- | --- | ---: | ---: |
| attack | full weighted training | 0.999976 | 0.945973 |
| attack | empirical | 0.999967 | 0.918389 |
| attack | synthetic | 0.999968 | 0.916981 |
| benign | full weighted training | 0.564195 | 0.996934 |
| benign | empirical | 0.721254 | 0.999356 |
| benign | synthetic | 0.719295 | 0.999319 |

| Profile | Mode | Max absolute correlation difference vs paired anchors | Max difference vs full training |
| --- | --- | ---: | ---: |
| attack | empirical | 0.000000 | 0.027583 |
| attack | synthetic | 0.001409 | 0.028992 |
| benign | empirical | 0.000000 | 0.344596 |
| benign | synthetic | 0.003133 | 0.341463 |

Joint perturbation changed sampled correlations only slightly (maximum about 0.00313 versus identical anchors), but benign sample-to-full-population differences remain substantial (about 0.34 maximum across counter pairs). In particular, benign empirical OUT_BYTES mean exceeds twice its full-training mean. The full JSON also includes a separately seeded weighted training bootstrap, complete counter correlation matrices, min/p50/p90/p99/max, category cardinalities and top ports. Differences across empirical bootstraps show sensitivity to rare extreme flows; preservation of local anchor ratios does not guarantee population tails or correlations in a small output. No realism acceptance threshold or statistical significance claim is asserted. Schema validity, novelty and agreement with a classifier would not verify attack behavior.

## CLI verification, streaming and examples

Both `--help` commands, profile build, benign-only empirical JSONL, attack-only synthetic CSV, mixed empirical JSONL, TCP/443-filtered synthesis, repeat-seed reproduction and a 100,000-row mixed synthetic CSV were executed successfully. See [README commands/options](../../README.md#simulation-lab-feature-record-generator-phase-6a). Existing paths are protected from overwrite; use new output/report directories for repeats. Documented commands run via the existing `uv` environment (this machine used `UV_CACHE_DIR=/tmp/cyberguard-uv-cache` and `--frozen --offline`).

```bash
uv run python scripts/build_traffic_profiles.py
uv run python scripts/generate_traffic.py --count 10000 --benign-ratio 0.9 --mode empirical --seed 42
uv run python scripts/generate_traffic.py --count 1000 --attack-ratio 1 --mode synthetic --format csv --output runtime/simulation/new_attack.csv
```

Actual benign-profile empirical JSONL example (seed 42):

```json
{"record":{"PROTOCOL":6,"L4_SRC_PORT":53597,"L4_DST_PORT":443,"IN_BYTES":2685,"OUT_BYTES":656704,"IN_PKTS":39,"OUT_PKTS":464},"simulation":{"mode":"empirical","source_profile":"benign","sequence":0,"generator_version":"nf-simulation-v1","profile_version":"nf-training-profiles-v1"}}
```

Actual attack-profile synthetic CSV excerpt (seed 42):

```csv
PROTOCOL,L4_SRC_PORT,L4_DST_PORT,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS
6,58198,80,40,0,1,0
6,51103,80,175,0,4,0
```

These source labels describe the profile used, not verified ground truth. JSONL defaults to just the seven fields; `--metadata` uses the envelope above. CSV defaults to seven ordered fields; optional metadata has `simulation_*` column names. Remove metadata before strict API submission. Every exported file gets a `.simulation.json` sidecar with config, software versions, profile/output hashes and an evidence warning. Example outputs are under `runtime/simulation/`, including final measurement runs under `runtime/simulation/final/` (Git-ignored).

`TrafficGenerator` is an iterator yielding one `{record,simulation}` object per `next()` call. Arrays are memory-mapped, filters/CDFs are built once per generator, and loaded `Profiles` can be reused. Output count is never allocated as an array. Generator initialization scans **profile arrays**, not source NPZ partitions; generation never rescans training shards. The membership database is used only by bounded audits. Serializers write each record immediately. Diagnostic samples are explicitly capped at 100,000 per cell. No workers/GPU are needed.

## Performance and verification

[Measured CLI runs](performance.json) use this CPU-only Python 3.13 machine. Export timers include record generation, per-record API schema validation, file writing, output hashing and provenance sidecar; they exclude imports/profile loading/filter setup. Results depend on filesystem cache, hardware, process scheduling and configuration. RSS is Linux `ru_maxrss`/1024, includes imports/mappings and is a process peak, not Python heap alone.

| Run | Records | Load/filter seconds | Export seconds | Export records/s | Peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| mixed_empirical | 10,000 | 0.387 | 0.314 | 31,828 | 427.44 |
| benign_empirical | 1,000 | 0.305 | 0.029 | 35,015 | 327.12 |
| attack_synthetic | 1,000 | 0.278 | 0.032 | 31,671 | 264.77 |
| mixed_filtered | 1,000 | 0.372 | 0.034 | 29,542 | 377.65 |
| reproduced | 10,000 | 0.311 | 0.263 | 38,000 | 427.71 |
| benchmark_synthetic | 100,000 | 0.322 | 3.178 | 31,464 | 431.67 |

Profile construction took **5.726 s**, with a measured initial build/audit process peak of **567.17 MiB**. The expanded final audit (including full weighted counter statistics and paired anchors) took **2.773 s**, peak **607.43 MiB** in its separate process. No full original-row expansion was used. Output disk consumption grows with count; profile/CDF working memory grows with compact support, not requested output length. A billion-record configuration is tested incrementally using a tiny fixture, without allocating that many records; streaming 10,000 fixture rows stays below 2 MB traced incremental heap.

Tests: `uv run --frozen --offline pytest -q` — **398 passed in 21.59 s**, including **54 generator tests**. One SQLite `ResourceWarning` about an unclosed connection surfaced during the full-suite network-training test; no tests failed. The generator suite uses synthetic sealed fixtures, poison metadata and temporary outputs only. Coverage includes train-only access, source/contract/checksum rejection, byte-reproducible builds, empty profiles, exact weighting, seed reproducibility/isolation, API validity, max counters/zeros/sentinels, half-up proportions, restrictions/failures, CSV/JSONL metadata separation, CLI round trips, incremental bounded memory, diagnostics and unsigned binary-search scalar regression. Ruff check/format verification passed for all introduced Python files.

Frozen classifier hashes were rechecked without deserializing or invoking models:

- BoT: `93b744ada3af044e2d0e7d4dd6d5fa70870536e7a972443c806a232ce9052c6f`.
- NF: `598129ae5580ad386937f78f4a9d7f8a668557e63cd15db20fcbde9696665e7a`.

## Evidence limits and remaining work

Empirical resampling is training replay; synthetic perturbation inherits the same training support, artifacts and label conflicts. Exact novelty can be a one-unit counter change and does not establish independent network behavior. Ports/protocols are not newly combined; counter vectors move locally around anchors. Outliers and rare protocols are neither guaranteed nor deliberately oversampled. Existing source ambiguity and exporter/accounting limitations remain. Synthetic label composition is exact by design, not an empirical attack-rate estimate.

Generated records are **not an independent evaluation set**. Source labels are not independently verified attacks or safety, prediction agreement is not test accuracy, simulated metrics must not be combined with the frozen final test, and generated records must not update classifiers without a separately approved training experiment. No model inference was performed in this phase. Future work may study fidelity with larger predetermined training-only audits and verified exporter constraints, or add separately scoped orchestration/frontend support. There is no claim of live or packet-level detection and no network packets are generated.
