# NF-CSE Phase 5B preparation report

Status: **complete**. No classifier trained, no predictions evaluated, no test-based selection, no existing model/API/dashboard changes. This is a binary-only preparation using Label 0=Benign, 1=Attack; Attack is original offline metadata, never a predictor. [Phase 5A audit](overview.md) remains historical; it did not create these partitions.

## Frozen completed-flow contract

`nf-cse-netflow-v1-completed-flow-v1`; preprocessing `nf-cse-normalization-v1`. Exact raw order:

| Exact raw column | Type/range | Unit / definition |
| --- | --- | --- |
| PROTOCOL | integer 0..255 | IP-header byte code; categorical, not ordinal |
| L4_SRC_PORT | integer 0..65535 | TCP/UDP port identifier |
| L4_DST_PORT | integer 0..65535 | TCP/UDP port identifier |
| IN_BYTES | integer 0..9007199254740991 | bytes as counted by supplied exporter |
| OUT_BYTES | integer 0..9007199254740991 | bytes as counted by supplied exporter |
| IN_PKTS | integer 0..9007199254740991 | packets as counted by supplied exporter |
| OUT_PKTS | integer 0..9007199254740991 | packets as counted by supplied exporter |

The supplied feature dictionary calls IN incoming and OUT outgoing. Treat these as exporter-relative forward/reverse totals within this dataset, not verified initiator/responder semantics. Byte-layer accounting, timeout, sampling and orientation parity with another exporter remain unknown. All seven fields are required; a missing column rejects header-only inputs. Explicit null values are represented by status. This is an offline **completed-flow, bidirectional** contract, never first-packet/partial-flow/live IDS inference. Both IPs, duration, L7_PROTO, cumulative TCP_FLAGS, labels and all other columns are excluded by an explicit allowlist.

Normalization: fixed protocol aliases and byte categories 0/1/2/6/17/47/58; other valid byte codes coalesce to other. Null/blank/NA-like values are missing, malformed/fractional/nonfinite/out-of-range/booleans invalid. Exact integral decimal/exponent numeric forms normalize identically; ports also accept hexadecimal. TCP/UDP ports retain valid zero, with -/-1 sentinel distinct. Known nontransport ports are not-applicable; unknown protocol ports have a separate unknown-protocol status. Final counts preserve zero and are bounded at 2^53−1 for exact float64 interoperability. There is no clipping, outlier removal or float32 conversion. Encoded model fields use deterministic zero fill plus categorical statuses, preserving canonical-vector information; protocol category codes are categorical, not an ordinal measurement. No vocabulary, imputation statistic, scaler, class weight or target encoder is learned. Future tree preprocessing can reuse NFCSECompletedFlowFeatures; raw and canonical entry points are deliberately distinct.

## Provenance and integrity

Source `/home/redstar/CyberGuard/data/raw/nf-cse-cic-ids2018/88a47ba2ab64258e_MOHANAD_A4706/data/NF-CSE-CIC-IDS2018.csv`; SHA-256 `ed3387646fda24084889f07788cd22da2978b860f5b3d2d6f1210a4e3d7998e0`. Dictionary SHA-256 `778271c208e0eb0c5de21f43ac6b13dea3e7b78625349fe915b36e6f814bcc39`. Input files were opened read-only and rehashed after indexing and materialization. No BoT-IoT or DNS data are opened by this workflow. Code/contract hashes, dependencies, input schema and per-file artifact hashes are in metadata. The processed snapshot is atomically published only after guards, roundtrips, checksum and inventory checks pass. Compatible reruns verify/reuse; incompatible or altered output is refused. There is no overwrite flag. Local checksums do not authenticate untrusted datasets.

## Full-data descriptive ambiguity (not model tuning)

| Measure | Observed value |
| --- | --- |
| attack_rows_in_binary_conflicts | 26571 |
| benign_rows_in_binary_conflicts | 164432 |
| binary_conflicting_groups | 18272 |
| binary_majority_correct_rows | 8370398 |
| binary_majority_label_accuracy_ceiling | 0.9973782234666814 |
| compact_records | 4762994 |
| distinct_feature_binary_records | 4748581 |
| groups_crossing_partitions | 0 |
| groups_multiple_Attack_labels | 32639 |
| largest_group_rows | 27250 |
| normalized_groups | 4730309 |
| normalized_vector_duplicate_excess | 3662092 |
| original_rows | 8392401 |
| projected_feature_label_metadata_duplicate_excess | 3629407 |
| rows_in_binary_conflicts | 191003 |

The empirical binary ceiling sums max(benign count, attack count) within every canonical group / all original rows. It describes best possible deterministic labeling of these observed vectors, **not trained accuracy, validation/test performance or a generalization bound**. Groups with multiple Attack names include benign-vs-attack and attack-vs-attack ambiguity. No group or record is relabeled or discarded. All original class multiplicities survive. Status counts and original Attack supports are recorded in manifests.

## Fixed split and actual supports

Phase 5A found no capture/session/timestamp mapping. Endpoint graph connectivity makes a three-way both-endpoint-disjoint split with attack support infeasible. Use canonical feature groups as the documented fallback, not invented sessions. Seed **20261115**, method: `sha256(schema_version,seed,canonical_integer_vector); first64; <floor(3*2^64/5) train; <floor(4*2^64/5) validation; else test`. Exact canonical JSON vector plus schema/seed determines assignment, with no labels, IPs or row positions. No seed searching. No identical normalized vector crosses partitions; all binary-conflicting groups stay intact. Fixed encodings are injective on canonical vectors; no learned transform can create additional collisions in this preparation.

| Partition | Original rows | Row % | Groups | Compact records | Benign | Attack |
| --- | --- | --- | --- | --- | --- | --- |
| test | 1689195 | 20.127673 | 947108 | 953681 | 1485639 | 203556 |
| train | 5038454 | 60.035906 | 2836328 | 2855997 | 4426247 | 612207 |
| validation | 1664752 | 19.836421 | 946873 | 953316 | 1461312 | 203440 |

Binary feature-group supports: {'test': {'0': 877289, '1': 73513}, 'train': {'0': 2626725, '1': 220612}, 'validation': {'0': 876995, '1': 73447}}.

Predeclared stop guards: absolute deviation <=10 percentage points from each target 60/20/20 and at least 10 distinct feature groups supporting each binary label per partition. These are engineering checks, not statistical independence guarantees. Errors: []. Counts were computed before staging partitions. Any failure blocks publication; no seed, label or guard is silently changed. Minority Attack names may have low or zero per-partition support; they are kept and reported, not silently dropped. No multiclass fit is authorized.

| Attack (metadata) | train | validation | test |
| --- | --- | --- | --- |
| Benign | 4426247 | 1461312 | 1485639 |
| Bot | 9480 | 3148 | 3055 |
| Brute Force -Web | 1343 | 436 | 834 |
| Brute Force -XSS | 1300 | 424 | 21 |
| DDOS attack-HOIC | 135 | 47 | 48 |
| DDOS attack-LOIC-UDP | 974 | 340 | 353 |
| DDoS attacks-LOIC-HTTP | 227467 | 75369 | 75363 |
| DoS attacks-GoldenEye | 19669 | 6587 | 6594 |
| DoS attacks-Hulk | 64968 | 21624 | 21544 |
| DoS attacks-SlowHTTPTest | 63437 | 21067 | 21046 |
| DoS attacks-Slowloris | 13616 | 4546 | 4663 |
| FTP-BruteForce | 116120 | 38611 | 38629 |
| Infilteration | 37343 | 12292 | 12437 |
| SQL Injection | 24 | 7 | 5 |
| SSH-Bruteforce | 56331 | 18942 | 18964 |

## Duplicate policy / population

Each shard stores one canonical vector + binary label + original Attack name with its uint64 multiplicity. This compacts the **projected normalized representation**, not a claimed removal of full raw records. Phase 5A's 1,077,740 full-record duplicate excess differs from these projected duplicate counts. Exact canonical vectors, not hash equality alone, define groups. SHA-256 group IDs are convenience identifiers; canonical values remain available for exact comparisons.

Use multiplicity as sample_weight for original-row population fitting/evaluation. Later optional balancing must derive only from train class mass and multiply multiplicity; validation/test use original multiplicities without balancing. Equal-vector metrics estimate something else and must be labelled separately. Weighting does not turn repeated flows into independent episodes, and compact fitting can change estimator constraints based on unweighted row counts (e.g. min_samples_leaf). No synthetic benign samples or oversampling are performed.

## Storage / resources / reproduction

Output is under data/processed/nf_cse_cic_ids2018 by default: train/, validation/, test/ NPZ shards; metadata/feature_contract.json, split_manifest.json + SHA-256 sidecar, class_distribution.json, preprocessing_manifest.json; one generated dataset README. NumPy loading disables pickle. Canonical fields are int64; labels uint8; multiplicity uint64; Attack Unicode; group IDs S64. No extra full-size raw CSV copies. Source chunks, compact shard batches and SQLite's 64 MiB page cache bound memory; SQLite grouping/sorts use disk. No GPU or worker pool.

Measured resources: `{'artifact_bytes_excluding_split_manifest': 203298976, 'peak_rss_mib': 351.10546875, 'seconds': 209.39, 'sqlite_bytes': 254738432}`. Manifest byte count excludes its own JSON/sidecar to avoid circular hash/size claims. Temporary indexes are deleted. Run `uv run python scripts/prepare_nf_cse.py --help`; `--dry-run` computes the complete descriptive plan but publishes no processed files. Materialize with `uv run python scripts/prepare_nf_cse.py --chunk-size 50000 --seed 20261115`. Same-identity reruns verify the sealed snapshot; do not create new seeds to optimize balance. Example options and test commands are in the root README.

## Future integration and remaining gates

Existing `bot_iot_restricted_baseline` accepts proto/sport/dport and returns four categories. Future `nf_cse_binary_completed_flow` requires seven finalized-flow inputs and returns Benign/Attack. Current Pydantic schemas, NetworkDetector, CLI validation and dashboard form/batch/response checks enforce the BoT contract and cannot accept a swapped artifact safely. Later work needs an allowlisted model registry, separate versioned input schemas/preprocessors/vocabularies, model-specific forms/CSV validation and explicit observation-boundary warnings. Header-only frontend records must never be forwarded to this model. No switching or endpoint/frontend behavior is implemented here; see [integration plan](integration_plan.md).

Test is reserved/sealed by checksums, **not encrypted/access-controlled**; preparation inspected only integrity, labels and support. Future modeling must fit/select on train/validation only, keep validation out of final fitting under this design, and freeze model/thresholds before an authorized final test evaluation. Group separation does not establish session/capture/host/time independence. Service signatures, collection artifacts, missing provenance, scarce SQL Injection records and unverified exporter semantics remain. Duration stays excluded despite its class-aligned artifact patterns. Obtain independently sourced capture/time/host evidence before operational claims.

## Software verification

Focused synthetic tests check normalization/order/exclusion, invalid/missing/zero values, label agreement, ambiguity accounting, deterministic group assignment, supports, atomic publication, rerun identity/hashes, dry-run behavior, source preservation and no access to other raw datasets. Synthetic fixtures test software, not generalization. Full-suite results for this execution are recorded below after regression checks.


Execution checks for this snapshot:

- `UV_CACHE_DIR=/tmp/cyberguard-uv-cache uv run --frozen --offline pytest -q`: **235 passed in 4.62 seconds**. The focused NF-CSE module had **46 passing cases**. Tests use synthetic fixtures only for software behavior.
- Ruff checks and formatting checks passed for the new modules, CLI and unit tests. `git diff --check` passed.
- Documented CLI help and invalid-argument handling were executed. CLI dry-run on a synthetic fixture returned success and created no processed output. The real materialization command performed its full-file preflight before staging; there were no guard failures or seed retries.
- Every one of the 4,762,994 compact stored records was reopened with pickle disabled. Canonical shape/dtype, multiplicity, binary/Attack totals, schema-derived encoding, group ID and expected partition were checked. Every canonical vector maps to its actual partition under the frozen hash rule, proving zero identical normalized vectors across partitions without constructing an expanded copy.
- Same-source/code/contract/seed rerun verified the existing inventory and hashes and printed “Existing compatible sealed output verified; no files rewritten”. Raw source/dictionary hashes still match the approved audit. The existing BoT-IoT artifact SHA-256 remains `93b744ada3af044e2d0e7d4dd6d5fa70870536e7a972443c806a232ce9052c6f`.
- No training, hyperparameter selection, test predictions, FastAPI changes or dashboard changes occurred. Reading test shards here was a preparation integrity/population check, not a model evaluation.

## Published storage and support cautions

Exact published size including manifests and the generated dataset README: **203,319,558 bytes (193.90 MiB)**. This post-publication measurement is recorded here rather than inside the manifest whose own length contributes to that size.

| Partition | Shards | NPZ bytes | Compact records | Represented original rows |
| --- | --- | --- | --- | --- |
| train | 58 | 121,381,579 | 2,855,997 | 5,038,454 |
| validation | 20 | 40,948,700 | 953,316 | 1,664,752 |
| test | 20 | 40,957,537 | 953,681 | 1,689,195 |

The empirical full-data ceiling is **99.737822%**; 22,003 observed records are the minimum disagreement count for any deterministic binary label lookup on these canonical vectors. This is descriptive, not a model score or a promise for unseen traffic.

All 15 original Attack names are present in each partition, but metadata imbalance remains: SQL Injection has only 24/7/5 train/validation/test records and Brute Force -XSS has 1,300/424/21. Binary support guards passed; these small, correlated category supports do not authorize multiclass performance claims. No records, guards, seed or category names were changed to improve those proportions. There is **no preparation blocker**; independent capture/session evidence and exporter/live parity remain unresolved limitations for future modeling and deployment.
