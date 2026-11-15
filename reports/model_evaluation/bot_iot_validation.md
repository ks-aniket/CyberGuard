# BoT-IoT restricted network baseline validation

Generated 2026-11-15 16:52 IST. Offline flow-record experiment; no live packet-level detection claim.

## Outcome

Validation macro-F1: **0.675270**; balanced accuracy / mean class recall: **0.741975**. Benign false-positive rate: **15.190%**, comprising 12 false alarms among 79 Normal records.

These are internal training-file validation results. They do not establish production performance, independent-session generalization or live capture compatibility. No supplied-test results were computed. DNS remains outside this experiment.

## Scope, inputs and target policy

Input: `data/raw/bot_iot/train/UNSW_2018_IoT_Botnet_Final_10_best_Training.csv`; SHA-256 `047e577cd9c7f8f61d44ac170114497904c33091bf80d1dd5e682e353a69c15b`. Read only proto, sport, dport and category in 50,000-row chunks. The supplied BoT-IoT test file and DNS files were never opened by the training runner. Input SHA-256 was verified unchanged after the run.

The supervised targets are Normal, DoS, DDoS, Reconnaissance. All 65 Theft records are explicitly excluded from fitting and four-class validation. Theft is an unsupported malicious category and is never relabeled Normal. This closed-set classifier always returns one of the four supported labels; it cannot certify traffic as safe or identify unsupported attacks. All excluded raw records are preserved.

The raw training file contains only 370 Normal examples (0.012607% of all rows). These are scarce recorded examples, not independent captures. No benign examples were fabricated, synthesized or oversampled.

| Target | Original training-file rows | Fit rows | Validation rows | Fit distinct input groups | Validation distinct input groups |
| --- | --- | --- | --- | --- | --- |
| Normal | 370 | 291 | 79 | 229 | 51 |
| DoS | 1,320,148 | 1,057,891 | 262,257 | 105274 | 26209 |
| DDoS | 1,541,315 | 1,234,093 | 307,222 | 107141 | 26655 |
| Reconnaissance | 72,919 | 59,656 | 13,263 | 50219 | 12709 |

## Reproducible preprocessing contract

Version `bot-iot-header-v1`. The reusable sklearn Pipeline accepts a pandas DataFrame requiring proto/sport/dport. Extra columns, including every target, IP and identifier, are ignored by an explicit allowlist. Missing required columns or duplicate column names fail. Unknown target categories fail instead of silently collapsing.

Protocol tokens are stripped/lowercased; TCP/6, UDP/17, ICMP/1/icmpv4, IPv6-ICMP/58/icmpv6 and ARP are normalized. Empty/NA tokens become missing; unsupported protocols become other. Protocol aliases are a fixed contract, not learned from targets.

TCP/UDP ports accept nonnegative decimal integers (including leading zeroes), hexadecimal 0x tokens, and integer-valued numeric scalars. Port 0 is valid; 65535 is the maximum. Blank/NA, -/-1 sentinel, and malformed/out-of-range/negative/nonfinite inputs have distinct missing/sentinel/invalid statuses. Non-TCP/UDP protocols have not_applicable ports, so ICMP hex type/code and ARP -1 tokens never masquerade as TCP/UDP port numbers. Unknown transports also receive not_applicable; no port semantics are guessed.

Each transport port produces a fixed value in [0,1] (port/65535, zero when unavailable), a status and a fixed well_known (0–1023), registered (1024–49151), dynamic (49152–65535) or none range. Status distinguishes valid zero from unavailable zero. Numeric values have no learned scale or imputation. Protocol, statuses and ranges are one-hot encoded using training partitions only, with handle_unknown=ignore. Unknown categories remain safe all-zero encoded categories while the numeric contract stays fixed.

[Feature availability and leakage audit](bot_iot_feature_audit.md) documents every source field and residual exporter/scenario risks. The model uses no historical counts, rates, completed-flow duration summaries, state, addresses or sequence identifiers.

## Validation boundary and duplicate policy

A label-independent SHA-256 of seed 20261115 and the complete canonical retained input vector assigns each group to validation when its first 64 bits are below 2^64//5 (nominal 20%). Other groups go to fitting. Assignment is deterministic across chunk sizes, row order and port spelling aliases. The seed was fixed before fitting; no seed search, hyperparameter search, stratification retry or test-based selection was performed.

There are 196,827 normalized input groups: 157,444 fit and 39,383 validation. Exact cross-partition input-group overlap is **0**, verified before fitting. This grouping is stricter than the prior full operational-vector duplicate check: identical operational rows necessarily map to one retained input group, even when raw IPs/flow summaries differ. It does not establish host, session, campaign or temporal independence.

The compact index retains 328,487 distinct (input vector, target) records and their exact multiplicities, representing 2,934,752 eligible original rows. Duplicate excess under this restricted view is 2,606,265. No repeated row is discarded from the weighting or evaluation denominators. Group assignment precedes fitting and applies without using its label.

There are 131,086 groups with more than one supported target, covering 2,866,209 rows. Removing context makes these inputs indistinguishable; this is not proof of source annotation errors. Every conflicting group remains entirely on one side, and each label/count is retained. No majority-vote relabeling is applied.

Full groups with few protocols (e.g. all ICMP or ARP observations after port removal) can be large and label-mixed, causing split proportions and rare-class coverage to differ from 80/20. The runner fails if any supported class is absent on either side. It does not silently change the partition. The manifest records every group/target/count/partition for audit.

## Fixed CPU baseline and training weights

Decision tree: max_depth=6, max_leaf_nodes=32, min_samples_leaf=5, random_state=20261115; all other parameters are recorded in JSON. Actual fitted depth 6, leaves 32. No tuning was performed. This simple model is intended to expose what the restricted inputs can and cannot distinguish.

Train-only inverse-frequency weights are N_train/(4×class_count). A compact record’s sample weight is its original multiplicity times its class weight, preserving original class mass in the weighted impurity calculation. min_samples_leaf=5 refers to compact feature-label records, not five independent raw observations. Validation metrics use original multiplicities without class balancing.

| Class | Train-only class weight |
| --- | --- |
| Normal | 2020.559278 |
| DoS | 0.555807 |
| DDoS | 0.476449 |
| Reconnaissance | 9.856222 |

## Validation results

| Class | Precision | Recall | F1 | Row support |
| --- | --- | --- | --- | --- |
| Normal | 0.443709 | 0.848101 | 0.582609 | 79 |
| DoS | 0.521740 | 0.624189 | 0.568385 | 262257 |
| DDoS | 0.614288 | 0.511594 | 0.558258 | 307222 |
| Reconnaissance | 0.999770 | 0.984016 | 0.991830 | 13263 |

Confusion matrix: rows are actual classes; columns are predictions. These counts include all repeated eligible validation records through multiplicity weighting.

| Actual / predicted | Normal | DoS | DDoS | Reconnaissance |
| --- | --- | --- | --- | --- |
| Normal | 67 | 3 | 6 | 3 |
| DoS | 0 | 163698 | 98559 | 0 |
| DDoS | 1 | 150048 | 157173 | 0 |
| Reconnaissance | 83 | 5 | 124 | 13051 |

The train-majority reference rule has macro-F1 0.172588 and benign FPR 100.000%. It uses only training class counts and serves as a descriptive reference, not a selected alternative model.

A secondary diagnostic gives each retained input vector total weight 1, distributing that weight among its label counts. Its macro-F1 is 0.667833, balanced accuracy 0.778497, and benign FPR 2.703%. This differs from row-weighted results because duplicate frequency can dominate them. It is not a session-independent evaluation.

Benign FPR denominator is exactly the 79 held-out Normal rows across 51 distinct input groups, not all validation traffic. A small benign set with repeated/related capture records cannot establish a reliable deployment false-alarm budget. Ordinary independent-row confidence intervals would overstate the evidence; no such confidence claim is made.

## Encoded features and fitted tree importances

| Encoded feature | Impurity importance |
| --- | --- |
| ports__dport_value | 0.811324 |
| categories__protocol_udp | 0.087409 |
| ports__sport_value | 0.054142 |
| categories__protocol_tcp | 0.036825 |
| categories__sport_range_registered | 0.010299 |
| categories__protocol_arp | 0.000000 |
| categories__protocol_icmp | 0.000000 |
| categories__protocol_ipv6-icmp | 0.000000 |
| categories__sport_status_not_applicable | 0.000000 |
| categories__sport_status_valid | 0.000000 |
| categories__dport_status_not_applicable | 0.000000 |
| categories__dport_status_valid | 0.000000 |
| categories__sport_range_dynamic | 0.000000 |
| categories__sport_range_none | 0.000000 |
| categories__sport_range_well_known | 0.000000 |
| categories__dport_range_dynamic | 0.000000 |
| categories__dport_range_none | 0.000000 |
| categories__dport_range_registered | 0.000000 |
| categories__dport_range_well_known | 0.000000 |

Importances describe this fitted tree only. Protocol/service or missingness may encode testbed scenarios and exporter behavior. A feature being obtainable from a header does not demonstrate robust intrusion detection. DoS versus DDoS often requires causal multi-source/time-window evidence that this deliberately restricted representation excludes.

## Validation and integrity checks

Before the raw-data fit, targeted unit tests covered protocol aliases, missing/sentinel/invalid/hex ports, nontransport semantics, exclusion invariance for labels/IPs/aggregates, required schema, target/Theft policy, exact key round trips, train-only encoding, serialization, duplicate-group/chunk invariance, conflicting groups and weighted metrics against expanded count fixtures. Synthetic fixtures are software tests only; they are not generalization evidence.

The real run checked class support, canonical reconstruction, disjoint group assignments, unchanged raw SHA-256, and exact equality of saved/reloaded model predictions on validation. Full hyperparameters, dependency versions, code hashes, normalization counts and metrics are in the JSON artifact.

## Artifacts and rerun

- Model including fitted preprocessing: `models/network/bot_iot_restricted_baseline.joblib` (4,747 bytes); SHA-256 `93b744ada3af044e2d0e7d4dd6d5fa70870536e7a972443c806a232ce9052c6f`.
- Group manifest: `models/network/bot_iot_split_manifest.csv.gz`; SHA-256 `d992d69683082595823adb269fb1fa6f2a43664d00c810fddbfc1e7a4fbe3b2d`.
- [Machine-readable run metrics](bot_iot_validation_metrics.json).
- [Confusion counts CSV](bot_iot_validation_confusion.csv).
- [Feature audit](bot_iot_feature_audit.md).

Run `.venv/bin/pytest -q tests/unit/test_preprocessing.py tests/unit/test_network_training.py` before `.venv/bin/python scripts/train_network_baseline.py`. Load the pipeline with `PYTHONPATH=src` or with the cyberguard package on the Python import path. Its only required predictor inputs are proto/sport/dport. Artifacts remain local under the repository’s model/data ignore policy; source and reports are reviewable.

Environment: Python 3.13.12, sklearn 1.9.1, NumPy 2.5.4, pandas 3.1.1. Full run 59.7s; tree fitting 2.86s; peak RSS 500.2 MiB. No GPU or worker pool was used. The baseline stores only a bounded CSV chunk during ingestion and a compact normalized group index for fitting, rather than an expanded full raw table.

## Recommendations and status

1. Treat this result as a reproducible offline diagnostic baseline. Any poor class recall or large benign FPR is an outcome to report, not a reason to reintroduce suspect aggregates or silently tune the held-out partition. Do not deploy it as a safety decision.
2. Collect more real benign traffic across independent devices, environments and periods, plus representative attacks and benign high-rate services. Preserve source/session/time metadata. Additional synthetic or repeated benign rows cannot solve the independent-evidence shortage.
3. Obtain packet/flow-export configuration and build explicitly past-only windows with bounded state. Verify packet/flow orientation, missingness, timeout behavior and feature parity. Add causal source counts or rate features only after their time boundaries and forward evaluation are established; never use capture-wide or future counts.
4. Add host/capture/session/time-held-out evaluations and group-aware uncertainty estimates with enough independent benign groups. Assess exporter/missingness and service-port sensitivity on new data. The supplied test remains untouched for a later explicitly authorized frozen evaluation, with the earlier EDA overlap caveats disclosed.
5. Expand Theft handling with sufficient independently sourced examples or a separately validated unsupported/abstention mechanism. Four-class Normal predictions provide no assurance against Theft or other unseen threats. DNS remains NO-GO under its separate investigation.
