# NF-CSE-CIC-IDS2018: proposed evaluation strategy (not executed)

## Independence evidence

The 14-column CSV has IPv4 source/destination, ports, protocol, L7 code, totals, flags, duration and labels. There are **no capture IDs, absolute timestamps, session IDs, campaign IDs, flow IDs or original capture-day fields**. Flow duration is not an absolute timestamp. Bagging date is packaging metadata. Row order and the five-tuple must not be manufactured into temporal/capture/session IDs; repeated endpoint/port pairs can be many flows. Attack names describe categories/tools, not distinct episode identities. Feature dictionary/BagIt metadata supply no per-row mapping back to captures.

Distinct observed source IP tokens: 75,405; destination IP tokens: 26,303. IPs make endpoint-held-out experiments technically possible but do not establish stable device identities (NAT, address reuse), balanced class support or campaign independence. Shared endpoints can connect many rows into one component. A bounded two-pass diagnostic joins every row's two endpoint tokens into connected components (up to 200,000 distinct hosts; stops explicitly if exceeded). These graph components are **not sessions or devices**; malformed IPv4 tokens are retained as tokens, not repaired or interpreted as real host identities. A host-based design would need a declared invalid-address policy and a new graph audit, while keeping every excluded-from-diagnostic row visible. Actual diagnostic: 2 components across 92093 endpoint tokens; largest component has 8392400 rows and 92092 hosts. Full completion/budget status is in audit JSON.

| Attack | Endpoint components | Rows in largest supporting component | Total rows |
| --- | --- | --- | --- |
| Benign | 2 | 7373197 | 7373198 |
| Bot | 1 | 15683 | 15683 |
| Brute Force -Web | 1 | 2613 | 2613 |
| Brute Force -XSS | 1 | 1745 | 1745 |
| DDOS attack-HOIC | 1 | 230 | 230 |
| DDOS attack-LOIC-UDP | 1 | 1667 | 1667 |
| DDoS attacks-LOIC-HTTP | 1 | 378199 | 378199 |
| DoS attacks-GoldenEye | 1 | 32850 | 32850 |
| DoS attacks-Hulk | 1 | 108136 | 108136 |
| DoS attacks-SlowHTTPTest | 1 | 105550 | 105550 |
| DoS attacks-Slowloris | 1 | 22825 | 22825 |
| FTP-BruteForce | 1 | 193360 | 193360 |
| Infilteration | 1 | 62072 | 62072 |
| SQL Injection | 1 | 36 | 36 |
| SSH-Bruteforce | 1 | 94237 | 94237 |

On this download, fewer than three components overall and one component per attack class make a three-way, both-endpoint-disjoint split retaining all classes infeasible without dropping/reassigning observations. This is a graph constraint, not proof of a single campaign. Three-way host-disjoint splitting requires at least three supported components per class; a single shared component cannot be divided while preserving both endpoints disjoint. No host partition was created. Even feasible graph separation would need independent capture evidence.

## Priority and gates

1. Obtain original capture/session mappings and exporter settings. Prefer sessions/captures held out across fit/validation/test; inspect independent class/benign support per unit before freezing. If timestamps become available, hold later periods out and keep sessions/duplicates from crossing boundaries. Avoid label-aware searches for an advantageous partition.
2. Otherwise use the endpoint graph diagnostic above to assess whether further host-held-out work is feasible; consider both endpoints (not only source), class counts and dominant shared infrastructure. A host-disjoint split requires no source/destination host overlap, enough independent components and all target classes. If common servers collapse components or rare classes reside on one host, report infeasibility and seek new captures; do not silently fall back while claiming host independence.
3. Current-file fallback: deterministic exact **canonical retained-feature group** partition, nominal 60/20/20 fit/validation/reserved test. Freeze schema, canonicalization, seed and label vocabulary before assigning; proposed fixed seed 20261115, SHA-256 of the schema-version/seed/unlabelled canonical JSON key, first 64 bits mapped uniformly to [0,1): <0.6 fit, [0.6,0.8) validation, >=0.8 reserved test. This is a proposed rule, not executed; no repeated seed search. Keep every label/count for a mixed group together. Full raw-vector grouping alone is insufficient after removing identifiers or rounding/collapsing tokens. The seven-input view is audited as `initial_completed`; `duration_inclusive` adds duration, and the ten-input no-IP view also includes L7/flags. These exact-token counts still need a canonical-key audit after protocol/port and missingness rules are frozen. Header-only counts show the stricter restriction.

## Support and conflict feasibility

| Attack | Full groups | No-IP completed groups | Duration-inclusive groups | Initial completed groups | Header groups |
| --- | --- | --- | --- | --- | --- |
| Benign | 6682887 | 5534773 | 5419630 | 4381009 | 518072 |
| Bot | 15498 | 15498 | 15498 | 14812 | 14733 |
| Brute Force -Web | 173 | 173 | 170 | 143 | 130 |
| Brute Force -XSS | 101 | 101 | 99 | 85 | 77 |
| DDOS attack-HOIC | 230 | 230 | 230 | 230 | 227 |
| DDOS attack-LOIC-UDP | 1667 | 1667 | 1667 | 1667 | 110 |
| DDoS attacks-LOIC-HTTP | 297364 | 49751 | 49724 | 49724 | 16478 |
| DoS attacks-GoldenEye | 32582 | 32582 | 32573 | 32573 | 14116 |
| DoS attacks-Hulk | 108129 | 108129 | 108129 | 108129 | 14116 |
| DoS attacks-SlowHTTPTest | 14116 | 14116 | 14116 | 14116 | 14116 |
| DoS attacks-Slowloris | 17109 | 17109 | 17109 | 17109 | 7247 |
| FTP-BruteForce | 14116 | 14116 | 14116 | 14116 | 14116 |
| Infilteration | 59505 | 59374 | 59333 | 58097 | 29779 |
| SQL Injection | 36 | 36 | 36 | 36 | 35 |
| SSH-Bruteforce | 71148 | 71148 | 71148 | 71148 | 14146 |

Counts above are exact token vector groups with at least one record of that class, not independent sessions. Mixed-label groups count for multiple classes. Current conflicts: {'all_predictors': 256, 'no_ip_completed': 22018, 'duration_inclusive': 24668, 'initial_completed': 32639, 'header_only': 61575}. They cannot be separated by label without leaking identical inputs. A rare class with fewer than three groups cannot support all three partitions at all; more than three is necessary but not sufficient under a fixed assignment. Even hundreds of header groups could all belong to one attack episode. Before training, verify each frozen partition has every promised class and enough independent benign/minority groups. If not, stop the multiclass claim, report unsupported labels explicitly and obtain data or justify a separate binary experiment; never relabel to Benign, silently merge/drop a class or reshuffle until scores look good. No partitions or split manifest have been created here.

## Fitting and reporting boundaries

All learned imputation, encoding, scaling/clip thresholds, constant removal and class weights use **fit only**. Validation supports model/configuration choice and probability-threshold decisions; it is not included in final fitting in the proposed experiment. Any early-stopping subdivision must also respect groups; disable automatic random-row early stopping for the initial HistGradientBoosting fit. Reserve the test once in a manifest with input SHA-256, feature/schema version, seed, groups, labels/counts and code versions. Freeze the model and all thresholds before one test evaluation; no repeated test-based tuning. If capture/time boundaries conflict with exact-key separation, purge/quarantine overlapping earlier groups by a predeclared rule and report counts; do not move future data backwards to optimize support.

Preserve original multiplicities and conflicts; no silent deduplication or majority vote. Future compact representation can weight original counts, but bounded estimator support for weights and leaf semantics must be checked. Balancing/reweighting only in fit, no synthetic benign examples or oversampled validation/test. Report original-row metrics plus equal-vector diagnostics; neither proves event independence.

Report macro-F1, balanced accuracy, per-class precision/recall/F1/support (including zero-support definitions), fixed-order raw and normalized confusion matrices, binary benign FPR = benign predicted attack / all benign, and malicious detection recall. For multiclass, any non-Benign prediction counts toward benign FPR. Include precision-recall metrics when probability scores are available; probabilities require calibration evidence before being called confidence. Report minority group/host/session support and group-based uncertainty where defensible. Accuracy and raw-row support alone can conceal near-duplicate domination.

This fallback measures held-out input combinations within one exported environment, **not independent capture, future traffic or deployment performance**. It is stronger than a random-row split but cannot repair missing provenance. The supplied BoT-IoT official test remains untouched and has no role in this dataset's split or model selection. NF-CSE is one file with no supplied official split; the proposed reserved test is new and has not been created.
