# NF-CSE-CIC-IDS2018: data quality

## Schema and values

All CSV fields are read as UTF-8 strings to preserve token identities and avoid chunk-dependent coercion. Semantic types below describe numeric convertibility in every chunk, not a pandas whole-file guessed dtype. `L7_PROTO` is a numeric-looking categorical code; fractional values do not establish measurement semantics. NA-like tokens are audited separately from truly blank fields; numeric infinities and invalid tokens are separate. Fractional ports/counts/flags would need rejection; fractional L7 IDs are retained for semantic investigation. Negative totals are invalid candidates, not silently clamped. Exact issue examples/counts are in [audit.json](audit.json).

| Column | Observed semantic types | Blank | NA token | Inf | Invalid number | Invalid IPv4 | Fractional | Min | Max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| IPV4_SRC_ADDR | string | 0 | 0 | 0 | 0 | 1 | 0 | — | — |
| L4_SRC_PORT | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 65535.0 |
| IPV4_DST_ADDR | string | 0 | 0 | 0 | 0 | 2 | 0 | — | — |
| L4_DST_PORT | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 65535.0 |
| PROTOCOL | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 58.0 |
| L7_PROTO | float64,int64 | 0 | 0 | 0 | 0 | 0 | 1702753 | 0.0 | 248.0 |
| IN_BYTES | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 24371270.0 |
| OUT_BYTES | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 214122854.0 |
| IN_PKTS | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 279963.0 |
| OUT_PKTS | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 142798.0 |
| TCP_FLAGS | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 223.0 |
| FLOW_DURATION_MILLISECONDS | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 4294967.0 |
| Label | int64 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 1.0 |
| Attack | string | 0 | 0 | 0 | 0 | 0 | 0 | — | — |

Full-file negative-value counts: {}.

Exact constants: {}. Near constants (>=99% one exact token but not constant): {}. These are verified by a second full-file pass after bounded majority-candidate tracking; no high-cardinality numeric frequency table is held in RAM. No claim is made about the mode when below 50%. Globally identical token columns: []. This tests every pair over every row, independently of numeric correlations.

Whitespace/non-ASCII/control-character occurrences: {}. Strict UTF-8 decode errors abort rather than replacing bytes. No Unicode repair is applied.

## Magnitudes and artifacts

| Numeric column | Finite N | Mean | Sample std | Population skew | Sample p01/p50/p95/p99 |
| --- | --- | --- | --- | --- | --- |
| L4_SRC_PORT | 8392401 | 42523.883461955615 | 22012.599474279865 | -1.1378967968555256 | {'p01': 21.0, 'p50': 51658.0, 'p95': 63616.05, 'p99': 65162.03} |
| L4_DST_PORT | 8392401 | 8406.352337430017 | 17572.71748544809 | 2.064485748263211 | {'p01': 21.0, 'p50': 443.0, 'p95': 54230.1, 'p99': 61727.04999999999} |
| PROTOCOL | 8392401 | 8.852956263648508 | 5.004571818112004 | 1.5773336105869034 | {'p01': 6.0, 'p50': 6.0, 'p95': 17.0, 'p99': 17.0} |
| L7_PROTO | 8392401 | 19.059153612893383 | 35.64543136254516 | 1.5335290300178261 | {'p01': 0.0, 'p50': 0.0, 'p95': 91.14, 'p99': 91.22} |
| IN_BYTES | 8392401 | 3761.336621069465 | 130629.80507329844 | 59.99672464099954 | {'p01': 40.0, 'p50': 152.0, 'p95': 3212.0, 'p99': 19468.359999999942} |
| OUT_BYTES | 8392401 | 4346.896442031311 | 257957.77105825127 | 261.63858334026935 | {'p01': 0.0, 'p50': 120.0, 'p95': 4498.199999999997, 'p99': 21064.229999999963} |
| IN_PKTS | 8392401 | 39.42268511716729 | 1948.3064415625206 | 65.98089037591785 | {'p01': 1.0, 'p50': 2.0, 'p95': 23.0, 'p99': 135.0} |
| OUT_PKTS | 8392401 | 5.899267682752529 | 177.2532330028698 | 275.4019653429852 | {'p01': 0.0, 'p50': 1.0, 'p95': 13.0, 'p99': 33.0} |
| TCP_FLAGS | 8392401 | 64.09238512316084 | 89.04567648843344 | 1.146425901034401 | {'p01': 0.0, 'p50': 24.0, 'p95': 222.0, 'p99': 223.0} |
| FLOW_DURATION_MILLISECONDS | 8392401 | 2832315.4091596664 | 2030249.8456969347 | -0.6779806615211483 | {'p01': 0.0, 'p50': 4291914.0, 'p95': 4294966.0, 'p99': 4294967.0} |
| Label | 8392401 | 0.12144355351942787 | 0.3266420510915457 | 2.317867327669967 | {'p01': 0.0, 'p50': 0.0, 'p95': 1.0, 'p99': 1.0} |

Header/flow rule counts (full file):

| Rule | Rows |
| --- | --- |
| L4_DST_PORT_nontransport_nonzero | 0 |
| L4_DST_PORT_out_of_range | 0 |
| L4_DST_PORT_zero | 50256 |
| L4_SRC_PORT_nontransport_nonzero | 0 |
| L4_SRC_PORT_out_of_range | 0 |
| L4_SRC_PORT_zero | 50256 |
| PROTOCOL_out_of_range | 0 |
| TCP_FLAGS_out_of_range | 0 |
| in_bytes_without_packets | 0 |
| non_tcp_nonzero_flags | 0 |
| out_bytes_without_packets | 0 |
| zero_duration | 2848134 |
| zero_in_packets | 3 |
| zero_out_packets | 2811463 |

Port zero is legal and is not automatically missing. Nontransport port tokens, absent reverse packets and zero duration need exporter semantics; zero reverse totals do not prove absence of reverse visibility in capture. Large durations and totals may reflect units, timeout/counter/export behavior. The supplied dictionary says milliseconds but does not define timestamp origin, timeout, counter width or sampling. Do not infer a correction factor, clip tails or diagnose overflow from extremes alone. Obtain exporter configuration or source traces. Cumulative TCP flags are not per-packet flags.

| Column | Exact token cardinality | Most frequent tokens/counts (up to 10) |
| --- | --- | --- |
| IPV4_SRC_ADDR | 75405 | [['172.31.69.25', 840864], ['18.221.219.4', 193360], ['18.219.193.20', 108136], ['13.59.126.31', 105550], ['172.31.69.24', 100992], ['13.58.98.64', 94237], ['5.101.40.43', 74883], ['5.101.40.105', 73661], ['172.31.67.6', 45162], ['18.219.9.1', 39607]] |
| IPV4_DST_ADDR | 26303 | [['172.31.0.2', 2045759], ['172.31.69.25', 940292], ['169.254.169.254', 238785], ['18.221.219.4', 193360], ['18.219.193.20', 108122], ['13.59.126.31', 105550], ['13.58.98.64', 94237], ['18.219.211.138', 43659], ['172.31.65.77', 37614], ['72.21.91.29', 33460]] |
| PROTOCOL | 7 | [['6', 6171561], ['17', 2170585], ['1', 38743], ['2', 6034], ['58', 5469], ['47', 5], ['0', 4]] |
| L7_PROTO | 237 | [['0.0', 5499959], ['88.0', 454106], ['91.126', 437970], ['7.0', 381997], ['5.126', 357950], ['91.178', 260540], ['41.0', 155847], ['91.0', 116248], ['5.178', 77605], ['5.119', 55318]] |
| Attack | 15 | [['Benign', 7373198], ['DDoS attacks-LOIC-HTTP', 378199], ['FTP-BruteForce', 193360], ['DoS attacks-Hulk', 108136], ['DoS attacks-SlowHTTPTest', 105550], ['SSH-Bruteforce', 94237], ['Infilteration', 62072], ['DoS attacks-GoldenEye', 32850], ['DoS attacks-Slowloris', 22825], ['Bot', 15683]] |
| Label | 2 | [['0', 7373198], ['1', 1019203]] |

Categorical L7 values are kept as exact tokens, including composite-looking decimal IDs; do not round or treat their numeric distance as meaningful. IPs are syntactically audited but endpoint roles cannot be inferred reliably from address strings alone. Top IPs may reveal testbed concentration; raw addresses must not be predictors.

## Export-duration boundary investigation

The full-file maximum duration is 4294967.0 in the dictionary's stated milliseconds; sample quantiles are above. Counts below are a separate full-file check at exactly the maximum, zero and >=99% of the observed maximum (a diagnostic range, not a clipping rule):

| Attack | Rows | Zero duration | Exactly maximum | >=99% of observed maximum |
| --- | --- | --- | --- | --- |
| Benign | 7373198 | 1904623 | 257436 | 5161610 |
| Bot | 15683 | 0 | 0 | 15683 |
| Brute Force -Web | 2613 | 1243 | 0 | 109 |
| Brute Force -XSS | 1745 | 829 | 0 | 46 |
| DDOS attack-HOIC | 230 | 0 | 0 | 97 |
| DDOS attack-LOIC-UDP | 1667 | 1667 | 0 | 0 |
| DDoS attacks-LOIC-HTTP | 378199 | 378199 | 0 | 0 |
| DoS attacks-GoldenEye | 32850 | 32850 | 0 | 0 |
| DoS attacks-Hulk | 108136 | 108136 | 0 | 0 |
| DoS attacks-SlowHTTPTest | 105550 | 105550 | 0 | 0 |
| DoS attacks-Slowloris | 22825 | 22825 | 0 | 0 |
| FTP-BruteForce | 193360 | 193360 | 0 | 0 |
| Infilteration | 62072 | 4615 | 8872 | 54727 |
| SQL Injection | 36 | 0 | 0 | 36 |
| SSH-Bruteforce | 94237 | 94237 | 0 | 0 |

A concentration near a numeric ceiling can be an exporter/timer artifact or a property of the observations. The measured maximum 4,294,967, when present, is also floor((2^32−1)/1000), an arithmetic pattern only; **no overflow, unit-conversion bug or causal explanation is established**. Source exporter configuration and original timing are needed. Do not invert, rescale, clip or learn an attack rule from this pattern without verification. Compare duration-free sensitivity later using validation only.

## Exact duplicates and ambiguity

| View | Distinct vectors | Repeated vector groups | Rows in repeated vectors | Vector excess | Exact record excess | Conflicting groups | Rows in conflicts | Largest group |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| all_predictors | 7314397 | 386257 | 1464261 | 1078004 | 1077740 | 256 | 3808 | 1173 |
| no_ip_completed | 5896743 | 522141 | 3017799 | 2495658 | 2473598 | 22018 | 353861 | 27250 |
| duration_inclusive | 5778866 | 539131 | 3152666 | 2613535 | 2588823 | 24668 | 385273 | 27250 |
| initial_completed | 4730309 | 825550 | 4487642 | 3662092 | 3629407 | 32639 | 493632 | 27250 |
| header_only | 574580 | 355685 | 8173506 | 7817821 | 7734903 | 61575 | 3965063 | 38743 |

Views (ordered column lists): {"all_predictors": ["IPV4_SRC_ADDR", "L4_SRC_PORT", "IPV4_DST_ADDR", "L4_DST_PORT", "PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "TCP_FLAGS", "FLOW_DURATION_MILLISECONDS"], "no_ip_completed": ["PROTOCOL", "L4_SRC_PORT", "L4_DST_PORT", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "TCP_FLAGS", "FLOW_DURATION_MILLISECONDS"], "duration_inclusive": ["PROTOCOL", "L4_SRC_PORT", "L4_DST_PORT", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS"], "initial_completed": ["PROTOCOL", "L4_SRC_PORT", "L4_DST_PORT", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS"], "header_only": ["PROTOCOL", "L4_SRC_PORT", "L4_DST_PORT"]}.

Keys are exact JSON arrays of **parsed CSV token strings**, compared directly in SQLite B-trees, without probabilistic hashes. Quoting or newline-format differences in the CSV serialization are not different record values. `all_predictors` plus both labels represents exact full records. Other exact-record-excess columns mean records projected onto that view plus both labels. Vector excess = rows − distinct vectors; exact-record excess = rows − distinct (vector, binary, attack) tuples; repeated-vector rows include the first occurrence. A conflict means >1 distinct label pair for identical retained tokens. It need not imply annotation error: removal of context creates irreducible ambiguity. No record is dropped, no majority relabeling performed. Alias/number normalization may create additional collisions; these counts are **not yet canonical preprocessing keys**. Future canonical retained keys require a new group audit before partitioning.

| Attack | Full predictor groups | No-IP completed groups | Duration-inclusive groups | Initial completed groups | Header-only groups |
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

These counts are overlapping class supports: a mixed-label group contributes to each affected class, so they cannot be summed as disjoint episodes. Audit JSON retains five deterministic conflict examples per view with label counts. Representative first examples (vectors in the view order listed above):

| View | Retained vector (exact tokens) | Binary / Attack / row multiplicities |
| --- | --- | --- |
| all_predictors | ['13.58.42.57', '1028', '172.31.69.28', '500', '17', '0.0', '1056', '0', '2', '0', '0', '0'] | [['1', 'Brute Force -Web', 4], ['1', 'Brute Force -XSS', 4]] |
| all_predictors | ['13.58.42.57', '1028', '172.31.69.28', '500', '17', '0.0', '1584', '0', '3', '0', '0', '0'] | [['1', 'Brute Force -Web', 1], ['1', 'Brute Force -XSS', 1]] |
| no_ip_completed | ['17', '1024', '500', '0.0', '1056', '0', '2', '0', '0', '0'] | [['1', 'Brute Force -Web', 1], ['1', 'Brute Force -XSS', 1]] |
| no_ip_completed | ['17', '1024', '500', '0.0', '528', '0', '1', '0', '0', '0'] | [['1', 'Brute Force -Web', 10], ['1', 'Brute Force -XSS', 10]] |
| duration_inclusive | ['17', '1024', '500', '1056', '0', '2', '0', '0'] | [['1', 'Brute Force -Web', 1], ['1', 'Brute Force -XSS', 1]] |
| duration_inclusive | ['17', '1024', '500', '1584', '0', '3', '0', '4283766'] | [['1', 'Brute Force -Web', 1], ['1', 'Brute Force -XSS', 1]] |
| initial_completed | ['17', '1024', '500', '1056', '0', '2', '0'] | [['1', 'Brute Force -Web', 1], ['1', 'Brute Force -XSS', 1]] |
| initial_completed | ['17', '1024', '500', '1584', '0', '3', '0'] | [['1', 'Brute Force -Web', 1], ['1', 'Brute Force -XSS', 1]] |
| header_only | ['17', '1024', '500'] | [['1', 'Brute Force -Web', 812], ['1', 'Brute Force -XSS', 812]] |
| header_only | ['17', '1028', '500'] | [['1', 'Brute Force -Web', 814], ['1', 'Brute Force -XSS', 814]] |

The observed examples include `Brute Force -Web` and `Brute Force -XSS` sharing UDP port-500 flow vectors, and a header-only UDP/123 vector shared by Benign and Infilteration. This raises label-granularity/background-traffic and scenario-generation questions: an attack-labelled record need not contain evidence of that attack in the retained fields. The examples do not prove which source annotation, if any, is wrong. Full-feature conflicts cannot be repaired from these features; no timestamp/session mapping is available to distinguish repeated similar events. An example can contain raw addresses for audit only, never for serving/training. Identical retained vectors must stay together; random-row splits can copy them into evaluation and amplify repeated scenario signatures. Report both original-row-weighted and equal-vector diagnostics later; weighting does not create independent sessions. Exact-key separation also cannot eliminate correlated neighboring flows or repeated campaigns.

## Correlations

Sampled Pearson correlation matrix, numeric-coded columns including `Label`, is saved only as diagnostics in `audit.json` (`correlation_sample`). Labels are never predictors; protocol/L7 numeric-code correlation has no ordinal interpretation. Correlation is not evidence of causal feature availability, redundancy or leakage-free behavior. Global identical-column test above is stronger for exact duplication. Quantiles/correlations use a seeded priority sample; very rare classes may be absent, so they cannot support rare-class distribution conclusions. No target-driven feature selection is performed.
