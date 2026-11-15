# BoT-IoT restricted baseline: feature availability and leakage audit

Scope: the original BoT-IoT training CSV and the existing EDA. DNS remains NO-GO under [its investigation](../dataset_analysis/dns_investigation.md). The supplied BoT-IoT test split is not accessed by this training/evaluation runner. `AGENTS.md` was read and is empty. Availability judgments below are conservative engineering assessments; exporter configuration and packet provenance are not supplied.

## Feature decisions

| Source column | Target / identifier risk | Observation needed | First baseline decision |
| --- | --- | --- | --- |
| `pkSeqID` | Export row identifier; can encode dataset ordering/scenario | Export metadata; no portable live meaning | Exclude |
| `proto` | Protocol may correlate with testbed attack construction | Packet header in one observed direction | Include normalized categorical protocol; retain scenario-bias caveat |
| `saddr` | Raw host identity can memorize roles/environment | Packet header | Exclude entirely |
| `sport` | Ephemeral/service distribution can encode tools/scenarios | TCP/UDP transport header; exported direction must be verified | Include protocol-aware normalized value/status/range |
| `daddr` | Destination identity strongly correlates with testbed roles | Packet header | Exclude entirely |
| `dport` | Service identity and attack setup can dominate performance | TCP/UDP transport header | Include protocol-aware normalized value/status/range; evaluate service generalization later |
| `seq` | Argus/export sequence metadata; possible ordering leakage | Exporter state; not assumed to be TCP sequence | Exclude |
| `stddev` | Potential look-ahead through aggregation | Aggregate records/window and completion boundaries | Exclude |
| `N_IN_Conn_P_SrcIP` | Historical/capture-wide source aggregate; causality unverified | Several observations and explicit causal window | Exclude |
| `min` | Aggregate duration context unavailable at first packet | Completed records/window/timeout | Exclude |
| `state_number` | Encoded final state can reveal responses/teardown/attack outcome | Often reverse direction, completed flow or timeout; codebook absent | Exclude |
| `mean` | Aggregate duration context; may include later records | Completed records/window/timeout | Exclude |
| `N_IN_Conn_P_DstIP` | Historical/capture-wide destination aggregate; causality unverified | Several observations and explicit causal window | Exclude |
| `drate` | Reverse-direction rate; final rate can depend on future packets | Bidirectional visibility and elapsed/completed observation window | Exclude |
| `srate` | Source-only running rates are possible, but CSV final-rate timing is unknown | Elapsed/completed flow or explicitly past-only interval | Exclude |
| `max` | Final duration maximum can expose later observations | Completed records/window/timeout | Exclude |
| `attack` | Binary ground truth and direct target leakage | Offline annotation | Exclude from predictors |
| `category` | Four-class target source | Offline annotation | Target only; never predictor |
| `subcategory` | Closely related ground truth and direct target leakage | Offline annotation | Exclude from predictors |

Every model input originates from exactly `proto`, `sport`, `dport`. The reusable normalizer selects these columns explicitly and ignores all extras. The training reader opens only those three columns and `category`; it does not load addresses, record IDs or excluded summaries. Unit tests verify invariance when labels, addresses, identifiers and aggregate values are added or changed.

The EDA found 370 Normal training records out of 2,934,817 total records (0.012607%), 65 Theft records, raw port `-1` aligned with ARP, and hexadecimal port fields in ICMP records. These findings motivated the declared policies before this fit. The EDA's 53 train/test operational-vector overlaps are historical audit findings; they are not used to tune or evaluate this baseline. The restricted representation can expose additional ambiguity beyond the full flow vector.

## Port and protocol contract

- Canonical protocols: TCP/6, UDP/17, ICMP/1/icmpv4, IPv6-ICMP/58/icmpv6, ARP; aliases are case/whitespace normalized. Missing and other protocols are explicit values. An unsupported protocol has no assumed transport-port semantics.
- Only TCP/UDP receive real ports. Nontransport inputs, including ICMP type/code hex fields and ARP sentinels, become `not_applicable`; their raw values are not numeric TCP/UDP features. This intentionally drops ICMP type/code information until a separately verified decoder exists.
- Decimal and hexadecimal integer TCP/UDP ports are normalized to the same number, with leading zeroes accepted. Integer-valued numeric scalars are accepted; noninteger textual numbers, malformed tokens, nonfinite values and numbers outside 0–65535 are invalid. Zero is valid. `-` and `-1` are sentinel values for TCP/UDP, and blank/NA values are missing. Range violations are flagged by status, not clamped into valid service IDs.
- Fixed numeric values are port/65535 with zero for unavailable inputs. Separate status tokens prevent confusing unavailable with valid port 0. Fixed ranges are well-known, registered, dynamic and none. Unknown one-hot categories are ignored safely; the encoder is fitted on training partitions only.
- Missingness, exporter sentinel behavior, service ports and protocol still carry possible collection artifacts. Excluding explicit identifiers does not remove scenario bias. These risks require independent-source and sensitivity evaluations; the first run does not estimate them away.

## Targets and unsupported attacks

The initial targets, in report order, are `Normal`, `DoS`, `DDoS`, `Reconnaissance`. All `Theft` rows remain unchanged in the raw file and are counted as unsupported/excluded from this four-class fit and validation. Unknown new category names raise an error. Theft is never mapped to benign, and this closed-set model has no trained Theft class or validated unknown-attack rejection mechanism. A Normal prediction cannot establish absence of Theft or other unseen threats.

## Validation boundaries

Groups are exact normalized model inputs, including protocol, port values and status/range information, with no target labels, addresses or row IDs. SHA-256 and seed 20261115 assign entire groups to nominal 80% fitting / 20% validation; group counts, row proportions and rare-class coverage are reported after assignment. There is no seed search or target-based split retry.

Grouping at the retained input level is stronger than merely grouping full operational vectors: every duplicate full operational row projects to the same retained group. Canonical aliases and inputs made identical by feature restriction also stay together. The same key can have several different target labels; their counts remain separate within the same partition. Such conflicts are expected when removing context and are not automatically annotation errors. No group is relabeled or silently deduplicated. Compact weighting preserves raw multiplicities for fitting and validation.

Full sessions, hosts, attack campaigns, captures and chronological windows cannot be isolated from these header triples. The group split tests held-out normalized inputs drawn from this training-file environment; it does not certify independent network events or temporal generalization. All learned encodings and inverse-frequency class weights use the fitting partition alone. The supplied test split remains untouched for later authorized evaluation, with existing contamination caveats disclosed.

## Availability boundary and next evidence needed

These features can be read from suitable plaintext packet headers, but this experiment operates on CSV flow-export records. Packet direction/orientation, fragmentation, protocol parser behavior, observation loss and exporter-to-capture parity have not been validated. No packet sniffer, causal window builder, flow finalization adapter or live deployment is implemented. No live packet-level intrusion-detection capability is claimed.

Before expanding features, obtain the exporter configuration and independently timestamped captures. Define source/destination orientation, state handling, observation window and timeout policy; prove every new count/rate uses only observations available by prediction time. Evaluate bounded causal windows on future captures. Completed-flow and bidirectional tasks, if pursued, require separate documented inference contracts and evaluation rather than being presented as first-packet detection.

Current results and recommendations: [validation report](bot_iot_validation.md). Earlier provenance and feature limitations: [BoT-IoT EDA](../dataset_analysis/bot_iot_report.md). The EDA cites the original UNSW dataset page and authors' paper; no new dataset semantics beyond that evidence are asserted here.
