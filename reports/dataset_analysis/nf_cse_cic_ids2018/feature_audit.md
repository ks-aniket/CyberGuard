# NF-CSE-CIC-IDS2018: feature availability and leakage

Evidence: local `data/NetFlow_v1_Features.csv`, actual CSV schema and value audits. The dictionary does not specify exporter software/version, direction, counter accounting, timeouts, packet sampling, L7 codebook or exact flag aggregation. Availability classifications are conservative design judgments, not a validated packet extractor.

A = packet header; B = possible causal running feature **with a specified cutoff**; C = final/exported flow value; D = reverse/bidirectional observation; E = identifier/label or scenario leakage risk; F = undocumented/ambiguous semantics. Multiple categories distinguish what could be derived from packets from what this exported column represents.

| Column | Supplied description | Categories | Initial decision / observation boundary |
| --- | --- | --- | --- |
| IPV4_SRC_ADDR | IPv4 source address | A/E | One IPv4 header; raw host identity / scenario memorization. Exclude; retain privately for split diagnostics. |
| L4_SRC_PORT | IPv4 source port number | A/E | TCP/UDP header where available; service/tool artifact risk. Include with protocol-aware validity/status; direction must match exporter. |
| IPV4_DST_ADDR | IPv4 destination address | A/E | One IPv4 header; raw endpoint identity. Exclude; host split may use both endpoints conservatively. |
| L4_DST_PORT | IPv4 destination port number | A/E | TCP/UDP header; service/scenario proxy risk. Include, assess service sensitivity later. |
| PROTOCOL | IP protocol identifier byte | A/E | IP header identifier; include categorically; protocol mix can encode scenario. |
| L7_PROTO | Layer 7 protocol (numeric) | F/E | Layer-7 numeric code; classifier/version/codebook and number of packets needed unknown. Exclude initial fit, including decimal sub-IDs; may proxy traffic generator or exporter. |
| IN_BYTES | Incoming number of bytes | B/C/F | Running forward bytes possible, but CSV is an exported total; byte accounting and orientation unverified. Include only for offline finalized-record baseline, never substitute partial bytes. |
| OUT_BYTES | Outgoing number of bytes | B/C/D/F | Reverse/outgoing total; use only with compatible two-direction exporter and finalization. Zero is not missing by default. |
| IN_PKTS | Incoming number of packets | B/C/F | Running forward count possible; current record total requires end/timeout. Include only finalized records. |
| OUT_PKTS | Outgoing number of packets | B/C/D/F | Reverse count requires reverse visibility; include only finalized records with verified orientation. |
| TCP_FLAGS | Cumulative of all TCP flags | A/B/C/F | Individual flags are headers, but supplied cumulative flags include later packets. Reverse-direction aggregation and bit semantics unspecified; exclude first fit pending specification. |
| FLOW_DURATION_MILLISECONDS | Flow duration in milliseconds | B/C/F | Elapsed duration possible causally, but final exported duration is available at termination/timeout. Quarantine from initial fit: class-aligned zeros and ceiling concentration require exporter/timing evidence. |
| Label | Not in supplied feature dictionary | E | Binary target only. Never input or imputation feature. |
| Attack | Not in supplied feature dictionary | E | Multiclass target only. Preserve exact labels; never input. |

## Initial feature contract

Recommend an **offline finalized-flow CSV experiment** with seven non-IP inputs: `PROTOCOL`, `L4_SRC_PORT`, `L4_DST_PORT`, `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`. Three header fields plus four final counters are proposed. Exclude both IPs, both labels, `L7_PROTO`, `TCP_FLAGS` and duration. The duration audit shows class-aligned zeros and a strong concentration near a numerical ceiling, so duration is quarantined from the initial fit until its export semantics are verified; do not silently correct it. Final values and reverse totals are allowed only under this explicitly completed-flow task. Counter accounting and direction verification are gates before using the four flow counters in any inference adapter. If those gates cannot be satisfied, restrict to the three header fields as an offline comparison and disclose its ambiguity counts in [quality](data_quality.md).

Packet-level classification: only the protocol/port subview is potentially header-accessible, subject to fragmentation, TCP/UDP availability and orientation; a flow-export classifier is not packet-validated. Partial-flow classification: **not supported by these final-record labels/features alone**; requires source captures, a defined cutoff, causal counters and a separate train/evaluation dataset matching that cutoff. Completed-flow classification: plausible offline use of the seven-input contract, with unknown exporter semantics explicitly gated; predictions wait for termination or configured timeout. No capture, replay, exporter, flow finalizer or live detection is implemented.

IP exclusion does not remove service/tool/host fingerprints in ports, protocol, zero counters or duration artifacts. Cumulative flags may encode teardown/outcome and L7 detection may need future packets; do not reintroduce them as a performance shortcut. No capture-wide historical aggregates are present in this 12-predictor schema, but upstream generation/sampling artifacts remain unverified. High correlations alone cannot clear a feature for deployment.
