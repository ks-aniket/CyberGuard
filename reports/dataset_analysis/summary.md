# CyberGuard dataset analysis summary

Generated 2026-11-15T09:32:40.888589+00:00 (UTC).

## Dataset characteristics

| Dataset | Train rows | Test rows | Columns | Labels |
| --- | --- | --- | --- | --- |
| bot_iot | 2,934,817 | 733,705 | 19 | attack, category, subcategory |
| dns_threats | 2,482,810 | 620,703 | 2 | class |

BoT-IoT supplies network flow/export features; DNS supplies a single raw string feature. Analyze and evaluate them separately; there is no supported cross-dataset join.

## Class imbalance findings

- bot_iot/train `attack`: 2 classes; minority `0` 370/2,934,817 (0.012607%); majority/minority 7930.94:1.
- bot_iot/test `attack`: 2 classes; minority `0` 107/733,705 (0.014584%); majority/minority 6856.06:1.
- bot_iot/train `category`: 5 classes; minority `Theft` 65/2,934,817 (0.002215%); majority/minority 23712.54:1.
- bot_iot/test `category`: 5 classes; minority `Theft` 14/733,705 (0.001908%); majority/minority 27522.07:1.
- bot_iot/train `subcategory`: 8 classes; minority `Data_Exfiltration` 6/2,934,817 (0.000204%); majority/minority 264108.33:1.
- bot_iot/test `subcategory`: 7 classes; minority `Keylogging` 14/733,705 (0.001908%); majority/minority 28327.14:1.
- dns_threats/train `class`: 3 classes; minority `2` 6,441/2,482,810 (0.259424%); majority/minority 237.89:1.
- dns_threats/test `class`: 3 classes; minority `2` 1,559/620,703 (0.251167%); majority/minority 245.72:1.
- bot_iot/subcategory: classes absent from test: Data_Exfiltration; their recall cannot be evaluated on this test split.

DNS numeric label meanings are unverified: do not assume a benign code or fabricate a binary grouping. Full split percentages and shifts are in each dataset report.

## Data quality problems and potential leakage

- bot_iot/train: 0 missing cells; 0 infinite cells; 332 invalid cells under documented numeric/IP rules. DNS lexical screening flags are separate in its report.
- bot_iot/test: 0 missing cells; 0 infinite cells; 94 invalid cells under documented numeric/IP rules. DNS lexical screening flags are separate in its report.
- bot_iot/raw: train/test duplicate excess 0/0; shared feature+label groups 0, affecting 0 train and 0 test rows; within-split conflicting vectors 0/0; cross-split conflicting vectors 0.
- bot_iot/operational: train/test duplicate excess 125/7; shared feature+label groups 53, affecting 53 train and 53 test rows; within-split conflicting vectors 0/0; cross-split conflicting vectors 0.
- dns_threats/train: 0 missing cells; 0 infinite cells; 0 invalid cells under documented numeric/IP rules. DNS lexical screening flags are separate in its report.
- dns_threats/test: 0 missing cells; 0 infinite cells; 0 invalid cells under documented numeric/IP rules. DNS lexical screening flags are separate in its report.
- dns_threats/raw: train/test duplicate excess 117,804/7; shared feature+label groups 0, affecting 0 train and 0 test rows; within-split conflicting vectors 100/0; cross-split conflicting vectors 0.
- DNS/train: 2,364,906 distinct domain strings; 100.0000% have no dot. Confirm whether these are stripped labels rather than full query names.
- DNS/test: 620,696 distinct domain strings; 0.0074% have no dot. Confirm whether these are stripped labels rather than full query names.

BoT-IoT identifiers can conceal matching traffic vectors; all labels must be excluded from predictors. Strong endpoint/protocol associations can encode scenario roles. Final flow state, reverse rate and aggregate windows can leak unavailable reverse/future traffic into a live detector. DNS repeated strings may permit memorization. Raw string checks omit case/numeric canonicalization and near-duplicates. No timestamps/session/family provenance are supplied, so temporal leakage and causal extraction cannot be ruled out. Neither dataset alone establishes real-world performance.

## Recommended preprocessing (not implemented)

BoT-IoT: exclude pkSeqID/seq and all three labels; validate port specials and state codebooks, ablate IP identities, encode categories with unknown-value handling, and assess log1p/robust scaling on highly skewed numeric inputs. Fit imputation/scaling/encoding only in training folds. Design past-only windows and establish train/live feature parity; drate and final state are unsuitable without reverse visibility and completion rules.

DNS: resolve the observed train/test single-label versus dotted-name mismatch before evaluating models; zero raw-string overlap is not evidence of underlying domain independence. Verify code meanings and domain representation; investigate conflicting labels and repetitions before proposing a deduplication policy. Consider IDNA/case/trailing-dot policy, lightweight lexical summaries or bounded sparse character n-grams, with group-safe train validation. Do not one-hot every unique domain. All changes require a later implementation task; this run preserves every raw row.

## Recommended model training strategy (no training performed)

Use train-only grouped validation with leakage groups, leaving supplied test splits untouched and reporting observed contamination. Obtain session/time/family metadata for stronger evaluation. Start with CPU-friendly class-weighted linear baselines and bounded tree/histogram models; use sparse linear models for character n-grams. Tune on training folds only, keep sampling inside folds, and avoid large oversampled copies. Evaluate binary and multiclass tasks separately where verified, using macro-F1, balanced accuracy, per-class precision/recall, confusion matrices and rare-class uncertainty; add PR-AUC/false-positive rates for verified binary targets. Scarce benign and minority samples require more representative data rather than confidence from accuracy alone.

## CPU, memory and reproducibility

Command: `.venv/bin/python scripts/inspect_datasets.py --chunk-size 50000 --sample-size 30000`. Python analysis uses pandas 3.1.1, NumPy 2.5.4, SQLite 3.50.4. No GPU or plotting dependency is required. SVG plots are self-contained.

Measured wall time: 270.5 seconds; process peak RSS: 377.5 MiB (Linux getrusage, includes native arrays/caches). Each split keeps at most 30,000 sampled rows plus a 50,000-row chunk and bounded numerical accumulators. BoT categorical counts scale with token cardinality; high-cardinality DNS domains and duplicate signatures stay in SQLite. SQLite has a 64 MiB page cache and disk-backed sorting; temporary indexes are deleted after each dataset. Budget several GB of free temporary disk and single-process CPU time. Limit BLAS threads externally if needed; this script does not spawn workers.

Counts/moments/correlations and categorical cardinalities are full-file results; quantiles/distribution plots/outlier percentages are seeded sample estimates. SHA-256 fingerprints are used for BoT-IoT identity comparisons. Full pairwise Pearson matrices are CSV artifacts. Input size and modification time are verified unchanged at completion; inputs are opened read-only. No model or preprocessing artifacts were created.

## Reports

- [BoT-IoT report](bot_iot_report.md)
- [DNS Threats report](dns_threats_report.md)

Provenance reference: [UNSW dataset page](https://research.unsw.edu.au/projects/bot-iot-dataset). All dataset statistics in these reports come from the local CSV files; streaming availability judgments are conservative engineering assessments.
