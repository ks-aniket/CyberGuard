# DNS dataset representation investigation

Investigation date: 2026-11-15 15:45 IST. Scope: the two supplied DNS CSV files only. `AGENTS.md` was read and is empty (0 bytes); the prior summary and DNS report were read.

## Decision: NO-GO for training on the supplied three-class train/test pair

The existing files are not a defensible basis for training and evaluating CyberGuard’s live three-class DNS detector as supplied. The class mapping is now confirmed, but training strings and test strings represent different prediction units. A projection that makes their superficial statistics similar also exposes substantial overlap and loses tunneling information. Resolve representation lineage, ambiguous labels and evaluation groups before training. Preserve the supplied test split as an immutable, already-inspected audit benchmark; do not rebuild training data from it.

## Evidence scope and method

Both CSVs were scanned independently in 50,000-row chunks using pandas/NumPy and a disk-backed SQLite audit. All 3,103,513 records were inspected; representative examples below are the first six encountered per split/class, not a random or exhaustive characterization. Counts, character frequencies, length distributions and entropy summaries in this report cover the full populations. No models, fitted encoders, preprocessing modules, cleaned datasets or new train/test splits were produced. Candidate string projections were evaluated transiently for overlap and information-loss diagnostics only. No DNS lookups were performed.

The scan took 49.2 seconds and peaked at 593.5 MiB RSS on this Linux process. Numeric diagnostic arrays and frequency counters were retained; domain identity checks used SQLite with a 64 MiB cache and disk-backed sorting. This fits the CPU-only, approximately 16 GB RAM environment. SHA-256 hashes of both raw files were checked before and after analysis and were unchanged.

## 1. Provenance and confirmed class mappings

The dataset maintainers’ [README](https://mcfp.felk.cvut.cz/publicDatasets/DNS-Threats-Dataset/README.html) explicitly assigns the CSV `class` codes below (the README spells benign as “Bening”). This verifies the hypotheses; the earlier EDA’s mapping uncertainty is resolved. [Zenodo Version 1](https://zenodo.org/records/6508640) names the same two archives and provides their checksums.

| Code | Confirmed meaning | Training rows | Test rows |
| --- | --- | --- | --- |
| 0 | Benign / Normal | 944,106 | 236,072 |
| 1 | DGA | 1,532,263 | 383,072 |
| 2 | DNS tunneling | 6,441 | 1,559 |

The release describes DGA examples from 51 malware families and laboratory tunneling examples generated with iodine, dnscat2 and dnsExfiltrator. These are collection-level descriptions; the local CSVs contain no row-level family, tool, session, seed or capture-time identifiers. [Release documentation](https://zenodo.org/records/6508640).

The original archives were downloaded into `/tmp` without overwriting either raw CSV. Each compressed archive’s MD5 matches the checksum displayed by Zenodo. SHA-256 of its decompressed bytes matches the corresponding local CSV:

| Split | Archive MD5 (matches release) | Decompressed bytes | Local and decompressed SHA-256 |
| --- | --- | --- | --- |
| train | c30a49c6f362e0c2dffe3881504a6825 | 42,771,791 | 42de9f7bbbed2dc09512a1f8302c67e5ef827987edaae78770ad034eeddc2dd8 |
| test | ce52df239c4245ffaa15c642b8b0b625 | 13,237,038 | 7343e18f861f9eb6ede5eb4de478ae00cd023e5676093eaba20df611ede42010 |

Thus the single-label/dotted-name discrepancy is present in the published artifacts. It was not introduced by the local CyberGuard EDA or a local file substitution. This establishes artifact identity, not the correctness of every individual label.

## 2. Representative strings and what they show

All examples are literal file contents, formatted as code and intentionally not linked. Class names follow the verified mapping.

### train: 0 (Benign)

- `namazvakti`
- `babybrezza`
- `jtads`
- `schneider`
- `escort-guide`
- `healthyslowcooking`

### train: 1 (DGA)

- `r5r5sp3et32`
- `v4ml7xko7pcz1dpiso31xwi4lm`
- `zjnaancorml`
- `16ql740g2v0dq1iu35o911nc4ig`
- `ixp1r77qf7e41uphcw3jmdxyi`
- `uogsiwiuggqaawyq`

### train: 2 (Tunneling)

- `ytb5gq`
- `pabiozra`
- `8b3f01b2c5e806215945c200197d90a92e`
- `0rdat0qonyvkrl2u3dpqw1aoogbmduryxvkpltkruontxax5tnhv221od1wl3a`
- `paaahyki`
- `paaioz0i`

### test: 0 (Benign)

- `askforspecial.com`
- `irepair.in`
- `mangable.com`
- `gameleader.cz`
- `pur-nadobi.cz`
- `allthemoney.org`

### test: 1 (DGA)

- `xujozlat.ru`
- `myomgeocygocsouc.org`
- `skqgowoggookqigy.org`
- `fnxqererwyatanb.com`
- `1ybtwjshh333h12yi9r7l1bl6t.org`
- `49yfa5n1cmps.com`

### test: 2 (Tunneling)

- `3eabapdnggydixon2aaaedrlp55zvgcamdmoehp2zp313hh4j5cibdeylkmqih.yddcaeir2gls.securitytesting.online`
- `pafiifcy.securitytesting.online`
- `25d201a3961a6dbfa3e59300643806bab8.securitytesting.harpozedcompute.com`
- `pamafw3q.securitytesting.online`
- `9923035bb70000000084624093179e93f4dd024693fc9428070c1faf7205.603b3aad15ad54b54b739cf2b6af323d771471986a1f3738312ced507383.d5d2aaa001a16c281e1bc0f3b3.securitytesting.online`
- `e2dc01ce4329fab4083da500f08c5483ab.securitytesting.harpozedcompute.com`

Training examples include ordinary name stems, generated-looking stems and tunnel-like payload tokens. Test examples include suffixes and, for tunneling, several dot-separated payload/control labels plus laboratory domain names. Visual appearance alone does not establish maliciousness; the documented labels establish the intended task.

## 3. Why the representations differ: established facts and limits

| Split/class | Dotted rows / total | Mean labels per string | Maximum individual label length | Strings with a label >63 chars |
| --- | --- | --- | --- | --- |
| test/0 | 236,027 / 236,072 | 2.1203 | 45 | 0 |
| test/1 | 383,071 / 383,072 | 2.0166 | 45 | 0 |
| test/2 | 1,559 / 1,559 | 3.7024 | 63 | 0 |
| train/0 | 0 / 944,106 | 1.0000 | 45 | 0 |
| train/1 | 0 / 1,532,263 | 1.0000 | 45 | 0 |
| train/2 | 0 / 6,441 | 1.0000 | 65 | 386 |

Every one of the 2,482,810 training strings lacks dots. In testing, 620,657/620,703 strings contain dots; the 46 exceptions comprise 45 benign and one DGA string. Dotted strings are described here as FQDN-like: the CSV alone does not prove their absolute DNS interpretation or resolvability.

An asymmetric upstream extraction/export is the leading explanation. Benign and DGA test names’ leftmost-label lengths and entropy almost exactly match their corresponding training distributions (Section 4). Training tokens such as `www` and `ns1` also resemble subdomain labels. This supports a label/stem extraction hypothesis, but does not identify an exact function: first-label selection, suffix removal, concatenation, truncation and mixed source-specific handling cannot be distinguished conclusively without the preparation code or parent records.

The 386 overlength training strings are all class 2: a single 64–65-character token is longer than a standard DNS wire label. These may be extracted/concatenated/truncated payload representations or problematic source records. They must not automatically be treated as valid full query names or repaired by truncation. Benign and DGA strings have observed maximum length 45 in both splits; whether this reflects source filtering or clipping remains unknown.

The [authors’ paper](https://sedici.unlp.edu.ar/bitstream/handle/10915/87859/Documento_completo.pdf-PDFA.pdf?isAllowed=y&sequence=1) reports totals of 1,180,178 Normal, 1,915,335 DGA and 8,000 Tunneling examples, matching the sums of the local per-class split counts. Its Section 4.2 describes a 70/30 split, but the distributed files are approximately 80/20. Table 3’s class support counts exactly match the supplied test file. The paper describes character tokenization but does not give an extraction recipe resolving this representation asymmetry. These inconsistencies prevent treating the publication as a complete reproduction specification.

**Root-cause boundary:** the anomaly is verified upstream in the release. The exact upstream code path, intent and recoverability of the discarded name context remain unresolved. There is no evidence here that permits blaming a specific parser or claiming an exact reconstruction.

## 4. Full-population distribution comparisons

Lengths count all characters, including dots and suffixes. Quantiles below use NumPy’s linear interpolation on every observed value. Shannon entropy is computed independently for each string as H = −Σ p(c) log₂ p(c), with case and punctuation preserved; it is empirical character entropy in bits. It is length-dependent and is not a measure of entropy rate, decoding success or maliciousness.

### Raw-string length

| Split/class | Mean ± population SD | Min–max | p01 / median / p95 / p99 |
| --- | --- | --- | --- |
| test/0 | 14.4025 ± 4.7826 | 4–45 | 6 / 14 / 23 / 29 |
| test/1 | 20.5080 ± 6.7464 | 8–45 | 10 / 20 / 31 / 37 |
| test/2 | 76.2187 ± 62.8525 | 29–253 | 29 / 57 / 246 / 252 |
| train/0 | 10.2933 ± 4.4092 | 1–45 | 3 / 10 / 18 / 23 |
| train/1 | 16.5808 ± 6.7071 | 3–45 | 6 / 15 / 27 / 34 |
| train/2 | 30.9247 ± 21.6909 | 3–65 | 6 / 34 / 64 / 65 |

### Raw-string Shannon entropy

| Split/class | Mean ± population SD | p01 / median / p95 / p99 |
| --- | --- | --- |
| test/0 | 3.2788 ± 0.3420 | 2.3219 / 3.3219 / 3.7842 / 3.9435 |
| test/1 | 3.6543 ± 0.3754 | 2.7500 / 3.6753 / 4.2603 / 4.4182 |
| test/2 | 4.3512 ± 0.4792 | 3.5633 / 4.3832 / 4.9608 / 5.8381 |
| train/0 | 2.8096 ± 0.5158 | 1.5000 / 2.9140 / 3.5069 / 3.7216 |
| train/1 | 3.3448 ± 0.4777 | 2.2359 / 3.3788 / 4.0850 / 4.2516 |
| train/2 | 3.4599 ± 0.8737 | 1.9183 / 3.5473 / 5.1204 / 5.2914 |

### Character distributions

Percentages in this table are character-weighted: character occurrences divided by all characters in the split/class. They differ from the percentage of rows containing a character.

| Split/class | Lowercase % | Uppercase % | Digits % | Dots % | Hyphens % | Underscores % |
| --- | --- | --- | --- | --- | --- | --- |
| test/0 | 90.27534 | 0.00000 | 0.93020 | 7.77883 | 1.01461 | 0.00103 |
| test/1 | 87.65617 | 0.00000 | 7.38665 | 4.95705 | 0.00013 | 0.00000 |
| test/2 | 71.95119 | 5.46097 | 18.63413 | 3.54555 | 0.20619 | 0.20198 |
| train/0 | 97.29906 | 0.00000 | 1.29097 | 0.00000 | 1.40885 | 0.00112 |
| train/1 | 90.86776 | 0.00000 | 9.13200 | 0.00000 | 0.00024 | 0.00000 |
| train/2 | 62.90502 | 4.99734 | 31.65684 | 0.00000 | 0.21889 | 0.22190 |

| Class | Train↔test character Jensen–Shannon divergence (bits) |
| --- | --- |
| 0 | 0.055082 |
| 1 | 0.033220 |
| 2 | 0.069478 |

Jensen–Shannon divergence uses the empirical case-sensitive character frequencies and base-2 logarithms; 0 means identical distributions, and its maximum is 1 bit. No significance test or population-generalization claim is implied. Suffixes, dots and length shifts change the inputs even though the class proportions are nearly equal across splits.

### Diagnostic leftmost-label comparison

This projection is a test of the representation hypothesis; it is not approved or implemented as model preprocessing. Since training strings have no dots, the training string is unchanged by the same projection.

| Class | Train raw mean length | Test raw mean length | Test leftmost mean length | Train raw mean H | Test raw mean H | Test leftmost mean H |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | 10.2933 | 14.4025 | 10.3020 | 2.8096 | 3.2788 | 2.8091 |
| 1 | 16.5808 | 20.5080 | 16.5765 | 3.3448 | 3.6543 | 3.3444 |
| 2 | 30.9247 | 76.2187 | 26.9711 | 3.4599 | 4.3512 | 3.1906 |

For benign and DGA examples, leftmost-label length p01/median/p95/p99 equals the training length quantiles exactly: 3/10/18/23 for benign, 6/15/27/34 for DGA. The similarity is strong evidence for a stem-level distribution mismatch. Tunneling does not align as closely: the projected test mean length is 26.9711 versus 30.9247 in training, and projected test mean H is 3.1906 versus 3.4599 in training.

## 5. Repeated strings and the 100 conflicting groups

| Split/class | Distinct feature+label records | Duplicate excess |
| --- | --- | --- |
| train/0 | 868,534 | 75572 |
| train/1 | 1,490,230 | 42033 |
| train/2 | 6,242 | 199 |
| test/0 | 236,072 | 0 |
| test/1 | 383,072 | 0 |
| test/2 | 1,552 | 7 |

The training split contains 117,804 repeated feature+label rows beyond the first occurrence; testing contains seven, all tunneling. Training has 2,364,906 distinct raw domain strings. Testing has 620,696. The exact raw-string and ASCII-lowercase/trailing-root-dot identity audits find no domain overlap across the supplied splits and no within-split case-variant groups. These results do not establish independence of the underlying names or generating processes.

Exactly 100 raw training strings carry conflicting labels, all between benign (0) and DGA (1). They cover 495 rows: 221 labeled benign and 274 labeled DGA. There are no class-2 conflicts in training and no raw-string conflicts in testing. Every conflicting group has both 0 and 1; Appendix A lists all 100 groups and their counts.

| Token | Benign rows | DGA rows | Interpretation boundary |
| --- | --- | --- | --- |
| ns1 | 1 | 174 | A highly repeated label can represent many parent names. |
| www | 112 | 1 | A subdomain token alone has lost parent context. |
| adeba | 2 | 1 | No parent-name or source evidence establishes the correct label. |
| caseking | 3 | 1 | Do not resolve by majority vote without lineage. |

These groups make a domain-string-only deterministic classifier incapable of reproducing every supplied training label: at least 100 of the 495 affected row labels would disagree with any single-label assignment per exact token. This is a descriptive inconsistency bound, not a trained-model result. The conflicts may reflect genuine stem collisions across distinct parent domains, DGA coincidence with legitimate names, source label problems, or a combination. Their cause cannot be adjudicated from the two-column CSV.

Recommendation: retain an audit list and quarantine entire ambiguous groups from any future supervised development partition until source records resolve them. Do not automatically select the majority class, remove only minority-labeled rows, or let different copies of a token cross folds. Any eventual exclusion policy must be documented and reflected in support counts. No rows were removed in this investigation.

## 6. Overlap hidden by representation differences

The following diagnostic projections were applied transiently to each test string and compared to unmodified training tokens. Casefold compares both sides under ASCII lowercase and trailing-dot removal. Other projections preserve case. “Remove final label” removes the final dot-separated component when present; “concatenate before final label” additionally removes remaining dots. These are string projections, not Public Suffix List parsing.

| Projection | Test class | Rows matching any train token | Rows with same-label train match | Rows with different-label train match |
| --- | --- | --- | --- | --- |
| raw | all | 0 | 0 | 0 |
| casefold | all | 0 | 0 | 0 |
| leftmost | 0 | 29,775 | 29,750 | 67 |
| leftmost | 1 | 17,440 | 17,415 | 61 |
| leftmost | 2 | 20 | 20 | 0 |
| remove_final_label | 0 | 22,270 | 22,248 | 40 |
| remove_final_label | 1 | 16,205 | 16,180 | 25 |
| concat_before_final_label | 0 | 22,403 | 22,379 | 43 |
| concat_before_final_label | 1 | 16,205 | 16,180 | 25 |

Unlisted classes for a projection have zero matching rows. Same-label and different-label columns may overlap when the matched training token is ambiguous. The leftmost projection yields 47,235 matching test rows (7.610% of testing), of which 47,185 have a same-label training match. Matching stems demonstrate exposure under that projected task; they do not prove that complete underlying FQDN records were copied.

| Test class | Distinct raw names | Distinct leftmost tokens |
| --- | --- | --- |
| 0 | 236,072 | 228,242 |
| 1 | 383,072 | 379,377 |
| 2 | 1,552 | 1,523 |

The leftmost projection also creates 18 conflicting token-label groups inside testing even though the original testing strings have none. Examples include numeric tokens `10`, `25`, `42` shared by benign and tunneling rows. Thus a superficially consistent projection can both expose leakage and introduce ambiguity.

## 7. Suffixes and generation artifacts

### Fixed laboratory names

| Test class | Rows under *.securitytesting.online | Rows under *.harpozedcompute.com |
| --- | --- | --- |
| 0 | 0 | 0 |
| 1 | 0 | 0 |
| 2 | 1,224 | 335 |

All 1,559 test tunneling rows fall under these two suffixes; neither occurs as a suffix in the benign or DGA test rows. The literal `securitytesting` label occurs in 1,514 tunneling rows and zero other test rows. This is a source-artifact association in the observed test file. The names alone provide a shortcut unrelated to demonstrating general tunneling detection. Because training has no suffixes, this is also a representation mismatch; it does not establish how a fitted model would behave.

Never add class-specific suffixes to training tokens, use these laboratory names as threat labels, or tune features to maximize their discrimination. If full names are later recovered and randomly split, keep controlled domains, tools, captures and payload sessions together; require tests with different controlled domains and tools. Avoid reading “last two labels” as a general registrable-domain rule: benign `co.uk` and dynamic DNS suffixes require a versioned public/private suffix policy.

### Repeated generation fragments and control labels

| Evidence | Observed count | Meaning and limit |
| --- | --- | --- |
| DGA leftmost ending `ticallyqozaw` | 12,310 train; 3,062 test | Repeated terminal 12-character fragment spans both splits; it may encode a generator family/template, but family or seed identity is not proved. |
| Train DGA ending `physicalohax` | 12,424 | Family/template-like repetition is substantial even without exact-name reuse. |
| Test DGA ending `bardinedazyx` | 3,146 | A lexical shortcut could survive a random row split. |
| Numeric first label in test tunneling | 75/1,559 | Each has later payload labels before the securitytesting marker. |
| Multiple labels before securitytesting in test tunneling | 334/1,559 | Payload/control structure extends beyond the first label. |
| Repeated full-name test tunnel rows | 7 excess rows | Exact repeats can overweight query-level metrics; keep supplied file intact and report both weighting views later. |

For example, `init.MRXHGRLYMZUWY5DSMF2G64ROMRWGY7BVHE.base64.securitytesting.online` occurs twice in testing. The `init` token occurs six times in training class 2. A first-label projection retains only a control marker and discards the encoded-looking payload and `base64` marker. No payload was decoded; the interpretation is based on visible string structure.

## 8. Can one consistent transformation solve this?

**No information-preserving transformation of the existing training tokens can recover their missing parent domains, dots, later payload labels or generation metadata.** Adding guessed suffixes cannot restore original observations. Syntax-only normalization cannot resolve the fundamental task-unit mismatch.

| Candidate approach | Assessment | Information / validity consequence |
| --- | --- | --- |
| Use raw strings identically at train and inference time | Reject for current three-class task | Training has no dots or suffixes; live full query names and the supplied test occupy a different representation. |
| Lowercase and remove a terminal root dot | Useful for identity grouping after validation; insufficient repair | Keep original case alongside any DNS identity key: mixed-case tunnel encodings occur. This does not restore missing structure. |
| Select first label for every query | Reject as universal three-class repair | Benign/DGA statistics align, but projected overlap and conflicts appear; later tunnel payload is lost, and 75 tunnel inputs reduce to numeric control tokens. |
| Strip only the final label or concatenate labels | Reject without extraction lineage | Multi-part public/private suffixes and lab control domains differ; boundaries can carry useful tunneling information and collapsing them creates collisions. |
| Use registrable label via a pinned public/private suffix list | Conditional DGA-specific design only | Needs confirmed training-token semantics; some names have subdomains/dynamic-DNS parents. It cannot support full-query tunneling detection alone. |
| Reconstruct/reacquire full query training records | Preferred route for three-class live detector | Preserves label boundaries and payload context and permits a single input contract. Requires parent/source records and compatible capture labels. |

A restricted label-level DGA research task may become defensible after confirming how labels were extracted, resolving ambiguous groups, auditing projected exposure, and defining matching inference input. That would be a separate, explicitly narrower task. It would not validate the current three-class detector or restore tunneling information.

## 9. Recommended preprocessing approach — specification only

1. Establish the prediction unit first: full plaintext DNS QNAME for joint tunneling/DGA detection, with a separately defined registrable-label view if needed for DGA. Obtain full-name training records or the original extraction pipeline with row-level source links. Do not reconstruct from or move any supplied test rows into training.
2. Preserve the raw QNAME and original case. Specify root-dot, escape decoding, ASCII/IDNA handling and invalid/overlength-name policy consistently for training and passive inference. Keep a separate canonical identity key for grouping; never silently truncate or discard payload labels. The DNS request can be observed passively without a response when plaintext is visible; encrypted DNS names require other visibility.
3. Parse label boundaries and public/private suffixes using a pinned, documented policy rather than hard-coded laboratory suffixes. Retain the complete payload/label structure for tunneling analysis. Keep source-specific suffix identities out of the first candidate feature set and require suffix-masked/held-out-source sensitivity evaluations in future work.
4. Resolve or quarantine conflicting groups and define duplicate weighting within training only. Keep all copies of an identity/source group in one partition. Fit any vocabulary, imputation, scaling or feature thresholds only inside the future training partition. Do not choose a representation based on supplied-test performance.
5. Candidate CPU-friendly diagnostics/features for later implementation include length, character composition, per-label entropy and bounded sparse character n-grams. Retain distinctions between full QNAME and label-level statistics, and validate live/offline parity with explicit examples. No such pipeline was implemented here.

## 10. Defensible train/validation/test strategy

**Current status:** keep the released test CSV and its checksum unchanged. It has now been inspected during EDA and this investigation; it can serve as a disclosed audit/reproduction benchmark, but cannot be the sole untouched confirmation set for a detector whose representation decisions were informed by this investigation.

**Once representation and label lineage are repaired:**

1. Build development partitions only from the original training side or newly acquired compatible development records, maintaining source traceability. Quarantine unresolved conflicting identities as complete groups. Keep the supplied test file separate throughout.
2. Use approximately 80/20 train/validation within eligible development data, with group-level class balancing where feasible. Exact canonical names, extracted stems/aliases and repeated payload/control records must remain together. Broaden groups using confirmed benign parent domains, DGA family/seed/generation date, and tunnel tool/session/capture/controlled domain when metadata is available. Allocate groups first; compute actual class support afterward. No grouping key should include the target label to split an otherwise identical input.
3. Acknowledge that these CSVs lack the metadata needed for verified family/session/time separation. Exact-token grouping is only a minimum internal evaluation, and repeated-fragment heuristics cannot certify family independence. If there are too few independent tunnel tools/sessions, acquire more rather than claiming that thousands of query rows are thousands of independent examples.
4. Add family-held-out DGA, tool/controlled-domain-held-out tunneling and forward-time evaluations once their identifiers exist. Use a newly acquired, source-independent full-QNAME final test set with benign traffic from the intended deployment environment. Freeze the input contract and development decisions before examining that final test.
5. Evaluate the preserved supplied test only as a separately labeled historical benchmark after freezing decisions. Disclose raw versus projected overlap and representation differences; report exposed and unexposed diagnostic strata without rewriting the file or tuning against the results. If its necessary representation cannot be justified, mark the benchmark incompatible rather than force a headline score.
6. Report per-class support, precision/recall, macro-F1, balanced accuracy, confusion matrices and benign false-positive rates. Any binary threat grouping can now use verified 0 versus {1,2}, but retain separate DGA/tunneling reporting. Use group-aware uncertainty estimates. Address imbalance only within training folds, and report row-weighted versus unique/group-weighted metrics when repeats matter. No evaluation or training was performed here.

## 11. Unresolved issues and conditions for a future GO

- Obtain the upstream preparation code and original parent records explaining the single-label training export, class-2 overlength tokens and observed 45-character benign/DGA maxima. Artifact provenance is verified; extraction semantics are not.
- Reconcile the publication’s stated split proportions with the released artifact counts and document the actual split mechanism and randomization/grouping rules.
- Identify the correct source/context for all 100 ambiguous training tokens. Document a reviewed inclusion/quarantine policy without majority-based relabeling.
- Recover source, family/seed, capture date, tool/session, controlled-domain and payload-generation metadata; quantify dependence beyond exact repeated strings and shared suffix fragments.
- Demonstrate an input contract that preserves full tunneling payload structure and can be computed identically from passive live requests and compatible offline records. A new source-independent final evaluation set is required for deployment claims.
- Clarify intended benign traffic, query-level versus session-level targets, domain parsing rules and handling of valid non-hostname DNS labels. The two-column files do not establish representativeness of production network traffic.

**Final recommendation: NO-GO for model training on the existing three-class split pair.** Confirmed labels and upstream identity remove provenance ambiguity but do not solve the representation and independence problems. A future GO requires compatible recoverable inputs, a documented conflict policy and defensible grouped evaluation. The supplied test remains preserved. This investigation stops at the report; no raw records, preprocessing or models were changed.

## Appendix A. Complete conflicting training domain-label groups

Counts are exact raw-string counts. All 100 groups contain class 0 and class 1 only; none contains class 2.

| Training token | Benign (0) | DGA (1) | Total rows |
| --- | --- | --- | --- |
| `ablenews` | 1 | 1 | 2 |
| `ableworld` | 1 | 1 | 2 |
| `adeba` | 2 | 1 | 3 |
| `afnic` | 1 | 1 | 2 |
| `akccs` | 1 | 1 | 2 |
| `amexio` | 1 | 1 | 2 |
| `annymo` | 1 | 1 | 2 |
| `artly` | 1 | 1 | 2 |
| `australiaonline` | 1 | 2 | 3 |
| `betterbridge` | 1 | 1 | 2 |
| `breadboard` | 1 | 1 | 2 |
| `caseking` | 3 | 1 | 4 |
| `cemba` | 1 | 1 | 2 |
| `championship` | 1 | 1 | 2 |
| `citep` | 1 | 1 | 2 |
| `ciweb` | 1 | 1 | 2 |
| `cloudmark` | 1 | 1 | 2 |
| `darkhorse` | 2 | 1 | 3 |
| `darkmoon` | 2 | 1 | 3 |
| `dreamworld` | 1 | 1 | 2 |
| `feltmark` | 1 | 1 | 2 |
| `flyto` | 1 | 1 | 2 |
| `foton` | 1 | 1 | 2 |
| `fotor` | 2 | 1 | 3 |
| `fotos` | 1 | 1 | 2 |
| `galek` | 1 | 1 | 2 |
| `galik` | 1 | 1 | 2 |
| `ganaf` | 1 | 1 | 2 |
| `gazel` | 1 | 1 | 2 |
| `grewe` | 1 | 1 | 2 |
| `groupdeal` | 1 | 1 | 2 |
| `grouphunt` | 1 | 1 | 2 |
| `hfpwp` | 1 | 1 | 2 |
| `hillstate` | 1 | 1 | 2 |
| `hulic` | 1 | 1 | 2 |
| `huppe` | 1 | 1 | 2 |
| `imppc` | 1 | 1 | 2 |
| `iqsim` | 1 | 1 | 2 |
| `ixina` | 1 | 1 | 2 |
| `jinakava` | 1 | 1 | 2 |
| `jumphouse` | 1 | 1 | 2 |
| `jumpshot` | 1 | 1 | 2 |
| `knowhouse` | 1 | 1 | 2 |
| `littleflower` | 1 | 1 | 2 |
| `looklive` | 1 | 1 | 2 |
| `lymil` | 1 | 1 | 2 |
| `lyrix` | 1 | 1 | 2 |
| `lyryx` | 1 | 1 | 2 |
| `lysol` | 1 | 1 | 2 |
| `lyson` | 2 | 1 | 3 |
| `makes` | 2 | 1 | 3 |
| `mamavit` | 1 | 1 | 2 |
| `mamet` | 1 | 1 | 2 |
| `mamon` | 1 | 1 | 2 |
| `mamul` | 1 | 1 | 2 |
| `marum` | 1 | 1 | 2 |
| `maxus` | 1 | 1 | 2 |
| `milkbone` | 1 | 1 | 2 |
| `mingmen` | 1 | 1 | 2 |
| `momoth` | 1 | 1 | 2 |
| `musicworld` | 1 | 1 | 2 |
| `navad` | 2 | 1 | 3 |
| `novacom` | 1 | 1 | 2 |
| `novus` | 1 | 1 | 2 |
| `ns1` | 1 | 174 | 175 |
| `oawio` | 1 | 1 | 2 |
| `offerworld` | 1 | 1 | 2 |
| `ordercircle` | 1 | 1 | 2 |
| `pkusz` | 1 | 1 | 2 |
| `purax` | 1 | 1 | 2 |
| `purex` | 1 | 1 | 2 |
| `purob` | 1 | 1 | 2 |
| `purum` | 1 | 1 | 2 |
| `puvap` | 1 | 1 | 2 |
| `puzat` | 1 | 1 | 2 |
| `quickmark` | 1 | 1 | 2 |
| `quickshirt` | 1 | 1 | 2 |
| `resea` | 1 | 1 | 2 |
| `shipt` | 1 | 1 | 2 |
| `sigov` | 1 | 1 | 2 |
| `sivoj` | 1 | 1 | 2 |
| `songtaste` | 1 | 1 | 2 |
| `spotdeal` | 1 | 1 | 2 |
| `sshmp` | 1 | 1 | 2 |
| `sundayworld` | 2 | 1 | 3 |
| `symama` | 1 | 1 | 2 |
| `thinkwritten` | 1 | 1 | 2 |
| `unina` | 1 | 1 | 2 |
| `uponunder` | 1 | 1 | 2 |
| `vocab` | 1 | 1 | 2 |
| `volim` | 1 | 1 | 2 |
| `wiego` | 1 | 1 | 2 |
| `withinspace` | 1 | 1 | 2 |
| `withnews` | 1 | 1 | 2 |
| `wpsite` | 1 | 1 | 2 |
| `www` | 112 | 1 | 113 |
| `wwwomen` | 1 | 1 | 2 |
| `yasiv` | 1 | 1 | 2 |
| `yeswe` | 1 | 1 | 2 |
| `zukov` | 1 | 1 | 2 |
