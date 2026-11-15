"""Count-weighted validation metrics with an explicit benign denominator."""

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, f1_score

from cyberguard.features.network import TARGETS


def evaluate_predictions(y, predictions, weights):
    matrix = confusion_matrix(
        y, predictions, labels=list(TARGETS), sample_weight=weights
    )
    normal_total = float(matrix[0].sum())
    if normal_total == 0:
        raise ValueError("Validation has no Normal support; benign FPR is undefined")
    false_alarms = float(matrix[0, 1:].sum())
    return {
        "class_order": list(TARGETS),
        "macro_f1": float(
            f1_score(
                y,
                predictions,
                labels=list(TARGETS),
                average="macro",
                sample_weight=weights,
                zero_division=0,
            )
        ),
        "per_class": classification_report(
            y,
            predictions,
            labels=list(TARGETS),
            output_dict=True,
            sample_weight=weights,
            zero_division=0,
        ),
        "confusion_matrix": matrix.tolist(),
        "benign_false_positive_rate": false_alarms / normal_total,
        "benign_false_positives": false_alarms,
        "benign_support": normal_total,
        "balanced_accuracy": float(
            np.mean([matrix[i, i] / matrix[i].sum() for i in range(len(TARGETS))])
        ),
    }


def write_validation_report(result, root):
    """Render the actual recorded run; no metric values are hard-coded."""
    from datetime import datetime
    from zoneinfo import ZoneInfo

    def table(headers, rows):
        return "\n".join(
            [
                "| " + " | ".join(headers) + " |",
                "| " + " | ".join(["---"] * len(headers)) + " |",
            ]
            + ["| " + " | ".join(map(str, row)) + " |" for row in rows]
        )

    r = result
    evaluation = r["evaluation"]
    train = r["split_counts"]["train"]
    validation = r["split_counts"]["validation"]
    normal_rate = (
        100 * r["raw_class_counts"]["Normal"] / sum(r["raw_class_counts"].values())
    )
    lines = [
        "# BoT-IoT restricted network baseline validation",
        "",
        f"Generated {datetime.now(ZoneInfo('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M %Z')}. Offline flow-record experiment; no live packet-level detection claim.",
        "",
        "## Outcome",
        "",
        f"Validation macro-F1: **{evaluation['macro_f1']:.6f}**; balanced accuracy / mean class recall: **{evaluation['balanced_accuracy']:.6f}**. Benign false-positive rate: **{100 * evaluation['benign_false_positive_rate']:.3f}%**, comprising {evaluation['benign_false_positives']:g} false alarms among {evaluation['benign_support']:g} Normal records.",
        "",
        "These are internal training-file validation results. They do not establish production performance, independent-session generalization or live capture compatibility. No supplied-test results were computed. DNS remains outside this experiment.",
        "",
        "## Scope, inputs and target policy",
        "",
        f"Input: `{r['source']}`; SHA-256 `{r['source_sha256']}`. Read only proto, sport, dport and category in 50,000-row chunks. The supplied BoT-IoT test file and DNS files were never opened by the training runner. Input SHA-256 was verified unchanged after the run.",
        "",
        f"The supervised targets are {', '.join(TARGETS)}. All {r['raw_class_counts'].get('Theft', 0)} Theft records are explicitly excluded from fitting and four-class validation. Theft is an unsupported malicious category and is never relabeled Normal. This closed-set classifier always returns one of the four supported labels; it cannot certify traffic as safe or identify unsupported attacks. All excluded raw records are preserved.",
        "",
        f"The raw training file contains only {r['raw_class_counts']['Normal']:,} Normal examples ({normal_rate:.6f}% of all rows). These are scarce recorded examples, not independent captures. No benign examples were fabricated, synthesized or oversampled.",
        "",
        table(
            [
                "Target",
                "Original training-file rows",
                "Fit rows",
                "Validation rows",
                "Fit distinct input groups",
                "Validation distinct input groups",
            ],
            [
                (
                    label,
                    f"{r['raw_class_counts'][label]:,}",
                    f"{train[label]:,}",
                    f"{validation[label]:,}",
                    r["class_unique_groups"]["train"][label],
                    r["class_unique_groups"]["validation"][label],
                )
                for label in TARGETS
            ],
        ),
        "",
        "## Reproducible preprocessing contract",
        "",
        f"Version `{r['preprocessing_version']}`. The reusable sklearn Pipeline accepts a pandas DataFrame requiring proto/sport/dport. Extra columns, including every target, IP and identifier, are ignored by an explicit allowlist. Missing required columns or duplicate column names fail. Unknown target categories fail instead of silently collapsing.",
        "",
        "Protocol tokens are stripped/lowercased; TCP/6, UDP/17, ICMP/1/icmpv4, IPv6-ICMP/58/icmpv6 and ARP are normalized. Empty/NA tokens become missing; unsupported protocols become other. Protocol aliases are a fixed contract, not learned from targets.",
        "",
        "TCP/UDP ports accept nonnegative decimal integers (including leading zeroes), hexadecimal 0x tokens, and integer-valued numeric scalars. Port 0 is valid; 65535 is the maximum. Blank/NA, -/-1 sentinel, and malformed/out-of-range/negative/nonfinite inputs have distinct missing/sentinel/invalid statuses. Non-TCP/UDP protocols have not_applicable ports, so ICMP hex type/code and ARP -1 tokens never masquerade as TCP/UDP port numbers. Unknown transports also receive not_applicable; no port semantics are guessed.",
        "",
        "Each transport port produces a fixed value in [0,1] (port/65535, zero when unavailable), a status and a fixed well_known (0–1023), registered (1024–49151), dynamic (49152–65535) or none range. Status distinguishes valid zero from unavailable zero. Numeric values have no learned scale or imputation. Protocol, statuses and ranges are one-hot encoded using training partitions only, with handle_unknown=ignore. Unknown categories remain safe all-zero encoded categories while the numeric contract stays fixed.",
        "",
        "[Feature availability and leakage audit](bot_iot_feature_audit.md) documents every source field and residual exporter/scenario risks. The model uses no historical counts, rates, completed-flow duration summaries, state, addresses or sequence identifiers.",
        "",
        "## Validation boundary and duplicate policy",
        "",
        f"A label-independent SHA-256 of seed {r['split_seed']} and the complete canonical retained input vector assigns each group to validation when its first 64 bits are below 2^64//5 (nominal 20%). Other groups go to fitting. Assignment is deterministic across chunk sizes, row order and port spelling aliases. The seed was fixed before fitting; no seed search, hyperparameter search, stratification retry or test-based selection was performed.",
        "",
        f"There are {r['vector_groups']:,} normalized input groups: {r['split_unique_groups']['train']:,} fit and {r['split_unique_groups']['validation']:,} validation. Exact cross-partition input-group overlap is **{r['cross_partition_shared_groups']}**, verified before fitting. This grouping is stricter than the prior full operational-vector duplicate check: identical operational rows necessarily map to one retained input group, even when raw IPs/flow summaries differ. It does not establish host, session, campaign or temporal independence.",
        "",
        f"The compact index retains {r['feature_label_records']:,} distinct (input vector, target) records and their exact multiplicities, representing {sum(train.values()) + sum(validation.values()):,} eligible original rows. Duplicate excess under this restricted view is {r['duplicate_feature_label_excess']:,}. No repeated row is discarded from the weighting or evaluation denominators. Group assignment precedes fitting and applies without using its label.",
        "",
        f"There are {r['conflicting_feature_vector_groups']:,} groups with more than one supported target, covering {r['rows_in_conflicting_groups']:,} rows. Removing context makes these inputs indistinguishable; this is not proof of source annotation errors. Every conflicting group remains entirely on one side, and each label/count is retained. No majority-vote relabeling is applied.",
        "",
        "Full groups with few protocols (e.g. all ICMP or ARP observations after port removal) can be large and label-mixed, causing split proportions and rare-class coverage to differ from 80/20. The runner fails if any supported class is absent on either side. It does not silently change the partition. The manifest records every group/target/count/partition for audit.",
        "",
        "## Fixed CPU baseline and training weights",
        "",
        f"Decision tree: max_depth=6, max_leaf_nodes=32, min_samples_leaf=5, random_state={r['split_seed']}; all other parameters are recorded in JSON. Actual fitted depth {r['classifier_depth']}, leaves {r['classifier_leaves']}. No tuning was performed. This simple model is intended to expose what the restricted inputs can and cannot distinguish.",
        "",
        "Train-only inverse-frequency weights are N_train/(4×class_count). A compact record’s sample weight is its original multiplicity times its class weight, preserving original class mass in the weighted impurity calculation. min_samples_leaf=5 refers to compact feature-label records, not five independent raw observations. Validation metrics use original multiplicities without class balancing.",
        "",
        table(
            ["Class", "Train-only class weight"],
            [
                (label, f"{weight:.6f}")
                for label, weight in r["class_weights_train_only"].items()
            ],
        ),
        "",
        "## Validation results",
        "",
        table(
            ["Class", "Precision", "Recall", "F1", "Row support"],
            [
                (
                    label,
                    *[
                        f"{evaluation['per_class'][label][metric]:.6f}"
                        for metric in ["precision", "recall", "f1-score"]
                    ],
                    f"{evaluation['per_class'][label]['support']:g}",
                )
                for label in TARGETS
            ],
        ),
        "",
        "Confusion matrix: rows are actual classes; columns are predictions. These counts include all repeated eligible validation records through multiplicity weighting.",
        "",
        table(
            ["Actual / predicted", *TARGETS],
            [
                (label, *[f"{value:g}" for value in row])
                for label, row in zip(
                    TARGETS, evaluation["confusion_matrix"], strict=True
                )
            ],
        ),
        "",
        f"The train-majority reference rule has macro-F1 {r['majority_reference']['macro_f1']:.6f} and benign FPR {100 * r['majority_reference']['benign_false_positive_rate']:.3f}%. It uses only training class counts and serves as a descriptive reference, not a selected alternative model.",
        "",
        f"A secondary diagnostic gives each retained input vector total weight 1, distributing that weight among its label counts. Its macro-F1 is {r['equal_vector_weight_evaluation']['macro_f1']:.6f}, balanced accuracy {r['equal_vector_weight_evaluation']['balanced_accuracy']:.6f}, and benign FPR {100 * r['equal_vector_weight_evaluation']['benign_false_positive_rate']:.3f}%. This differs from row-weighted results because duplicate frequency can dominate them. It is not a session-independent evaluation.",
        "",
        f"Benign FPR denominator is exactly the {validation['Normal']} held-out Normal rows across {r['class_unique_groups']['validation']['Normal']} distinct input groups, not all validation traffic. A small benign set with repeated/related capture records cannot establish a reliable deployment false-alarm budget. Ordinary independent-row confidence intervals would overstate the evidence; no such confidence claim is made.",
        "",
        "## Encoded features and fitted tree importances",
        "",
        table(
            ["Encoded feature", "Impurity importance"],
            [
                (name, f"{value:.6f}")
                for name, value in sorted(
                    r["feature_importances"].items(), key=lambda item: -item[1]
                )
            ],
        ),
        "",
        "Importances describe this fitted tree only. Protocol/service or missingness may encode testbed scenarios and exporter behavior. A feature being obtainable from a header does not demonstrate robust intrusion detection. DoS versus DDoS often requires causal multi-source/time-window evidence that this deliberately restricted representation excludes.",
        "",
        "## Validation and integrity checks",
        "",
        "Before the raw-data fit, targeted unit tests covered protocol aliases, missing/sentinel/invalid/hex ports, nontransport semantics, exclusion invariance for labels/IPs/aggregates, required schema, target/Theft policy, exact key round trips, train-only encoding, serialization, duplicate-group/chunk invariance, conflicting groups and weighted metrics against expanded count fixtures. Synthetic fixtures are software tests only; they are not generalization evidence.",
        "",
        "The real run checked class support, canonical reconstruction, disjoint group assignments, unchanged raw SHA-256, and exact equality of saved/reloaded model predictions on validation. Full hyperparameters, dependency versions, code hashes, normalization counts and metrics are in the JSON artifact.",
        "",
        "## Artifacts and rerun",
        "",
        f"- Model including fitted preprocessing: `{r['model_path']}` ({r['model_bytes']:,} bytes); SHA-256 `{r['model_sha256']}`.",
        f"- Group manifest: `{r['manifest_path']}`; SHA-256 `{r['manifest_sha256']}`.",
        "- [Machine-readable run metrics](bot_iot_validation_metrics.json).",
        "- [Confusion counts CSV](bot_iot_validation_confusion.csv).",
        "- [Feature audit](bot_iot_feature_audit.md).",
        "",
        "Run `.venv/bin/pytest -q tests/unit/test_preprocessing.py tests/unit/test_network_training.py` before `.venv/bin/python scripts/train_network_baseline.py`. Load the pipeline with `PYTHONPATH=src` or with the cyberguard package on the Python import path. Its only required predictor inputs are proto/sport/dport. Artifacts remain local under the repository’s model/data ignore policy; source and reports are reviewable.",
        "",
        f"Environment: Python {r['python']}, sklearn {r['sklearn']}, NumPy {r['numpy']}, pandas {r['pandas']}. Full run {r['wall_seconds']:.1f}s; tree fitting {r['fit_seconds']:.2f}s; peak RSS {r['peak_rss_mib']:.1f} MiB. No GPU or worker pool was used. The baseline stores only a bounded CSV chunk during ingestion and a compact normalized group index for fitting, rather than an expanded full raw table.",
        "",
        "## Recommendations and status",
        "",
        "1. Treat this result as a reproducible offline diagnostic baseline. Any poor class recall or large benign FPR is an outcome to report, not a reason to reintroduce suspect aggregates or silently tune the held-out partition. Do not deploy it as a safety decision.",
        "2. Collect more real benign traffic across independent devices, environments and periods, plus representative attacks and benign high-rate services. Preserve source/session/time metadata. Additional synthetic or repeated benign rows cannot solve the independent-evidence shortage.",
        "3. Obtain packet/flow-export configuration and build explicitly past-only windows with bounded state. Verify packet/flow orientation, missingness, timeout behavior and feature parity. Add causal source counts or rate features only after their time boundaries and forward evaluation are established; never use capture-wide or future counts.",
        "4. Add host/capture/session/time-held-out evaluations and group-aware uncertainty estimates with enough independent benign groups. Assess exporter/missingness and service-port sensitivity on new data. The supplied test remains untouched for a later explicitly authorized frozen evaluation, with the earlier EDA overlap caveats disclosed.",
        "5. Expand Theft handling with sufficient independently sourced examples or a separately validated unsupported/abstention mechanism. Four-class Normal predictions provide no assurance against Theft or other unseen threats. DNS remains NO-GO under its separate investigation.",
        "",
    ]
    (root / "reports/model_evaluation/bot_iot_validation.md").write_text(
        "\n".join(lines)
    )
