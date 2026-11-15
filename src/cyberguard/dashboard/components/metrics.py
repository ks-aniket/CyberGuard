import streamlit as st

from cyberguard.dashboard.components import visuals

HISTORICAL = "Historical offline validation — not live detection performance."


def summary(report, *, overview=False):
    st.caption(HISTORICAL)
    labels = [
        "Macro-F1",
        "Balanced accuracy",
        "Benign FPR",
        "Supported classes" if overview else "Validation records",
    ]
    values = [
        f"{report.evaluation['macro_f1']:.2%}",
        f"{report.evaluation['balanced_accuracy']:.2%}",
        f"{report.evaluation['benign_false_positive_rate']:.2%}",
        str(len(report.per_class)) if overview else f"{report.total:,}",
    ]
    with st.container(key="metric_row_summary"):
        columns = st.columns(4)
    for index, (column, label, value, tone) in enumerate(
        zip(columns, labels, values, ["cyan", "blue", "warning", "purple"])
    ):
        with column:
            visuals.metric_card(label, value, key=f"summary_{index}", tone=tone)


def methodology(report):
    normal = int(report.per_class.loc["Normal", "support"])
    visuals.banner(
        "EVIDENCE BOUNDARY / INTERNAL VALIDATION",
        f"Results come from the original BoT-IoT training file using a deterministic group-aware partition. Only {normal:,} Normal records are present. Extreme imbalance and related capture records limit the evidence; independent-session generalization is not established. The official test split remains reserved. Predictions are not evidence of live attack detection.",
    )


def capabilities():
    for column, label, title, description in zip(
        st.columns(3),
        ["AVAILABLE NOW", "ROADMAP", "OUT OF SCOPE"],
        ["Offline intelligence", "Operational context", "No safety guarantees"],
        [
            "HTTP inference, interactive & CSV testing, historical validation charts.",
            "Causal streaming replay, packet/flow ingestion and alert persistence remain planned.",
            "Live attack detection, DNS classification, Theft and unknown attack identification are unsupported.",
        ],
    ):
        with column:
            visuals.capability(label, title, description)
