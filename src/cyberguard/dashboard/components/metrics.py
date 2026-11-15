import streamlit as st

HISTORICAL = "Historical offline validation — not live detection performance."


def summary(report):
    st.caption(HISTORICAL)
    columns = st.columns(4)
    for column, label, value in zip(
        columns,
        [
            "Macro-F1",
            "Balanced accuracy",
            "Benign false-positive rate",
            "Validation records",
        ],
        [
            f"{report.evaluation['macro_f1']:.2%}",
            f"{report.evaluation['balanced_accuracy']:.2%}",
            f"{report.evaluation['benign_false_positive_rate']:.2%}",
            f"{report.total:,}",
        ],
    ):
        column.metric(label, value)


def methodology(report):
    normal = int(report.per_class.loc["Normal", "support"])
    st.warning(
        f"Internal validation from the original BoT-IoT training file uses a deterministic group-aware partition. Only {normal:,} Normal records are present. Extreme imbalance and related capture records limit the evidence; these results do not establish independent-session generalization. The official test split remains reserved. Predictions are not evidence of live attack detection."
    )


def capabilities():
    for column, heading, text in zip(
        st.columns(3),
        ["Implemented", "Planned", "Unsupported"],
        [
            "HTTP model serving · interactive and CSV testing · historical validation charts",
            "Packet/flow ingestion · causal streaming replay · alert storage and operational evaluation",
            "Live attack detection · DNS classification · Theft / unknown attack identification · safety guarantees",
        ],
    ):
        with column:
            st.subheader(heading)
            st.write(text)
