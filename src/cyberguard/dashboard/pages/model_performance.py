import streamlit as st

from cyberguard.dashboard.components import charts
from cyberguard.dashboard.components.metrics import methodology, summary
from cyberguard.dashboard.ui import report_or_warning


def render(client, connection, report, report_error):
    st.title("Model Performance")
    st.write("Saved validation evidence · available independently of the inference API")
    if not report_or_warning(report, report_error):
        return
    summary(report)
    methodology(report)
    st.subheader("Per-class performance")
    st.plotly_chart(charts.class_performance(report), width="stretch")
    st.dataframe(report.per_class.rename_axis("Class"), width="stretch")
    st.subheader("Confusion matrix")
    normalized = st.checkbox("Show row-normalized percentages")
    st.plotly_chart(charts.confusion(report, normalized), width="stretch")
    st.caption(
        "Rows = actual classes; columns = predictions. Hover shows exact record counts in either view."
    )
    st.dataframe(report.confusion.rename_axis("Actual / predicted"), width="stretch")
    st.subheader("Validation class support")
    st.plotly_chart(charts.support(report), width="stretch")
    st.caption(
        "The logarithmic count axis keeps the scarce Normal class visible. Supports are recorded rows, including duplicates, not independent sessions."
    )
    st.caption(
        "Source: reports/model_evaluation/bot_iot_validation_metrics.json and bot_iot_validation_confusion.csv. No inference or official-test evaluation is performed by this page."
    )
