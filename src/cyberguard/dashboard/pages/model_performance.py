import streamlit as st

from cyberguard.dashboard.components import charts, visuals
from cyberguard.dashboard.components.metrics import methodology, summary
from cyberguard.dashboard.ui import report_or_warning


def render(client, connection, report, report_error):
    if (
        connection.selected is not None
        and connection.selected.input_contract_version
        == "nf-cse-netflow-v1-completed-flow-v1"
    ):
        from cyberguard.dashboard.pages import final_performance

        return final_performance.render(connection, report, report_error)
    if (
        connection.selected is not None
        and connection.selected.input_contract_version != "bot-iot-header-v1"
    ):
        visuals.heading(
            "Model Performance", "Performance metadata for the selected contract."
        )
        if connection.selected.performance_metadata:
            st.json(connection.selected.performance_metadata)
        else:
            st.info("No matched performance metadata is available for this model.")
        return
    visuals.heading(
        "Model Performance",
        "Saved evidence, clearly bounded. Historical report artifacts remain available independently of the inference API.",
        "EVIDENCE EXPLORER / INTERNAL VALIDATION",
    )
    if not report_or_warning(report, report_error):
        return
    summary(report)
    methodology(report)
    with st.container(key="layout_performance"):
        performance, support = st.columns([1.15, 1], gap="medium")
    with performance, st.container(key="panel_performance_scores"):
        visuals.section("Per-class performance", "01")
        st.caption("Equal visibility for each class · precision / recall / F1")
        st.plotly_chart(
            charts.class_performance(report),
            width="stretch",
            config={"displaylogo": False},
        )
    with support, st.container(key="panel_performance_support"):
        visuals.section("Validation class support", "02")
        st.caption("Logarithmic count axis · recorded rows, including repetitions")
        st.plotly_chart(
            charts.support(report), width="stretch", config={"displaylogo": False}
        )
        st.caption(
            "The scarce Normal class remains visible. Rows are not independent sessions."
        )
    with st.container(key="panel_performance_confusion"):
        visuals.section("Confusion matrix", "03")
        normalized = st.checkbox("Show row-normalized percentages")
        st.plotly_chart(
            charts.confusion(report, normalized),
            width="stretch",
            config={
                "displaylogo": False,
                "modeBarButtonsToRemove": ["select2d", "lasso2d"],
            },
        )
        st.caption(
            "Rows = actual classes; columns = predictions. Exact record counts remain available on hover in either view."
        )
    with st.expander("Inspect exact metrics & confusion counts"):
        st.dataframe(report.per_class.rename_axis("Class"), width="stretch")
        st.dataframe(
            report.confusion.rename_axis("Actual / predicted"), width="stretch"
        )
    st.caption(
        "Source: reports/model_evaluation/bot_iot_validation_metrics.json and bot_iot_validation_confusion.csv. No inference or official-test evaluation is performed by this page."
    )
