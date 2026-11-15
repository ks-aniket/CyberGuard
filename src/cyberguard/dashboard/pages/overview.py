import streamlit as st

from cyberguard.dashboard.components import visuals
from cyberguard.dashboard.components.metrics import capabilities, summary
from cyberguard.dashboard.ui import report_or_warning


def render(client, connection, report, report_error):
    if connection.selected is not None:
        from cyberguard.dashboard.pages import registry_overview

        registry_overview.render(connection)
        if (
            report is not None
            and connection.selected.input_contract_version == "bot-iot-header-v1"
        ):
            visuals.section("Offline validation snapshot", "03")
            summary(report, overview=True)
            st.caption(
                f"{report.total:,} historical validation rows, including repetitions; only {int(report.per_class.loc['Normal', 'support']):,} Normal rows. Independent-session generalization is not established."
            )
            with st.expander("Per-class recall & validation support"):
                st.dataframe(
                    report.per_class[["recall", "support"]].rename_axis("Class"),
                    width="stretch",
                )
        return
    visuals.heading(
        "Network Intelligence Console",
        "Experimental ML-powered network traffic classification. A focused workspace for testing, inspection and evidence.",
        "RESTRICTED MODEL / OFFLINE ANALYSIS",
    )
    with st.container(key="layout_overview_status"):
        left, right = st.columns(2)
    left.metric(
        "API connectivity",
        "Connected" if connection.live else "Disconnected",
        help="Snapshot from the last connection check or failed request; no live polling.",
    )
    right.metric(
        "Model readiness", "Ready" if connection.ready else "Unavailable / unverified"
    )
    with st.container(key="layout_overview_panels"):
        model_column, boundary_column = st.columns([1.7, 1])
    with model_column, st.container(key="panel_overview_model"):
        visuals.section("Model intelligence", "01")
        if connection.info:
            info = connection.info
            visuals.metadata(
                [
                    ("Model identifier", info.model),
                    ("Architecture", info.model_type),
                    ("Input features", ", ".join(info.required_features)),
                    (
                        "Preprocessing",
                        info.preprocessing_contract_version or "Not reported",
                    ),
                    (
                        "Probabilities",
                        "Available · uncalibrated"
                        if info.probabilities_available
                        else "Unavailable",
                    ),
                    ("Mode", "Header-only classification"),
                ]
            )
            visuals.chips(info.supported_classes)
            if report:
                if info.artifact_sha256 == report.model_sha256:
                    st.caption(
                        ":material/verified: Artifact SHA-256 matches historical validation."
                    )
                else:
                    st.warning(
                        "Loaded artifact cannot be matched to historical validation. Saved scores describe the historical artifact only."
                    )
        else:
            visuals.empty_state(
                "Model metadata unavailable",
                connection.error
                or "Connect the API and refresh to inspect the loaded model.",
            )
    with boundary_column, st.container(key="panel_overview_limits"):
        visuals.section("Know the boundary", "02")
        visuals.banner(
            "EXPERIMENTAL CLASSIFICATION",
            connection.info.warning
            if connection.info
            else "Header-only predictions use protocol and ports. Probabilities are uncalibrated. Normal does not establish safety. Theft and unknown attacks are unsupported. No live packet-level detection is performed.",
        )
        st.caption(
            "A DDoS prediction does not prove that a DDoS attack occurred. Review historical evidence before drawing conclusions."
        )
        visuals.metadata(
            [("Live capture", "Not implemented"), ("DNS model", "NO-GO · unsupported")]
        )
    visuals.section("Offline validation snapshot", "03")
    if report_or_warning(report, report_error):
        summary(report, overview=True)
        st.caption(
            f"{report.total:,} recorded rows · {int(report.per_class.loc['Normal', 'support']):,} Normal rows · deterministic group-aware partition of the training file. Independent-session generalization is not established; the official test remains reserved."
        )
        with st.expander("Per-class recall & validation support"):
            st.dataframe(
                report.per_class[["recall", "support"]].rename_axis("Class"),
                width="stretch",
            )
            st.caption(
                f"{report.total:,} recorded validation rows, including repetitions. Normal support is only {int(report.per_class.loc['Normal', 'support']):,}; this is not independent-session evidence."
            )
    visuals.section("Capability map", "04")
    capabilities()
