import streamlit as st

from cyberguard.dashboard.components.metrics import capabilities, summary
from cyberguard.dashboard.ui import report_or_warning


def render(client, connection, report, report_error):
    st.title("CyberGuard")
    st.write("Network classification workspace")
    st.caption(
        "Experimental, header-only inference · offline testing · no live monitoring"
    )
    st.subheader("System status")
    left, right = st.columns(2)
    left.metric("API connectivity", "Connected" if connection.live else "Disconnected")
    right.metric(
        "Model readiness", "Ready" if connection.ready else "Unavailable / unverified"
    )
    if connection.error:
        st.error(connection.error)
    if connection.info:
        info = connection.info
        with st.container(border=True):
            st.subheader("Loaded model")
            st.write(f"**Identifier:** {info.model}")
            st.write(f"**Type:** {info.model_type}")
            st.write("**Classes:** " + " · ".join(info.supported_classes))
            st.write("**Required inputs:** " + ", ".join(info.required_features))
            st.write(
                "**Class probabilities:** "
                + (
                    "Available — uncalibrated"
                    if info.probabilities_available
                    else "Unavailable"
                )
            )
            st.caption(
                f"Preprocessing contract: {info.preprocessing_contract_version or 'Not reported'}"
            )
            st.warning(info.warning)
            if report:
                if info.artifact_sha256 == report.model_sha256:
                    st.caption(
                        "Loaded artifact SHA-256 matches the historical validation model."
                    )
                else:
                    st.warning(
                        "Loaded artifact cannot be matched to the historical validation model. The scores below describe the saved historical artifact only."
                    )
    st.subheader("Historical validation")
    if report_or_warning(report, report_error):
        summary(report)
        st.dataframe(
            report.per_class[["recall", "support"]].rename_axis("Class"),
            width="stretch",
        )
        st.caption(
            "Recall is per-class coverage; support counts recorded validation rows, including repetitions."
        )
    st.subheader("Capabilities and boundaries")
    capabilities()
