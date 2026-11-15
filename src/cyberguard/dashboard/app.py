"""Run with: uv run streamlit run src/cyberguard/dashboard/app.py."""

import sys
from datetime import UTC, datetime
from pathlib import Path

# Streamlit executes a file rather than an installed package under this src layout.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from cyberguard.dashboard.api_client import APIClient, APIError, Connection
from cyberguard.dashboard.pages import (
    about,
    batch_testing,
    model_performance,
    overview,
    test_lab,
)
from cyberguard.dashboard.report_loader import ReportError, load_validation

st.set_page_config(
    page_title="CyberGuard | Network classification", page_icon="🛡️", layout="wide"
)


def main():
    try:
        client = APIClient()
    except APIError as exc:
        client = None
        st.session_state.connection = Connection(error=str(exc))
    with st.sidebar:
        st.title("CyberGuard")
        st.caption("Network classification workspace")
        refresh = st.button("Refresh connection", width="stretch")
        if client and (refresh or "connection" not in st.session_state):
            with st.spinner("Checking API and model…"):
                st.session_state.connection = client.check_connection()
                st.session_state.checked_at = datetime.now(UTC).strftime("%H:%M:%S UTC")
            # Do not reuse results across an explicit connection/model refresh.
            st.session_state.pop("single_result", None)
            st.session_state.pop("batch_result", None)
        connection = st.session_state.connection
        if connection.ready:
            st.success("API connected · model ready")
        else:
            st.error("Backend unavailable / unverified")
            st.caption(connection.error)
        if client:
            st.caption(f"API: {client.base_url}")
        st.caption("Last check: " + st.session_state.get("checked_at", "Not checked"))
        st.caption(
            "Status is checked on first visit or refresh, not on every interaction. Prediction failures block further submissions until refreshed."
        )
    try:
        report = load_validation()
        report_error = None
    except ReportError as exc:
        report, report_error = None, str(exc)

    def page(module):
        return lambda: module.render(client, connection, report, report_error)

    navigation = st.navigation(
        [
            st.Page(
                page(overview), title="Overview", url_path="overview", default=True
            ),
            st.Page(
                page(test_lab), title="Interactive Testing", url_path="interactive"
            ),
            st.Page(page(batch_testing), title="Batch Testing", url_path="batch"),
            st.Page(
                page(model_performance),
                title="Model Performance",
                url_path="performance",
            ),
            st.Page(page(about), title="About CyberGuard", url_path="about"),
        ]
    )
    navigation.run()


if __name__ == "__main__":
    main()
