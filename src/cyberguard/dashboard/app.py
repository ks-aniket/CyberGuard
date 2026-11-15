"""Run with: uv run streamlit run src/cyberguard/dashboard/app.py."""

import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st

from cyberguard.dashboard.api_client import APIClient, APIError, Connection
from cyberguard.dashboard.components import visuals
from cyberguard.dashboard.pages import (
    about,
    batch_testing,
    model_performance,
    overview,
    test_lab,
)
from cyberguard.dashboard.report_loader import ReportError, load_validation
from cyberguard.dashboard.theme import apply_theme

st.set_page_config(
    page_title="CyberGuard | Intelligence Console",
    page_icon=":material/shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)


def main():
    apply_theme()
    try:
        client = APIClient()
    except APIError as exc:
        client = None
        st.session_state.connection = Connection(error=str(exc))

    def page(module):
        return lambda: module.render(
            client, st.session_state.connection, report, report_error
        )

    pages = [
        st.Page(
            page(overview),
            title="Overview",
            icon=":material/dashboard:",
            url_path="overview",
            default=True,
        ),
        st.Page(
            page(test_lab),
            title="Interactive Testing",
            icon=":material/radar:",
            url_path="interactive",
        ),
        st.Page(
            page(batch_testing),
            title="Batch Testing",
            icon=":material/table_chart:",
            url_path="batch",
        ),
        st.Page(
            page(model_performance),
            title="Model Performance",
            icon=":material/monitoring:",
            url_path="performance",
        ),
        st.Page(
            page(about),
            title="About CyberGuard",
            icon=":material/hub:",
            url_path="about",
        ),
    ]
    navigation = st.navigation(pages, position="hidden")
    with st.sidebar:
        visuals.brand()
        st.html('<div class="cg-nav-label">WORKSPACE</div>')
        for index, item in enumerate(pages):
            state = "active" if navigation.url_path == item.url_path else "idle"
            with st.container(key=f"nav_{state}_{index}"):
                st.page_link(item, width="stretch")
        st.html('<div class="cg-nav-label">CONNECTION</div>')
        refresh = st.button(
            "Refresh connection", icon=":material/sync:", width="stretch"
        )
        if client and (refresh or "connection" not in st.session_state):
            with st.spinner("Checking API and model…"):
                st.session_state.connection = client.check_connection()
                st.session_state.checked_at = datetime.now(UTC).strftime("%H:%M:%S UTC")
            st.session_state.pop("single_result", None)
            st.session_state.pop("batch_result", None)
        connection = st.session_state.connection
        st.html(
            '<div class="cg-badges">'
            + visuals.badge(
                "CONNECTED" if connection.live else "DISCONNECTED",
                "ok" if connection.live else "off",
            )
            + visuals.badge(
                "MODEL READY" if connection.ready else "UNVERIFIED",
                "ok" if connection.ready else "caution",
            )
            + "</div>"
        )
        if connection.error:
            st.error("Backend unavailable / unverified")
            st.caption(connection.error)
        if client:
            st.caption(f"API: {client.base_url}")
        st.caption("Last check: " + st.session_state.get("checked_at", "Not checked"))
        with st.expander("Connection behavior"):
            st.caption(
                "Status is checked on first visit or refresh, not on every interaction. Prediction failures block further submissions until refreshed. Refresh clears prior results."
            )
        st.html(
            '<div class="cg-footer">LOCAL WORKSPACE<br>EXPERIMENTAL · HEADER-ONLY</div>'
        )
    try:
        report, report_error = load_validation(), None
    except ReportError as exc:
        report, report_error = None, str(exc)
    visuals.topbar(navigation.title, connection)
    navigation.run()


if __name__ == "__main__":
    main()
