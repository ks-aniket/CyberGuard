"""Shared session behavior; connectivity checks are explicit, not widget polling."""

import streamlit as st

from cyberguard.dashboard.api_client import Connection


def prediction_failed(error):
    st.session_state.connection = Connection(error=str(error))
    st.session_state.pop("single_result", None)
    st.session_state.pop("batch_result", None)
    st.error(str(error))
    st.info("Use Refresh connection in the sidebar before submitting again.")


def available(connection):
    if not connection.ready:
        st.warning(
            "Predictions are blocked while the backend is unavailable or its contract is unverified. Start the API, then Refresh connection."
        )
    return connection.ready


def report_or_warning(report, error):
    if report is None:
        st.warning(error)
        return False
    return True
