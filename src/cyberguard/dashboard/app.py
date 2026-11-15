"""Run with: uv run streamlit run src/cyberguard/dashboard/app.py."""

import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from dataclasses import replace

import streamlit as st

from cyberguard.dashboard.api_client import APIClient, APIError, Connection
from cyberguard.dashboard.components import visuals
from cyberguard.dashboard.model_ui import choose_mode, choose_model, clear_results
from cyberguard.dashboard.pages import (
    about,
    batch_testing,
    model_performance,
    overview,
    test_lab,
)
from cyberguard.dashboard.report_loader import (
    ReportError,
    load_nf_final,
    load_validation,
)
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
        def render():
            if st.session_state.connection.selected is None and module in (
                test_lab,
                batch_testing,
            ):
                visuals.heading(
                    navigation.title,
                    "Select a registered model to inspect its input requirements.",
                )
                st.warning(
                    "No selected model metadata is available. Refresh the API connection; no alternative model has been selected automatically."
                )
                return
            module.render(client, st.session_state.connection, report, report_error)

        return render

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
                st.session_state.connection = client.check_models()
                st.session_state.checked_at = datetime.now(UTC).strftime("%H:%M:%S UTC")
            clear_results(st.session_state, upload=True)
            st.session_state.pop("active_selection", None)
        connection = st.session_state.connection
        models = {model.id: model for model in connection.models}
        if models or st.session_state.get("selected_model_id"):
            options = list(models)
            previous = st.session_state.get("selected_model_id")
            if previous and previous not in options:
                options.append(previous)
            if previous is None and options:
                previous = options[0]
            st.html('<div class="cg-nav-label">MODEL WORKSPACE</div>')
            selected = st.selectbox(
                "Selected model",
                options,
                index=options.index(previous),
                format_func=lambda key: (
                    models[key].display_name
                    if key in models
                    else "Unavailable / " + key
                ),
                key="model_selector",
            )
            choose_model(st.session_state, selected)
            if client and st.session_state.get("active_selection") != selected:
                connection = client.select_model(connection, selected)
                st.session_state.connection = connection
                st.session_state.active_selection = selected
            if connection.selected:
                info = connection.selected
                st.caption(f"{info.task.title()} · {info.readiness}")
                st.caption(info.description)
                mode_ids = [option.id for option in info.available_operating_modes]
                preferences = st.session_state.setdefault("mode_preferences", {})
                preferred = preferences.get(selected, info.default_operating_mode)
                if preferred not in mode_ids:
                    preferred = info.default_operating_mode
                if len(mode_ids) > 1:
                    mode_key = "mode_selector:" + selected
                    if (
                        mode_key in st.session_state
                        and st.session_state[mode_key] not in mode_ids
                    ):
                        del st.session_state[mode_key]
                    mode = st.selectbox(
                        "Operating mode",
                        mode_ids,
                        index=mode_ids.index(preferred),
                        format_func=lambda value: value.replace("_", " ").title(),
                        key=mode_key,
                    )
                    st.caption(
                        f"Applied threshold: {info.threshold(mode):.17g} · uncalibrated scores"
                    )
                else:
                    mode = info.default_operating_mode
                choose_mode(st.session_state, selected, mode)
                connection = replace(connection, mode=mode)
                st.session_state.connection = connection
        elif connection.live and not connection.error:
            st.info("The API has no registered models.")
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
            '<div class="cg-footer">LOCAL WORKSPACE<br>EXPERIMENTAL · OFFLINE INFERENCE</div>'
        )
    try:
        if connection.selected is None and st.session_state.get("selected_model_id"):
            report = None
            report_error = "Selected-model metadata cannot be verified. Refresh the API connection; no other model's evidence is substituted."
        elif (
            connection.selected
            and connection.selected.input_contract_version
            == "nf-cse-netflow-v1-completed-flow-v1"
        ):
            report = load_nf_final(expected_version=connection.selected.model_version)
        elif (
            connection.selected
            and connection.selected.input_contract_version != "bot-iot-header-v1"
        ):
            report = None
            report_error = (
                "No matched local performance adapter is available for this contract."
            )
        else:
            report = load_validation()
            if (
                connection.selected
                and connection.selected.model_version != "sha256:" + report.model_sha256
            ):
                raise ReportError(
                    "Saved BoT validation belongs to a different artifact. Historical scores are not attributed to the selected model."
                )
        if report is not None:
            report_error = None
    except ReportError as exc:
        report, report_error = None, str(exc)
    visuals.topbar(navigation.title, connection)
    navigation.run()


if __name__ == "__main__":
    main()
