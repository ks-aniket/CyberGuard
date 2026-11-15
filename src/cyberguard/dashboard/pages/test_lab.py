import streamlit as st

from cyberguard.dashboard.api_client import APIError
from cyberguard.dashboard.components import visuals
from cyberguard.dashboard.components.charts import probabilities
from cyberguard.dashboard.ui import available, prediction_failed


def render(client, connection, report, report_error):
    if connection.selected is not None:
        from cyberguard.dashboard.model_ui import interactive

        return interactive(client, connection)
    visuals.heading(
        "Interactive Testing",
        "Inspect one header record. Read the model's response alongside the exact input you submitted.",
        "ANALYSIS WORKSTATION / SINGLE RECORD",
    )
    enabled = available(connection)
    with st.container(key="layout_workstation"):
        inputs, results = st.columns([1, 1.15], gap="large")
    with inputs, st.container(key="panel_single_input"):
        visuals.section("Traffic input", "01")
        protocol = st.selectbox(
            "Protocol", ["TCP", "UDP", "ICMP", "IPv6-ICMP", "ARP", "Custom"]
        )
        if protocol == "Custom":
            protocol = st.text_input("Custom protocol", "tcp")
        protocol_null = st.checkbox("Protocol: JSON null")
        if protocol.lower() not in ("tcp", "udp", "6", "17"):
            st.info(
                "For ICMP, IPv6-ICMP, ARP and unknown protocols, these fields are not interpreted as TCP/UDP transport ports."
            )
        sport = st.text_input("Source port", "49152")
        sport_null = st.checkbox("Source port: JSON null")
        dport = st.text_input("Destination port", "80")
        dport_null = st.checkbox("Destination port: JSON null")
        record = {
            "proto": None if protocol_null else protocol,
            "sport": None if sport_null else sport,
            "dport": None if dport_null else dport,
        }
        with st.expander("Accepted input formats"):
            st.caption(
                "Tokens are sent unchanged as strings: decimal / hex ports, valid zero, sentinel - or -1, empty and invalid tokens use existing pipeline statuses. JSON null represents missingness. The API also accepts strict integer values; the text controls preserve spelling as strings."
            )
        if st.button(
            "Analyze traffic",
            type="primary",
            icon=":material/radar:",
            width="stretch",
            disabled=not enabled,
        ):
            st.session_state.pop("single_result", None)
            try:
                with st.spinner("Requesting model prediction…"):
                    result = client.predict(record)
                    if result.model != connection.info.model:
                        raise APIError(
                            "The backend model changed. Refresh the connection before resubmitting."
                        )
                st.session_state.single_result = (record, result)
            except APIError as exc:
                prediction_failed(exc)
                st.rerun()
    with results, st.container(key="panel_single_result"):
        visuals.section("Classification result", "02")
        if "single_result" in st.session_state:
            submitted, result = st.session_state.single_result
            st.caption("Last successful prediction · submitted values shown below")
            visuals.prediction_card(result)
            if result.probabilities is not None:
                st.plotly_chart(
                    probabilities(result.probabilities),
                    width="stretch",
                    config={"displaylogo": False},
                )
            else:
                st.info("This model did not return class probabilities.")
            with st.expander("Submitted input", expanded=True):
                st.json(submitted)
            visuals.banner("MODEL LIMITATIONS", result.warning)
        else:
            visuals.empty_state(
                "Awaiting analysis",
                "Enter protocol and port values, then analyze the record. Only actual API results appear here.",
            )
    visuals.banner(
        "INTERPRETATION / NOT A SAFETY DECISION",
        "Experimental predictions use only protocol and ports. Probabilities are uncalibrated. Normal does not guarantee safety; DDoS does not prove an attack occurred. Theft and unknown attacks are unsupported.",
        info=True,
    )
