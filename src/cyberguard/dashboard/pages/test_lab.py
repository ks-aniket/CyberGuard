import streamlit as st

from cyberguard.dashboard.api_client import APIError
from cyberguard.dashboard.components.charts import probabilities
from cyberguard.dashboard.ui import available, prediction_failed


def render(client, connection, report, report_error):
    st.title("Interactive Testing")
    st.write("Submit one header record to the existing FastAPI model.")
    enabled = available(connection)
    protocol = st.selectbox(
        "Protocol", ["TCP", "UDP", "ICMP", "IPv6-ICMP", "ARP", "Custom"]
    )
    if protocol == "Custom":
        protocol = st.text_input("Custom protocol", "tcp")
    protocol_null = st.checkbox("Protocol: JSON null")
    if protocol.lower() not in ("tcp", "udp", "6", "17"):
        st.info(
            "For ICMP, IPv6-ICMP, ARP and unknown protocols, the fitted pipeline does not interpret these fields as TCP/UDP transport ports."
        )
    st.caption(
        "Tokens are sent unchanged: decimal / hex ports, 0, sentinel - or -1, empty strings and invalid tokens use the existing pipeline statuses. Select JSON null to represent missingness. JSON strings, integers and null are accepted by the API; text controls preserve your spelling as strings."
    )
    left, right = st.columns(2)
    with left:
        sport = st.text_input("Source port", "49152")
        sport_null = st.checkbox("Source port: JSON null")
    with right:
        dport = st.text_input("Destination port", "80")
        dport_null = st.checkbox("Destination port: JSON null")
    record = {
        "proto": None if protocol_null else protocol,
        "sport": None if sport_null else sport,
        "dport": None if dport_null else dport,
    }
    if st.button("Predict record", type="primary", disabled=not enabled):
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
    if "single_result" in st.session_state:
        submitted, result = st.session_state.single_result
        st.subheader("Last successful prediction")
        st.metric("Predicted class", result.prediction)
        st.caption(f"Model: {result.model}")
        st.write("Submitted input")
        st.json(submitted)
        if result.probabilities is not None:
            st.plotly_chart(probabilities(result.probabilities), width="stretch")
        else:
            st.info("This model did not return class probabilities.")
        st.warning(result.warning)
    st.caption(
        "Experimental predictions use only protocol and ports. Probabilities are uncalibrated. Normal does not guarantee safety; DDoS does not prove an attack occurred. Theft and unknown attacks are unsupported."
    )
