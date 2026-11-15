import streamlit as st

from cyberguard.dashboard.components import visuals
from cyberguard.dashboard.components.metrics import capabilities
from cyberguard.dashboard.report_loader import PROJECT_ROOT


def render(client, connection, report, report_error):
    visuals.heading(
        "About CyberGuard",
        "CyberGuard is an experimental AI-assisted network intrusion detection MVP. This phase provides an offline classification workspace around a restricted BoT-IoT baseline.",
    )
    visuals.section("Architecture / request path", "01")
    visuals.architecture()
    st.caption(
        "The dashboard never loads a model, normalizes features or trains an estimator. The FastAPI service owns inference."
    )
    capabilities()
    visuals.section("Input contract", "02")
    st.code('{"proto": "tcp", "sport": "49152", "dport": "80"}', language="json")
    st.write(
        "Exactly three features: proto, sport, dport. API values may be strings, integers or explicit null. TCP/UDP ports support decimal, hexadecimal, sentinel and invalid/missing statuses; ICMP/ARP fields are not transport ports. CSV tokens are retained as strings. Supported targets: Normal, DoS, DDoS, Reconnaissance."
    )
    visuals.section("Evidence and limitations", "03")
    visuals.banner(
        "RESEARCH BASELINE / NOT A PRODUCTION IDS",
        "Header-only classification cannot establish an attack or safety. Probabilities are uncalibrated. Theft and unknown attacks are unsupported. The original training file contains only 370 Normal records, with 79 in internal validation. Related records and scenario/exporter artifacts limit generalization. DNS three-class training remains NO-GO. The official BoT-IoT test split is reserved.",
    )
    st.write(
        "Live intrusion detection would additionally require validated capture, causal feature extraction, independently labeled evaluation and operational handling. This app performs none of those activities and does not generate alerts."
    )
    visuals.section("Local documentation", "04")
    st.caption(
        "These existing Markdown documents can be read here without exposing server filesystem paths."
    )
    for label, relative in [
        ("Project README", "README.md"),
        (
            "Baseline validation report",
            "reports/model_evaluation/bot_iot_validation.md",
        ),
        (
            "Feature availability and leakage audit",
            "reports/model_evaluation/bot_iot_feature_audit.md",
        ),
        ("DNS investigation", "reports/dataset_analysis/dns_investigation.md"),
    ]:
        with st.expander(label):
            try:
                # Render as plain text: repository Markdown links are relative to files,
                # not served by Streamlit's URL router. No arbitrary paths are accepted.
                st.text((PROJECT_ROOT / relative).read_text())
            except OSError:
                st.info(
                    "This documentation file is not available in this installation."
                )
