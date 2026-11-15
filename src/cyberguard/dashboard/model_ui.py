"""Registry-aware session transitions, scalar forms and prediction workspaces."""

import hashlib

import pandas as pd
import streamlit as st

from cyberguard.dashboard.api_client import APIError
from cyberguard.dashboard.batch import (
    DEMO_CSV,
    UploadError,
    parse_csv,
    results_frame,
    safe_csv,
)
from cyberguard.dashboard.components import charts, visuals
from cyberguard.dashboard.contracts import field_specs, validate_record
from cyberguard.dashboard.ui import available, prediction_failed


def clear_results(state, *, upload=False):
    for key in ("single_result", "batch_result", "batch_input_hash", "demo_csv"):
        state.pop(key, None)
    if upload:
        state["upload_epoch"] = state.get("upload_epoch", 0) + 1


def choose_model(state, model_id):
    if state.get("selected_model_id") != model_id:
        clear_results(state, upload=True)
        state["selected_model_id"] = model_id
        state.pop("active_selection", None)


def choose_mode(state, model_id, mode):
    preferences = state.setdefault("mode_preferences", {})
    if preferences.get(model_id) != mode:
        clear_results(state)
        preferences[model_id] = mode


def template_csv(model):
    return pd.DataFrame(columns=model.required_features).to_csv(index=False).encode()


def record_form(model):
    preferences = st.session_state.setdefault("form_preferences", {}).setdefault(
        model.id, {}
    )
    prefix = "form:" + model.id + ":"
    if model.input_contract_version == "bot-iot-header-v1":
        options = ["TCP", "UDP", "ICMP", "IPv6-ICMP", "ARP", "Custom"]
        protocol = st.selectbox(
            "Protocol",
            options,
            index=options.index(preferences.get("choice", "TCP")),
            key=prefix + "choice",
        )
        preferences["choice"] = protocol
        if protocol == "Custom":
            protocol = st.text_input(
                "Custom protocol",
                preferences.get("custom", "tcp"),
                key=prefix + "custom",
            )
            preferences["custom"] = protocol
        pnull = st.checkbox(
            "Protocol: JSON null",
            value=preferences.get("pnull", False),
            key=prefix + "pnull",
        )
        if protocol.lower() not in ("tcp", "udp", "6", "17"):
            st.info(
                "Nontransport protocols do not interpret these fields as TCP/UDP ports."
            )
        sport = st.text_input(
            "Source port", preferences.get("sport", "49152"), key=prefix + "sport"
        )
        snull = st.checkbox(
            "Source port: JSON null",
            value=preferences.get("snull", False),
            key=prefix + "snull",
        )
        dport = st.text_input(
            "Destination port", preferences.get("dport", "80"), key=prefix + "dport"
        )
        dnull = st.checkbox(
            "Destination port: JSON null",
            value=preferences.get("dnull", False),
            key=prefix + "dnull",
        )
        preferences.update(
            sport=sport, dport=dport, pnull=pnull, snull=snull, dnull=dnull
        )
        return dict(
            zip(
                model.required_features,
                [
                    None if pnull else protocol,
                    None if snull else sport,
                    None if dnull else dport,
                ],
                strict=True,
            )
        )
    specs = field_specs(model)
    labels = (
        [
            "Protocol",
            "Source port",
            "Destination port",
            "Incoming bytes",
            "Outgoing bytes",
            "Incoming packets",
            "Outgoing packets",
        ]
        if model.input_contract_version == "nf-cse-netflow-v1-completed-flow-v1"
        else None
    )
    record = {}
    for index, spec in enumerate(specs):
        name = spec["name"]
        label = labels[index] if labels else spec["label"]
        value = st.text_input(
            label,
            preferences.get(name, ""),
            key=prefix + name,
            help=f"{name}. {spec['help']}",
        )
        if "null" in spec["types"]:
            null = st.checkbox(
                label + ": JSON null",
                value=preferences.get(name + ":null", False),
                key=prefix + name + ":null",
            )
            preferences[name + ":null"] = null
        else:
            null = False
        preferences[name] = value
        record[name] = None if null else value
    return record


def interactive(client, connection):
    model = connection.selected
    visuals.heading(
        "Interactive Testing",
        "Inspect one supplied record with the selected model. Submitted values and actual API results stay together.",
        "ANALYSIS WORKSTATION / SINGLE RECORD",
    )
    st.caption(
        f"{model.display_name} · {model.task} · {connection.mode.replace('_', ' ')}"
    )
    enabled = available(connection)
    if model.input_contract_version == "nf-cse-netflow-v1-completed-flow-v1":
        st.info(
            "Completed bidirectional flow totals are required. IN/OUT follow the dataset/exporter convention; do not assume client/server directions without verified provenance. Counters are never inferred or filled with zero."
        )
    left, right = st.columns([1, 1.15], gap="large")
    with left, st.container(key="panel_single_input"):
        visuals.section("Traffic input", "01")
        try:
            record = record_form(model)
        except ValueError:
            st.warning(
                "This model uses an input schema without a supported form adapter."
            )
            return
        with st.expander("Accepted input formats"):
            st.caption(
                "Values are sent as entered. Exact numeric/alias rules belong to the API. Nonempty completed-flow counters are required; BoT retains null and token-status behavior."
            )
            st.json(model.input_schema)
        if st.button(
            "Analyze traffic",
            type="primary",
            icon=":material/radar:",
            width="stretch",
            disabled=not enabled,
        ):
            st.session_state.pop("single_result", None)
            try:
                validate_record(model, record)
            except ValueError as exc:
                st.error(str(exc))
            else:
                try:
                    result = client.predict_model(model, record, connection.mode)
                    st.session_state.single_result = (record, result)
                except APIError as exc:
                    prediction_failed(exc)
                    st.rerun()
    with right, st.container(key="panel_single_result"):
        visuals.section("Classification result", "02")
        saved = st.session_state.get("single_result")
        if (
            saved
            and saved[1].model_id == model.id
            and saved[1].operating_mode == connection.mode
        ):
            submitted, result = saved
            visuals.prediction_card(result)
            visuals.metadata(
                [
                    ("Model", model.display_name),
                    ("Task", result.task),
                    ("Operating mode", result.operating_mode),
                    (
                        "Applied threshold",
                        result.applied_threshold
                        if result.applied_threshold is not None
                        else "Not applicable",
                    ),
                    ("Input contract", result.input_contract_version),
                ]
            )
            if result.positive_class_score is not None:
                st.metric(
                    "Raw attack score · uncalibrated",
                    f"{result.positive_class_score:.8g}",
                )
            if result.class_scores is not None:
                st.plotly_chart(
                    charts.probabilities(result.class_scores),
                    width="stretch",
                    config={"displaylogo": False},
                )
            with st.expander("Submitted input", expanded=True):
                st.json(submitted)
            visuals.banner("MODEL LIMITATIONS", result.warning)
        else:
            visuals.empty_state(
                "Awaiting analysis",
                "Supply the selected model’s required fields. Only actual API responses appear here.",
            )
    visuals.banner(
        "INTERPRETATION / NOT A SAFETY DECISION",
        "Model scores are uncalibrated. A predicted class is not proof of attack occurrence or safety. No live monitoring is performed.",
        info=True,
    )


def batch_testing(client, connection):
    model = connection.selected
    visuals.heading(
        "Batch Testing",
        "Validate the selected schema, request bounded ordered predictions and download complete results.",
        "DATA WORKSPACE / CSV ANALYSIS",
    )
    st.caption(
        f"Required columns: {', '.join(model.required_features)} · UTF-8 · maximum 5 MiB / 20,000 records. Extra columns are preserved locally, never sent as predictors."
    )
    enabled = available(connection)
    st.download_button(
        "Download CSV template",
        template_csv(model),
        model.id + "_template.csv",
        "text/csv",
        on_click="ignore",
    )
    with st.expander("Expected CSV schema"):
        try:
            specs = field_specs(model)
        except ValueError:
            st.warning(
                "This model uses an input schema without a supported CSV adapter."
            )
            return
        st.table(
            pd.DataFrame(
                [
                    {
                        "Column": s["name"],
                        "Accepted types": ", ".join(sorted(s["types"])),
                        "Minimum": s["minimum"],
                        "Maximum": s["maximum"],
                    }
                    for s in specs
                ]
            )
        )
        st.caption(
            "Templates contain headers only, no fabricated traffic or attack labels."
        )
    upload = st.file_uploader(
        "Network records CSV",
        type=["csv"],
        max_upload_size=5,
        key=f"upload:{model.id}:{st.session_state.get('upload_epoch', 0)}",
    )
    if model.input_contract_version == "bot-iot-header-v1" and st.button(
        "Load demonstration CSV", icon=":material/science:"
    ):
        st.session_state.demo_csv = True
    data = (
        upload.getvalue()
        if upload is not None
        else DEMO_CSV
        if st.session_state.get("demo_csv")
        and model.input_contract_version == "bot-iot-header-v1"
        else None
    )
    if data is None:
        visuals.empty_state(
            "Ready for your records",
            "Download the header-only template and supply your own completed records before uploading.",
        )
        return
    if upload is None:
        st.info(
            "Four documented synthetic BoT software examples; no attack labels or evidence of generalization."
        )
    fingerprint = hashlib.sha256(model.id.encode() + data).hexdigest()
    if st.session_state.get("batch_input_hash") != fingerprint:
        st.session_state.pop("batch_result", None)
        st.session_state.batch_input_hash = fingerprint
    try:
        frame = parse_csv(data, model=model)
    except (UploadError, ValueError) as exc:
        st.error(str(exc))
        return
    visuals.section("Dataset preview", "02")
    st.metric("Input records", f"{len(frame):,}")
    st.table(frame.head(20))
    if connection.batch_limit:
        st.caption(
            f"At most {min(connection.batch_limit, 250)} records per API request; 10-second timeout, no automatic retries."
        )
    if st.button("Classify CSV", type="primary", disabled=not enabled):
        st.session_state.pop("batch_result", None)
        progress = st.progress(0, text="Submitting records…")
        try:
            result = client.predict_model_chunks(
                model,
                frame[model.required_features].to_dict("records"),
                connection.mode,
                batch_limit=connection.batch_limit,
                progress=lambda done, total: progress.progress(done / total),
            )
            st.session_state.batch_result = results_frame(frame, result, model=model)
        except APIError as exc:
            prediction_failed(exc)
            st.rerun()
    output = st.session_state.get("batch_result")
    if (
        output is not None
        and len(output)
        and output["model"].iloc[0] == model.id
        and output["operating_mode"].iloc[0] == connection.mode
    ):
        visuals.section("Classification distribution", "03")
        st.caption(
            f"{model.display_name} · operating mode {connection.mode}. Assignments on this upload, not verified network attack prevalence; source and sampling determine interpretation."
        )
        counts = (
            output.prediction.value_counts()
            .reindex(model.classes, fill_value=0)
            .rename("Predicted records")
            .to_frame()
        )
        counts["Percentage"] = counts["Predicted records"] / len(output) * 100
        a, b = st.columns([1.5, 1])
        a.plotly_chart(
            charts.distribution(counts), width="stretch", config={"displaylogo": False}
        )
        b.dataframe(counts, width="stretch")
        if "positive_class_score" in output:
            import plotly.express as px

            from cyberguard.dashboard.theme import CYAN, chart_theme

            figure = px.histogram(
                output,
                x="positive_class_score",
                nbins=30,
                color_discrete_sequence=[CYAN],
            )
            st.plotly_chart(
                chart_theme(figure), width="stretch", config={"displaylogo": False}
            )
            st.caption(
                "Raw attack-score distribution; uncalibrated, not verified attack prevalence."
            )
        page = st.number_input(
            "Results page (100 records per page)",
            min_value=1,
            max_value=(len(output) + 99) // 100,
            value=1,
            step=1,
            key=f"result_page:{model.id}:{fingerprint}",
        )
        st.table(
            output[[*model.required_features, "prediction"]].iloc[
                (page - 1) * 100 : page * 100
            ]
        )
        st.download_button(
            "Download prediction CSV",
            safe_csv(output),
            model.id + "_predictions.csv",
            "text/csv",
            on_click="ignore",
        )
        visuals.banner("MODEL LIMITATIONS", " ".join(model.limitations))
        st.caption(
            "Exports escape spreadsheet formula prefixes. Submitted tokens and row order are unchanged; metadata, mode, threshold and raw scores are included."
        )
