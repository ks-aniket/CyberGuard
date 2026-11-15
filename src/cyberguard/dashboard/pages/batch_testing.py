import hashlib

import streamlit as st

from cyberguard.dashboard.api_client import APIError
from cyberguard.dashboard.batch import (
    DEMO_CSV,
    FEATURES,
    UploadError,
    parse_csv,
    results_frame,
    safe_csv,
)
from cyberguard.dashboard.components import visuals
from cyberguard.dashboard.components.charts import distribution
from cyberguard.dashboard.ui import available, prediction_failed


def render(client, connection, report, report_error):
    visuals.heading(
        "Batch Testing",
        "From header records to ordered predictions. Inspect your data, run bounded inference and export the complete result.",
        "DATA WORKSPACE / CSV ANALYSIS",
    )
    st.caption(
        "Required columns: proto, sport, dport · UTF-8 · maximum 5 MiB and 20,000 records. Additional columns are preserved for export and never sent as model features. Files remain in memory."
    )
    enabled = available(connection)
    with st.container(key="panel_batch_upload"):
        visuals.section("Import records", "01")
        upload = st.file_uploader(
            "Network records CSV", type=["csv"], max_upload_size=5
        )
        if st.button("Load demonstration CSV", icon=":material/science:"):
            st.session_state.demo_csv = True
    if upload is not None:
        data = upload.getvalue()
    elif st.session_state.get("demo_csv"):
        data = DEMO_CSV
        st.info(
            "Using four synthetic demonstration records. These are software examples, with no verified attack labels or generalization evidence. An uploaded file takes priority."
        )
    else:
        visuals.empty_state(
            "Ready for your records",
            "Choose a CSV to preview and classify, or load the explicitly synthetic demonstration CSV.",
        )
        return
    fingerprint = hashlib.sha256(data).hexdigest()
    if st.session_state.get("batch_input_hash") != fingerprint:
        st.session_state.pop("batch_result", None)
        st.session_state.batch_input_hash = fingerprint
    try:
        frame = parse_csv(data)
    except UploadError as exc:
        st.error(str(exc))
        return
    visuals.section("Dataset preview", "02")
    a, b, c = st.columns(3)
    a.metric("Input records", f"{len(frame):,}")
    b.metric("Input columns", str(len(frame.columns)))
    c.metric("Preview rows", str(min(20, len(frame))))
    # Native dataframe toolbars offer an unescaped CSV export. Raw user tokens
    # therefore use non-downloadable tables; only safe_csv owns file exports.
    st.table(frame.head(20))
    if connection.ready:
        st.caption(
            f"Backend maximum: {connection.batch_limit:,} records/request. This dashboard submits at most {min(connection.batch_limit, 250):,} per request, with a 10-second timeout per request and no automatic retries."
        )
    if st.button(
        "Classify CSV",
        type="primary",
        disabled=not enabled,
        icon=":material/play_arrow:",
    ):
        st.session_state.pop("batch_result", None)
        progress = st.progress(0, text="Submitting records…")
        try:
            results = client.predict_chunks(
                frame[list(FEATURES)].to_dict("records"),
                batch_limit=connection.batch_limit,
                expected_model=connection.info.model,
                progress=lambda done, total: progress.progress(
                    done / total, text=f"Classified {done:,} / {total:,} records"
                ),
            )
            st.session_state.batch_result = results_frame(frame, results)
        except APIError as exc:
            progress.empty()
            prediction_failed(exc)
            st.rerun()
    if "batch_result" in st.session_state:
        output = st.session_state.batch_result
        visuals.section("Classification distribution", "03")
        st.caption("Model predictions on uploaded records.")
        st.metric("Total records classified", f"{len(output):,}")
        counts = (
            output["prediction"]
            .value_counts()
            .reindex(connection.info.supported_classes, fill_value=0)
            .rename("Predicted records")
            .to_frame()
        )
        counts["Percentage"] = counts["Predicted records"] / len(output) * 100
        with st.container(key="layout_batch_results"):
            chart_column, table_column = st.columns([1.5, 1])
        with chart_column, st.container(key="panel_batch_distribution"):
            st.plotly_chart(
                distribution(counts), width="stretch", config={"displaylogo": False}
            )
        with table_column:
            st.dataframe(
                counts,
                width="stretch",
                column_config={
                    "Percentage": st.column_config.NumberColumn(format="%.1f%%")
                },
            )
        visuals.section("Ordered results", "04")
        page_count = (len(output) + 99) // 100
        page = st.number_input(
            "Results page (100 records per page)",
            min_value=1,
            max_value=page_count,
            value=1,
            step=1,
        )
        start = (page - 1) * 100
        st.caption(
            f"Showing records {start + 1:,}–{min(start + 100, len(output)):,} of {len(output):,}. The download contains every record."
        )
        st.caption(
            f"Model: {connection.info.model}. The CSV export also includes extra input columns, warnings and available probabilities."
        )
        st.table(output[[*FEATURES, "prediction"]].iloc[start : start + 100])
        visuals.banner("MODEL LIMITATIONS", connection.info.warning)
        st.download_button(
            "Download prediction CSV",
            safe_csv(output),
            "cyberguard_predictions.csv",
            "text/csv",
            on_click="ignore",
            icon=":material/download:",
        )
        st.caption(
            "Downloads escape spreadsheet formula prefixes in cells and column headers using a leading apostrophe. Displayed/submitted tokens are unchanged. Counts are model assignments, not verified attacks. Probabilities are uncalibrated; Normal does not establish safety."
        )
