"""HTTP-only Simulation Lab. The backend owns every generator/inference worker."""

import pandas as pd
import streamlit as st

from cyberguard.dashboard import simulation_charts as charts
from cyberguard.dashboard.api_client import APIError
from cyberguard.dashboard.components import visuals
from cyberguard.dashboard.simulation_contracts import NF_SIM_MODEL
from cyberguard.dashboard.simulation_ui import (
    LabState,
    actions,
    activity_frame,
    event_frame,
    form_payload,
    json_export,
    milliseconds,
)


def _resources(client, cache, refresh):
    resources = st.session_state.setdefault("sim_resources", {})
    if client and (refresh or not resources):
        try:
            model = client.model_info(NF_SIM_MODEL)
            schema = client.simulation_schema()
            if (
                model.id != NF_SIM_MODEL
                or model.task != "binary"
                or any(m.threshold is None for m in model.available_operating_modes)
            ):
                raise APIError(
                    "The NF-CSE simulation metadata is incompatible; refresh after restoring the supported model."
                )
            if model.readiness == "ready":
                client.model_ready(NF_SIM_MODEL)
            resources = {"model": model, "schema": schema, "error": None}
        except APIError as exc:
            resources = {"error": str(exc)}
        st.session_state.sim_resources = resources
    if client and (refresh or cache.refresh_history):
        try:
            cache.runs = client.list_simulations()
            cache.refresh_history = False
            if refresh:
                cache.creation_uncertain = False
                cache.blocked = False
                cache.missing = False
                cache.error = None
                cache.exhausted = False
            if cache.selected and cache.selected not in {r["id"] for r in cache.runs}:
                cache.missing = cache.blocked = True
                cache.error = "This run is no longer retained. The backend may have restarted. Cached results remain available; select an existing run or prepare a new simulation."
        except APIError as exc:
            cache.error = str(exc)
            cache.blocked = True
    return resources


def _configuration(client, cache, resources, connection):
    model = resources.get("model")
    schema = resources.get("schema")
    with st.expander("Configure a simulation", expanded=cache.creation_armed):
        if resources.get("error"):
            st.warning(resources["error"])
        if not model or not schema:
            st.info(
                "Refresh Lab to retrieve the NF-CSE model and API configuration limits. Retained results can still be inspected below."
            )
            return
        if model.readiness != "ready":
            st.warning(
                "NF-CSE is unavailable. Restore the backend model and refresh Lab. Existing simulations can still be inspected."
            )
        props = schema["properties"]
        preferences = st.session_state.setdefault("sim_form_values", {})

        def value(name):
            return preferences.get(name, props[name].get("default"))

        batch_limit = min(
            int(props["batch_size"]["maximum"]),
            (connection.batch_limits or {}).get(model.id, 0),
        )
        if not batch_limit:
            st.warning(
                "NF-CSE's model batch limit is unavailable. Refresh the dashboard connection before creating a run."
            )
        with st.form("sim_configuration", border=False):
            left, right = st.columns(2, gap="large")
            with left:
                st.selectbox("Simulation model", [model.display_name], disabled=True)
                mode = st.selectbox(
                    "Generation mode",
                    props["mode"]["enum"],
                    index=props["mode"]["enum"].index(value("mode")),
                    format_func=str.title,
                    key="sim_form_mode",
                )
                st.caption(
                    "Empirical: multiplicity-weighted training replay. Synthetic: training-derived synthesis with bounded joint-counter perturbations."
                )
                rate_options = [
                    v
                    for v in (10, 50, 100, 250, 500)
                    if props["generation_rate"].get("minimum", 1)
                    <= v
                    <= props["generation_rate"]["maximum"]
                ]
                rate = st.selectbox(
                    "Generation rate (flows/s)",
                    rate_options,
                    index=rate_options.index(int(value("generation_rate")))
                    if int(value("generation_rate")) in rate_options
                    else 0,
                    key="sim_form_rate",
                )
                duration = st.number_input(
                    "Duration cap (seconds)",
                    min_value=1,
                    max_value=int(props["max_duration"]["maximum"]),
                    value=int(value("max_duration")),
                    key="sim_form_duration",
                    help=f"Backend accepts >{props['max_duration'].get('exclusiveMinimum', 0)} to {props['max_duration']['maximum']} s. Includes setup and pauses; accepted records drain afterward.",
                )
            with right:
                attack = st.slider(
                    "Attack-profile share (%)",
                    0,
                    100,
                    int(preferences.get("attack_percent", 10)),
                    format="%d%%",
                    key="sim_form_attack",
                    help="Benign-profile percentage is 100 minus this value. Training-derived labels are not verified attacks.",
                )
                st.caption(
                    "Benign profile = 100% − attack-profile share. The submitted proportions always total 100%."
                )
                operating = [
                    m.id
                    for m in model.available_operating_modes
                    if m.id in props["operating_mode"]["enum"]
                ]
                selected_mode = preferences.get(
                    "operating_mode", model.default_operating_mode
                )
                operation = st.selectbox(
                    "Simulation operating mode",
                    operating,
                    index=operating.index(selected_mode)
                    if selected_mode in operating
                    else 0,
                    format_func=lambda m: (
                        f"{m.replace('_', ' ').title()} · threshold {model.threshold(m):.6g}"
                    ),
                    key="sim_form_operating",
                )
                records = st.number_input(
                    "Maximum generated records",
                    min_value=int(props["max_records"]["minimum"]),
                    max_value=int(props["max_records"]["maximum"]),
                    value=int(value("max_records")),
                    key="sim_form_records",
                )
                seed = st.text_input(
                    "Random seed (optional)",
                    value=preferences.get(
                        "seed_text", str(props["seed"].get("default", 42))
                    ),
                    key="sim_form_seed",
                    help="Blank uses the advertised backend default. Identical configuration/profiles/model/seed reproduce records and predictions; timing varies.",
                )
            with st.expander("Advanced settings"):
                a, b, c = st.columns(3)
                batch = a.number_input(
                    "Batch size",
                    min_value=1,
                    max_value=max(1, batch_limit),
                    value=min(int(value("batch_size")), max(1, batch_limit)),
                    key="sim_form_batch",
                )
                queue = b.number_input(
                    "Queue capacity",
                    min_value=int(props["queue_capacity"]["minimum"]),
                    max_value=int(props["queue_capacity"]["maximum"]),
                    value=int(value("queue_capacity")),
                    key="sim_form_queue",
                )
                retention = c.number_input(
                    "Backend event retention",
                    min_value=int(props["event_capacity"]["minimum"]),
                    max_value=int(props["event_capacity"]["maximum"]),
                    value=int(
                        preferences.get(
                            "event_capacity",
                            min(1000, props["event_capacity"]["maximum"]),
                        )
                    ),
                    key="sim_form_retention",
                )
                st.caption(
                    "A full queue blocks generation. Frontend retains at most 1,000 events and 120 chart samples; exports may be partial."
                )
            submitted = st.form_submit_button(
                "Create simulation",
                type="primary",
                disabled=not client
                or model.readiness != "ready"
                or not batch_limit
                or not cache.creation_armed
                or cache.creation_uncertain,
                icon=":material/add_circle:",
            )
        preferences.update(
            mode=mode,
            generation_rate=rate,
            max_duration=duration,
            max_records=records,
            seed_text=seed,
            attack_percent=attack,
            operating_mode=operation,
            batch_size=batch,
            queue_capacity=queue,
            event_capacity=retention,
        )
        if submitted and cache.creation_armed and not cache.creation_uncertain:
            try:
                payload = form_payload(
                    {
                        "mode": mode,
                        "generation_rate": rate,
                        "max_duration": duration,
                        "max_records": records,
                        "seed_text": seed,
                        "attack_ratio": attack / 100,
                        "benign_ratio": (100 - attack) / 100,
                        "operating_mode": operation,
                        "batch_size": batch,
                        "queue_capacity": queue,
                        "event_capacity": retention,
                        "history_capacity": min(
                            120, int(props["history_capacity"]["maximum"])
                        ),
                    },
                    schema,
                    model,
                    batch_limit,
                )
                cache.create(client, payload)
                st.session_state.sim_selection_epoch = (
                    st.session_state.get("sim_selection_epoch", 0) + 1
                )
                st.rerun()
            except (APIError, ValueError) as exc:
                st.error(str(exc))
        if cache.creation_uncertain:
            st.warning(
                "Creation outcome is uncertain. Refresh Lab and inspect history before another create request; the frontend never retries automatically."
            )
        elif not cache.creation_armed:
            st.caption(
                "Creation is locked after submission. Use Prepare new simulation for another run."
            )


def _kpis(metrics):
    latency = metrics["latency_seconds"]["end_to_end"]
    latency_display = (
        "—"
        if latency["mean_lifetime"] is None or latency["p95_recent"] is None
        else f"{latency['mean_lifetime'] * 1000:.1f} / {latency['p95_recent'] * 1000:.1f} ms"
    )
    rows = [
        [
            ("Generated", f"{metrics['generated']:,}", "cyan"),
            ("Classified", f"{metrics['classified']:,}", "cyan"),
            ("Predicted benign", f"{metrics['predicted_benign']:,}", "purple"),
            ("Predicted attack", f"{metrics['predicted_attack']:,}", "warning"),
        ],
        [
            ("Generation rate", f"{metrics['actual_generation_rate']:,.1f} /s", "cyan"),
            (
                "Classification rate",
                f"{metrics['actual_inference_rate']:,.1f} /s",
                "purple",
            ),
            (
                "Queue depth",
                f"{metrics['queue_depth']} / {metrics['queue_capacity']}",
                "cyan",
            ),
            (
                "Latency · mean / p95",
                latency_display,
                "purple",
            ),
        ],
    ]
    for rownum, row in enumerate(rows):
        for col, (label, val, tone) in zip(st.columns(4), row, strict=True):
            with col:
                visuals.metric_card(label, val, key=f"sim_{rownum}_{label}", tone=tone)
    st.caption(
        f"Generated = accepted into the backend queue. {metrics['inflight']} in flight · {metrics['discarded']} discarded · {metrics['queue_full']} queue-full episodes. Rates include setup, pauses and drain; requested target {metrics['requested_generation_rate']:g}/s."
    )


def _plots(cache):
    metrics = cache.metrics
    history = [p for p in metrics["history"]][-120:]
    samples = pd.DataFrame(list(cache.samples))
    left, right = st.columns(2, gap="large")
    with left:
        visuals.section("Traffic activity", "02")
        st.plotly_chart(
            charts.series(
                activity_frame(history),
                [("Generated / s", "Generated"), ("Classified / s", "Classified")],
                "Observed interval records / s",
            ),
            width="stretch",
            key="sim_activity",
        )
        st.caption(
            "Derived from adjacent backend history counters / actual elapsed intervals; no interpolation. First retained point is a baseline."
        )
        visuals.section("Processing performance", "04")
        st.plotly_chart(
            charts.performance(samples), width="stretch", key="sim_performance"
        )
    with right:
        visuals.section("Prediction distribution", "03")
        st.plotly_chart(
            charts.series(
                samples,
                [
                    ("predicted_benign", "Predicted benign"),
                    ("predicted_attack", "Predicted attack"),
                ],
                "Cumulative classified records",
            ),
            width="stretch",
            key="sim_prediction",
        )
        st.caption(
            "Backend cumulative prediction counts observed at polls. Only samples collected while this page is open are shown."
        )
        visuals.section("End-to-end latency", "05")
        st.plotly_chart(
            charts.series(
                samples,
                [("mean_ms", "Lifetime mean"), ("p95_ms", "Recent p95")],
                "Milliseconds",
            ),
            width="stretch",
            key="sim_latency",
        )
    st.caption(
        "Latency: admission → inference and score verification complete; excludes event rendering. Mean is lifetime record-weighted; p95 covers the latest ≤2,000 backend records. Chart points are aggregate snapshots, not interval-specific latency."
    )
    with st.expander("Latency components and queue diagnostics"):
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Component": name,
                        "Lifetime mean": milliseconds(v["mean_lifetime"]),
                        "Recent p95": milliseconds(v["p95_recent"]),
                        "Recent samples": v["recent_samples"],
                    }
                    for name, v in metrics["latency_seconds"].items()
                ]
            ),
            hide_index=True,
            width="stretch",
        )
        st.caption(
            f"Queue wait includes batch gathering; processing includes shared model-lock contention. Queue high-water: {metrics['queue_high_water']}; admission backpressure: {metrics['queue_backpressure_seconds']:.3f} s (can include paused time during a blocked episode)."
        )
    visuals.section("Prediction Agreement with Generator Profiles", "06")
    agreement = metrics["source_agreement_fraction"]
    st.caption(
        f"Backend lifetime agreement: {'—' if agreement is None else format(agreement, '.2%')} ({metrics['source_agreement']:,} / {metrics['classified']:,} classified records). Training-derived profile labels are not independently verified ground truth; agreement is not test accuracy."
    )
    st.plotly_chart(
        charts.profile_prediction(metrics), width="stretch", key="sim_agreement"
    )
    st.caption(
        "Separate marginal counts: generated source profiles versus classified predictions. The backend does not expose joint cross-counts; no confusion matrix is inferred from the retained event buffer."
    )


def _explorer(cache):
    visuals.section("Recent classified events", "07")
    count = len(cache.events)
    st.caption(
        f"{count:,} frontend-retained events · exclusive cursor {cache.cursor}. Table shows latest 100; inspector and CSV use up to 1,000 retained events."
    )
    if cache.gap:
        st.warning(
            "Event cursor gap: older backend events were overwritten while this page was away or polling lagged. Metrics remain full-run; retained-event export is partial."
        )
    if not cache.events:
        st.info(
            "No classified events are available yet. Generation may be starting, paused, or empty after failure."
        )
        return
    frame = event_frame(cache.events[-100:])
    styled = frame.style.map(
        lambda v: (
            "color: #ffb454; font-weight: 600" if v == "Attack" else "color: #26dfb5"
        ),
        subset=["predicted_class"],
    )
    st.dataframe(
        styled,
        hide_index=True,
        width="stretch",
        height=310,
        column_config={
            "attack_score": st.column_config.NumberColumn(
                "Attack score", format="%.6f"
            ),
            "simulation_time_s": st.column_config.NumberColumn(
                "Simulation time (s)", format="%.3f"
            ),
        },
    )
    options = [e["sequence"] for e in reversed(cache.events)]
    if cache.selected_event not in options:
        cache.selected_event = options[0]
    event_key = f"sim_event_choice:{cache.selected}"
    if event_key in st.session_state and st.session_state[event_key] not in options:
        del st.session_state[event_key]
    sequence = st.selectbox(
        "Inspect retained event",
        options,
        index=options.index(cache.selected_event),
        key=event_key,
    )
    cache.selected_event = sequence
    with st.expander(f"Event {sequence} · full input and prediction details"):
        st.json(next(e for e in cache.events if e["sequence"] == sequence))
    st.caption(
        "Amber marks a model-predicted attack; it does not confirm malicious activity. Attack scores are uncalibrated."
    )


def _summary_exports(cache):
    metrics, snapshot = cache.metrics, cache.snapshot
    if snapshot["finished"]:
        visuals.section("Finished simulation summary", "08")
        if snapshot["state"] == "failed":
            st.error(
                "Simulation failed. Results below include work committed before failure. Check backend logs; restore profiles/model availability and create a new run."
            )
        elif snapshot["state"] == "stopped":
            st.success(
                f"Manually stopped · {metrics['generated']:,} accepted / {metrics['classified']:,} classified · {metrics['discarded']:,} discarded. Accepted records drain before finished=true."
            )
        else:
            st.success(
                f"Completed · {metrics['classified']:,} classified of {metrics['generated']:,} accepted; configured ceiling {snapshot['config']['max_records']:,}."
            )
        config = snapshot["config"]
        visuals.metadata(
            [
                ("Simulation ID", snapshot["id"]),
                ("Model", config["model_id"]),
                ("Generation / seed", f"{config['mode']} / {config['seed']}"),
                (
                    "Configured / actual rate",
                    f"{config['generation_rate']:g} / {metrics['actual_generation_rate']:.2f} flows/s",
                ),
                (
                    "Generated source profiles",
                    f"{metrics['benign_profile']:,} benign / {metrics['attack_profile']:,} attack",
                ),
                (
                    "Model predictions",
                    f"{metrics['predicted_benign']:,} benign / {metrics['predicted_attack']:,} attack",
                ),
                (
                    "Lifetime source agreement",
                    "—"
                    if metrics["source_agreement_fraction"] is None
                    else f"{metrics['source_agreement_fraction']:.2%}",
                ),
                (
                    "End-to-end mean / recent p95",
                    f"{milliseconds(metrics['latency_seconds']['end_to_end']['mean_lifetime'])} / {milliseconds(metrics['latency_seconds']['end_to_end']['p95_recent'])}",
                ),
                ("Queue high-water", metrics["queue_high_water"]),
                (
                    "Termination",
                    f"{snapshot['state']} / {snapshot['termination_reason']}",
                ),
            ]
        )
        if snapshot.get("error"):
            error = snapshot["error"]
            st.caption(
                f"Diagnostic code: {str(error.get('code', 'worker_failure'))[:64]} · stage: {str(error.get('stage', 'unknown'))[:64]}"
            )
    visuals.section("Export available results", "09")
    complete = cache.complete_export()
    st.caption(
        "Retained-event CSV contains all classified events for this run."
        if complete
        else "Partial event export: only the frontend-retained recent events are included. These are not all generated or classified records; aggregate metrics remain full-run backend values."
    )
    a, b, c = st.columns(3)
    a.download_button(
        "Retained events CSV",
        cache.event_export(),
        file_name=f"simulation_{cache.selected}_retained_events.csv",
        mime="text/csv",
        disabled=not cache.events,
        key="sim_download_events",
        on_click="ignore",
    )
    b.download_button(
        "Configuration JSON",
        json_export(snapshot["config"]),
        file_name=f"simulation_{cache.selected}_configuration.json",
        mime="application/json",
        key="sim_download_configuration",
        on_click="ignore",
    )
    c.download_button(
        "Aggregate metrics JSON",
        json_export(metrics),
        file_name=f"simulation_{cache.selected}_metrics.json",
        mime="application/json",
        key="sim_download_metrics",
        on_click="ignore",
    )


def render(client, connection, _report=None, _report_error=None):
    visuals.heading(
        "Simulation Lab",
        "Controlled feature-record generation and backend-owned inference. No packet capture or network attack traffic.",
        eyebrow="TRAINING-DERIVED · OFFLINE SIMULATION",
    )
    visuals.chips(["NF-CSE ONLY", "BOUNDED PIPELINE", "HTTP-ONLY DASHBOARD"])
    st.caption(
        "Simulation controls use NF-CSE independently of the sidebar model workspace."
    )
    cache = st.session_state.setdefault("simulation_lab", LabState())
    preferences = st.session_state.setdefault(
        "sim_poll_preferences", {"auto": True, "interval": 1000}
    )
    left, middle, right = st.columns([2, 2, 2])
    auto = left.toggle("Auto-refresh", value=preferences["auto"], key="sim_auto")
    interval = middle.selectbox(
        "Refresh interval (ms)",
        [500, 750, 1000],
        index=[500, 750, 1000].index(preferences["interval"]),
        key="sim_interval",
    )
    refresh = right.button("Refresh Lab", icon=":material/sync:", width="stretch")
    preferences.update(auto=auto, interval=interval)
    resources = _resources(client, cache, refresh)
    if right.button(
        "Prepare new simulation",
        disabled=cache.creation_uncertain,
        width="stretch",
        icon=":material/add:",
    ):
        cache.creation_armed = True
    if not client:
        st.error(
            "API configuration is unavailable. Correct CYBERGUARD_API_URL and refresh the connection."
        )
    options = [None] + [r["id"] for r in cache.runs]
    if cache.selected and cache.selected not in options:
        options.append(cache.selected)
    mapping = {r["id"]: r for r in cache.runs}
    selected = st.selectbox(
        "Simulation history",
        options,
        index=options.index(cache.selected),
        format_func=lambda value: (
            "Select an existing simulation"
            if value is None
            else f"{value[:12]} · {mapping.get(value, {}).get('config', {}).get('mode', 'cached')}"
        ),
        key=f"sim_history:{st.session_state.get('sim_selection_epoch', 0)}",
    )
    if selected != cache.selected:
        # A stale Streamlit selector after option changes must not become a URL.
        if selected is None or selected in mapping:
            cache.select(selected, mapping.get(selected))
        elif selected != cache.selected:
            cache.error = "Simulation selection changed after a backend restart. Refresh Lab and choose a current run."
            cache.blocked = True
    with st.expander("Retained simulations · last history refresh"):
        if cache.runs:
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Simulation ID": r["id"],
                            "State": r["state"],
                            "Generation": r["config"]["mode"],
                            "Seed": r["config"]["seed"],
                        }
                        for r in cache.runs
                    ]
                ),
                hide_index=True,
                width="stretch",
            )
        else:
            st.caption(
                "No retained simulations are available. Refresh Lab to update history."
            )
    st.caption(
        "Simulation history is process-local and transient. A backend restart removes IDs; cached completed results are retained locally until another run is selected."
    )
    _configuration(client, cache, resources, connection)
    if not cache.selected:
        if cache.error:
            st.warning(cache.error)
        visuals.empty_state(
            "Ready for a controlled run",
            "Create a simulation, then explicitly start it. Generation and inference run in FastAPI, independently of page navigation.",
        )
        return
    scheduled = bool(auto and client and cache.needs_poll())

    @st.fragment(run_every=interval / 1000 if scheduled else None)
    def monitor():
        was_polling = cache.needs_poll()
        if (
            client
            and not cache.blocked
            and (cache.needs_poll() or cache.metrics is None or refresh)
        ):
            cache.poll(client)
        if scheduled and (cache.blocked or not cache.needs_poll()):
            # One full rerun removes the timer once finished/error/cursor-drained.
            cache.refresh_history = not cache.blocked
            st.rerun()
        snapshot = cache.snapshot
        if cache.error:
            st.error(cache.error)
            st.caption(
                "Live polling is stopped. Cached data below is the last verified snapshot; Refresh Lab to reconnect. No action or creation request is retried automatically."
            )
        if not snapshot:
            return
        tone = (
            "ok"
            if snapshot["state"] in {"running", "completed"}
            else "off"
            if snapshot["state"] == "failed"
            else "caution"
        )
        st.html(
            '<div class="cg-sim-status">'
            + visuals.badge(snapshot["state"].upper(), tone)
            + f"<span>{visuals.text(cache.selected)}</span></div>"
        )
        if cache.blocked or cache.missing:
            valid = ()
        else:
            valid = actions(snapshot)
        if snapshot["stop_requested"] and not snapshot["finished"]:
            st.info(
                "Stopping generation and draining accepted records. Wait for finished status; this does not delete results."
            )
        columns = st.columns(max(1, len(valid)))
        for col, action in zip(columns, valid, strict=False):
            with col:
                if action == "delete":
                    confirm = st.checkbox(
                        "Confirm deletion of retained results",
                        key=f"sim_confirm_delete:{cache.selected}",
                    )
                    clicked = st.button(
                        "Delete simulation",
                        disabled=not confirm or not client,
                        key="sim_delete",
                        icon=":material/delete:",
                    )
                else:
                    clicked = st.button(
                        action.title() + " simulation",
                        disabled=not client
                        or (
                            action == "start"
                            and (
                                resources.get("model") is None
                                or resources["model"].readiness != "ready"
                            )
                        ),
                        type="primary"
                        if action in {"start", "resume"}
                        else "secondary",
                        key="sim_control_" + action,
                    )
                if clicked:
                    try:
                        cache.command(client, action)
                        if action == "delete":
                            st.session_state.sim_selection_epoch = (
                                st.session_state.get("sim_selection_epoch", 0) + 1
                            )
                        st.rerun()
                    except APIError as exc:
                        cache.error = str(exc)
                        # A transition conflict is recovered by GET, never retry POST.
                        cache.poll(client)
                        st.warning(str(exc))
        if cache.metrics:
            _kpis(cache.metrics)
            if cache.metrics["generated"] or snapshot["finished"]:
                _plots(cache)
                _explorer(cache)
            else:
                visuals.empty_state(
                    "Waiting for classified flows",
                    "Start this run explicitly. The backend will initialize profiles, generate records and publish predictions here.",
                )
            _summary_exports(cache)
        else:
            st.info("No verified metrics are available yet.")
        if not was_polling and cache.needs_poll() and auto and not scheduled:
            st.rerun()

    monitor()
