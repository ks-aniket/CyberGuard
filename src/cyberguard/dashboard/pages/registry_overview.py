"""Selected-model overview in the existing card vocabulary."""

import streamlit as st

from cyberguard.dashboard.components import visuals


def render(connection):
    model = connection.selected
    visuals.heading(
        "Network Intelligence Console",
        "An offline inference workspace with separate input contracts and clearly bounded evidence.",
        "MODEL REGISTRY / OFFLINE ANALYSIS",
    )
    a, b, c, d = st.columns(4)
    a.metric("Registered models", len(connection.models))
    b.metric("Ready models", sum(m.readiness == "ready" for m in connection.models))
    c.metric("API connectivity", "Connected" if connection.live else "Disconnected")
    d.metric(
        "Model readiness", "Ready" if connection.ready else "Unavailable / unverified"
    )
    with st.container(key="panel_overview_model"):
        visuals.section("Selected model", "01")
        visuals.metadata(
            [
                ("Model", model.display_name),
                ("Task", model.task),
                ("Input contract", model.input_contract_version),
                ("Input requirements", ", ".join(model.required_features)),
            ]
        )
        visuals.chips(model.classes)
        st.caption(model.description)
        visuals.banner("KNOW THE BOUNDARY", " ".join(model.limitations))
    visuals.section("Model overview", "02")
    columns = st.columns(min(2, max(1, len(connection.models))))
    for index, item in enumerate(connection.models):
        with (
            columns[index % len(columns)],
            st.container(key="panel_registry_" + item.id),
        ):
            visuals.capability(item.task.upper(), item.display_name, item.description)
            st.html(
                visuals.badge(
                    item.readiness.upper(),
                    "ok" if item.readiness == "ready" else "caution",
                )
            )
            st.caption(
                item.input_contract.get(
                    "observation_contract", ", ".join(item.required_features)
                )
            )
    st.caption(
        "Model scores cannot be directly ranked across different datasets, tasks and evaluation conditions. No live monitoring is performed."
    )
