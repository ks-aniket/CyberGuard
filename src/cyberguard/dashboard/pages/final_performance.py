"""Frozen NF-CSE evidence only, never inference on reserved records."""

from types import SimpleNamespace

import pandas as pd
import streamlit as st

from cyberguard.dashboard.components import charts, visuals


def render(connection, report, error):
    visuals.heading(
        "Model Performance",
        "Frozen final-test evidence for the selected completed-flow model; no test records are loaded or rescored.",
        "EVIDENCE EXPLORER / OFFLINE FINAL TEST",
    )
    if report is None:
        st.warning(error or "Frozen performance artifacts are unavailable.")
        fallback = (connection.selected.performance_metadata or {}).get("final_test")
        if fallback:
            st.caption(
                "Verified API metadata summary only; detailed figures are unavailable locally."
            )
            st.json(fallback)
        return
    key = "lower_false_alarm" if connection.mode == "standard" else "high_sensitivity"
    metrics = report.metrics[key]
    if metrics["threshold"] != connection.selected.threshold(connection.mode):
        st.error(
            "The saved evidence threshold does not match the selected operating mode."
        )
        return
    st.caption(
        f"{connection.selected.display_name} · {connection.mode.replace('_', ' ')} · threshold {metrics['threshold']:.17g}"
    )
    cols = st.columns(4)
    for col, title, name in zip(
        cols,
        ["Attack recall", "Benign FPR", "Precision", "F1"],
        ["recall", "benign_fpr", "precision", "f1"],
        strict=True,
    ):
        col.metric(
            title, f"{metrics[name]:.4f}" if name == "f1" else f"{metrics[name]:.5%}"
        )
    a, b = st.columns(2)
    a.metric("ROC-AUC", f"{metrics['roc_auc']:.5f}")
    b.metric("Average precision", f"{metrics['average_precision']:.5f}")
    st.caption(
        "Weighted original-record final test, group-disjoint rather than independently captured. AP is step-wise average precision, not trapezoidal PR-AUC. Scores are uncalibrated; offline evidence does not establish live detection effectiveness."
    )
    families = report.families
    focus = families[families.attack_family == "Infilteration"]
    recalls = {row["mode"]: row["recall"] for row in focus.to_dict("records")}
    if {"high_sensitivity", "lower_false_alarm"} <= set(recalls):
        visuals.banner(
            "INFILTERATION / PERSISTENT WEAKNESS",
            f"Infilteration recall is only {recalls['high_sensitivity']:.2%} in High sensitivity and {recalls['lower_false_alarm']:.2%} in Standard. Strong aggregate metrics conceal this family weakness.",
        )
    sql = families[
        (families.attack_family == "SQL Injection") & (families["mode"] == key)
    ]
    if len(sql):
        st.warning(
            f"SQL Injection has only {int(sql.iloc[0].original_records)} original test records. This tiny support cannot establish robust category detection."
        )
    visuals.banner(
        "OPERATING-POINT LIMIT",
        "High sensitivity exceeded its validation 1% benign FPR selection constraint on final test. Neither operating mode is a calibrated risk level or deployment recommendation.",
    )
    matrix = pd.DataFrame(
        metrics["confusion_matrix"],
        index=metrics["confusion_order"],
        columns=metrics["confusion_order"],
    )
    st.plotly_chart(
        charts.confusion(SimpleNamespace(confusion=matrix)),
        width="stretch",
        config={"displaylogo": False},
    )
    st.caption(
        "Actual rows / predicted columns; original-record multiplicity weights retained."
    )
    st.dataframe(families[families["mode"] == key], width="stretch", hide_index=True)
    with st.expander(
        "Frozen ROC, precision-recall and family-recall figures", expanded=False
    ):
        for name, svg in report.figures.items():
            st.caption(name.replace("_", " ").title())
            st.image(svg, width="stretch")
    st.caption(
        "Different tasks, datasets and split conditions prevent direct BoT versus NF-CSE ranking. No deployment, independent-session or calibrated-probability claim."
    )
