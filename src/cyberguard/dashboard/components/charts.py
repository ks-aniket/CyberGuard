"""Consistent figures from supplied report counts or actual API outputs."""

import plotly.express as px
import plotly.graph_objects as go

from cyberguard.dashboard.theme import (
    CLASS_COLORS,
    CYAN,
    MODEL_COLORS,
    PURPLE,
    chart_theme,
)


def probabilities(values):
    figure = go.Figure(
        go.Bar(
            x=list(values.values()),
            y=list(values),
            orientation="h",
            marker_color=[MODEL_COLORS.get(label, CYAN) for label in values],
            text=[f"{p:.1%}" for p in values.values()],
            textposition="outside",
            cliponaxis=False,
            hovertemplate="%{y}<br>Uncalibrated probability: %{x:.4%}<extra></extra>",
        )
    )
    chart_theme(figure, height=260)
    figure.update_xaxes(
        range=[0, 1.15],
        tickvals=[0, 0.25, 0.5, 0.75, 1],
        tickformat=".0%",
        title="Uncalibrated probability",
    )
    figure.update_yaxes(autorange="reversed", title=None)
    return figure


def class_performance(report):
    frame = (
        report.per_class[["precision", "recall", "f1-score"]]
        .rename_axis("Class")
        .reset_index()
        .melt(id_vars="Class", var_name="Metric", value_name="Value")
    )
    figure = px.bar(
        frame,
        x="Value",
        y="Class",
        color="Metric",
        orientation="h",
        barmode="group",
        color_discrete_sequence=[CYAN, PURPLE, "#4776ff"],
        hover_data={"Value": ":.2%"},
    )
    chart_theme(figure, height=360)
    figure.update_xaxes(range=[0, 1], tickformat=".0%", title="Precision / recall / F1")
    figure.update_yaxes(autorange="reversed", title=None)
    return figure


def confusion(report, normalized=False):
    counts = report.confusion.to_numpy()
    values = counts / counts.sum(axis=1, keepdims=True) if normalized else counts
    text = [
        [f"{v:.1%}" if normalized else f"{int(v):,}" for v in row] for row in values
    ]
    figure = go.Figure(
        go.Heatmap(
            z=values,
            x=list(report.confusion.columns),
            y=list(report.confusion.index),
            text=text,
            texttemplate="%{text}",
            textfont={"color": "#f1f5ff", "size": 13},
            customdata=counts,
            colorscale=[[0, "#111b30"], [0.4, "#223b69"], [1, "#306ca2"]],
            xgap=3,
            ygap=3,
            colorbar={
                "thickness": 9,
                "tickformat": ".0%" if normalized else ",",
                "outlinewidth": 0,
            },
            hovertemplate="Actual: %{y}<br>Predicted: %{x}<br>Records: %{customdata:,}<extra></extra>",
        )
    )
    chart_theme(figure, height=400)
    figure.update_layout(
        xaxis_title="Predicted class",
        yaxis_title="Actual class",
        margin={"l": 12, "r": 12, "t": 15, "b": 20},
    )
    figure.update_yaxes(autorange="reversed")
    return figure


def support(report):
    frame = report.per_class.rename_axis("Class").reset_index()
    figure = px.bar(
        frame,
        x="support",
        y="Class",
        orientation="h",
        log_x=True,
        text="support",
        color="Class",
        color_discrete_map=CLASS_COLORS,
        labels={"support": "Validation records (log scale)"},
    )
    chart_theme(figure, height=330)
    figure.update_traces(
        texttemplate="%{x:,.0f}",
        textposition="outside",
        cliponaxis=False,
        hovertemplate="%{y}<br>Recorded validation rows: %{x:,}<extra></extra>",
    )
    figure.update_layout(showlegend=False, margin={"l": 12, "r": 65, "t": 15, "b": 20})
    figure.update_yaxes(
        autorange="reversed",
        title=None,
        categoryorder="array",
        categoryarray=list(report.per_class.index),
    )
    return figure


def distribution(counts):
    figure = go.Figure(
        go.Bar(
            x=list(counts.index),
            y=counts["Predicted records"],
            marker_color=[MODEL_COLORS.get(label, CYAN) for label in counts.index],
            text=[f"{count:,}" for count in counts["Predicted records"]],
            textposition="outside",
            cliponaxis=False,
            customdata=counts["Percentage"],
            hovertemplate="%{x}<br>Model assignments: %{y:,}<br>Share: %{customdata:.1f}%<extra></extra>",
        )
    )
    chart_theme(figure, height=280)
    figure.update_yaxes(
        title="Predicted records",
        rangemode="tozero",
        dtick=1 if counts["Predicted records"].max() < 10 else None,
    )
    return figure
