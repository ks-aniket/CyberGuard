"""Charts use supplied report counts or API outputs, never generated telemetry."""

import plotly.express as px
import plotly.graph_objects as go


def probabilities(values):
    figure = px.bar(
        x=list(values),
        y=list(values.values()),
        labels={"x": "Model class", "y": "Uncalibrated probability"},
        color_discrete_sequence=["#60a5fa"],
    )
    figure.update_yaxes(range=[0, 1], tickformat=".0%")
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
        x="Class",
        y="Value",
        color="Metric",
        barmode="group",
        color_discrete_sequence=["#60a5fa", "#34d399", "#c4b5fd"],
    )
    figure.update_yaxes(range=[0, 1], tickformat=".0%")
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
            textfont={"color": "white"},
            customdata=counts,
            colorscale=[[0, "#101827"], [1, "#2563eb"]],
            hovertemplate="Actual: %{y}<br>Predicted: %{x}<br>Records: %{customdata:,}<extra></extra>",
        )
    )
    figure.update_layout(xaxis_title="Predicted class", yaxis_title="Actual class")
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
        labels={"support": "Validation records (log scale)"},
        color_discrete_sequence=["#60a5fa"],
    )
    figure.update_traces(
        texttemplate="%{x:,.0f}", textposition="outside", cliponaxis=False
    )
    return figure
