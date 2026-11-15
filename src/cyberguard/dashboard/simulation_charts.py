"""Figures use only observed backend values; no made-up history or labels."""

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from cyberguard.dashboard.theme import CYAN, PURPLE, chart_theme


def series(frame, columns, y_title):
    figure = go.Figure()
    if not frame.empty:
        for (column, label), color in zip(columns, (CYAN, PURPLE), strict=False):
            figure.add_trace(
                go.Scatter(
                    x=frame.elapsed_seconds,
                    y=frame[column],
                    name=label,
                    mode="lines+markers",
                    line={"color": color, "width": 2},
                    marker={"size": 4},
                    connectgaps=False,
                )
            )
    chart_theme(figure, height=270)
    figure.update_layout(xaxis_title="Simulation elapsed seconds", yaxis_title=y_title)
    return figure


def performance(frame):
    figure = make_subplots(specs=[[{"secondary_y": True}]])
    if not frame.empty:
        figure.add_trace(
            go.Scatter(
                x=frame.elapsed_seconds,
                y=frame.queue_depth,
                name="Queue depth",
                line={"color": CYAN},
            ),
            secondary_y=False,
        )
        figure.add_trace(
            go.Scatter(
                x=frame.elapsed_seconds,
                y=frame.actual_inference_rate,
                name="Lifetime classification rate",
                line={"color": PURPLE},
            ),
            secondary_y=True,
        )
    chart_theme(figure, height=270)
    figure.update_xaxes(title="Simulation elapsed seconds")
    figure.update_yaxes(title="Queued records", secondary_y=False, rangemode="tozero")
    figure.update_yaxes(
        title="Classified / s (lifetime)", secondary_y=True, rangemode="tozero"
    )
    return figure


def profile_prediction(metrics):
    figure = go.Figure()
    for name, values, color in (
        ("Benign", [metrics["benign_profile"], metrics["predicted_benign"]], CYAN),
        ("Attack", [metrics["attack_profile"], metrics["predicted_attack"]], PURPLE),
    ):
        figure.add_trace(
            go.Bar(
                x=values,
                y=["Generated source profile", "Model prediction"],
                orientation="h",
                name=name,
                marker_color=color,
            )
        )
    chart_theme(figure, height=210)
    figure.update_layout(
        barmode="stack", xaxis_title="Records (different denominators while draining)"
    )
    return figure
