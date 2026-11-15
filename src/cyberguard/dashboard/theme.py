"""One visual vocabulary for native Streamlit layouts and Plotly figures."""

from pathlib import Path

import streamlit as st

CLASS_COLORS = {
    "Normal": "#26dfb5",
    "DoS": "#ffb454",
    "DDoS": "#ff617b",
    "Reconnaissance": "#b89bff",
}
CYAN = "#38def5"
PURPLE = "#b89bff"
TEXT = "#edf3ff"
MUTED = "#a4b2ca"


def apply_theme():
    # Local, static CSS only. No external fonts, JavaScript or uploaded content.
    st.html(Path(__file__).with_name("theme.css"))


def chart_theme(figure, *, height=330):
    figure.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"family": "Inter, Arial, sans-serif", "color": MUTED, "size": 12},
        margin={"l": 12, "r": 24, "t": 22, "b": 20},
        height=height,
        legend={"orientation": "h", "y": 1.15, "x": 0, "title_text": ""},
        hoverlabel={"bgcolor": "#17243a", "font_color": TEXT},
        bargap=0.32,
    )
    figure.update_xaxes(
        gridcolor="rgba(145,174,220,0.08)",
        zeroline=False,
        automargin=True,
        title_font_size=11,
    )
    figure.update_yaxes(
        gridcolor="rgba(145,174,220,0.08)",
        zeroline=False,
        automargin=True,
        title_font_size=11,
    )
    return figure
