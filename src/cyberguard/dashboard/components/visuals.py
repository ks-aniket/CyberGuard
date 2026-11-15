"""Small escaped HTML components; native Streamlit owns all interactions."""

from html import escape

import streamlit as st

from cyberguard.dashboard.theme import CLASS_COLORS, CYAN

SHIELD = '<span class="cg-logo" aria-hidden="true"></span>'


def text(value):
    return escape(str(value), quote=True)


def badge(label, tone="ok"):
    tone = tone if tone in {"ok", "off", "caution"} else "caution"
    return f'<span class="cg-badge cg-{tone}"><span class="cg-dot" aria-hidden="true"></span>{text(label)}</span>'


def brand():
    st.html(
        f'<div class="cg-brand">{SHIELD}<div><div class="cg-brand-name">Cyber<span>Guard</span></div><div class="cg-brand-sub">THREAT INTELLIGENCE CONSOLE</div></div></div>'
    )


def topbar(page, connection):
    status = badge(
        "API ONLINE" if connection.live else "API OFFLINE",
        "ok" if connection.live else "off",
    )
    status += badge(
        "MODEL READY" if connection.ready else "MODEL UNVERIFIED",
        "ok" if connection.ready else "caution",
    )
    st.html(
        f'<div class="cg-topbar"><div class="cg-breadcrumb"><b>CYBERGUARD</b> / {text(page.upper())}</div><div class="cg-badges">{status}</div></div>'
    )


def heading(title, description, eyebrow="CLASSIFICATION WORKSPACE"):
    st.html(
        f'<div class="cg-hero"><span class="cg-hero-tag">{text(eyebrow)}</span></div>'
    )
    st.title(title)
    st.caption(description)


def section(title, number="01"):
    st.html(
        f'<div class="cg-section"><span class="cg-index">{text(number)}</span><h2>{text(title)}</h2><span class="cg-rule" aria-hidden="true"></span></div>'
    )


def metric_card(label, value, *, key, tone="cyan"):
    tone = tone if tone in {"cyan", "purple", "warning", "blue"} else "cyan"
    with st.container(key=f"metric_{tone}_{key}"):
        st.metric(label, value)


def metadata(items):
    cells = "".join(
        f"<div><dt>{text(label)}</dt><dd>{text(value)}</dd></div>"
        for label, value in items
    )
    st.html(f'<dl class="cg-meta-grid">{cells}</dl>')


def chips(values):
    st.html(
        '<div class="cg-chips">'
        + "".join(f'<span class="cg-chip">{text(value)}</span>' for value in values)
        + "</div>"
    )


def banner(title, message, *, info=False):
    style = " info" if info else ""
    st.html(
        f'<div class="cg-banner{style}" role="note"><div class="cg-banner-title">{text(title)}</div><p>{text(message)}</p></div>'
    )


def prediction_card(result):
    color = CLASS_COLORS.get(result.prediction, CYAN)
    st.html(
        f'<div class="cg-prediction" style="--cg-class-color:{color}"><span class="cg-eyebrow">PREDICTED CLASS · EXPERIMENTAL</span><strong>{text(result.prediction)}</strong><small>MODEL / {text(result.model)}</small></div>'
    )


def empty_state(title, description):
    st.html(
        f'<div class="cg-empty"><div class="cg-reticle" aria-hidden="true"></div><h3>{text(title)}</h3><p>{text(description)}</p></div>'
    )


def capability(label, title, description):
    st.html(
        f'<div class="cg-capability"><span class="cg-eyebrow">{text(label)}</span><h3>{text(title)}</h3><p>{text(description)}</p></div>'
    )


def architecture():
    nodes = [
        ("01 / INTERFACE", "Streamlit Dashboard", "Input & visual analysis"),
        ("02 / HTTP", "FastAPI Backend", "Validated request contract"),
        ("03 / INFERENCE", "Inference Service", "Shared model execution"),
        ("04 / ARTIFACT", "ML Pipeline", "Fitted preprocessing + model"),
    ]
    st.html(
        '<div class="cg-architecture" aria-label="Architecture, in request order">'
        + "".join(
            f'<div class="cg-node"><span class="cg-eyebrow">{text(index)}</span><b>{text(title)}</b><small>{text(detail)}</small></div>'
            for index, title, detail in nodes
        )
        + "</div>"
    )
