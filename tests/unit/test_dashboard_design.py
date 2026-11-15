"""Presentation regressions: escaped content, accessible charts, input parity."""

from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from cyberguard.core.schemas import ModelInfoResponse, PredictionResponse
from cyberguard.dashboard.api_client import APIClient, Connection
from cyberguard.dashboard.components import charts, visuals
from cyberguard.dashboard.theme import CLASS_COLORS

ATTACK = '"><img src=x onerror=alert(1)><script>bad()</script>&'


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attributes = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)

    def handle_data(self, data):
        self.text.append(data)


@pytest.mark.parametrize(
    "component", ["banner", "metadata", "chips", "prediction", "empty", "topbar"]
)
def test_untrusted_values_stay_text_in_visual_components(component, monkeypatch):
    output = []
    monkeypatch.setattr(visuals.st, "html", output.append)
    if component == "banner":
        visuals.banner(ATTACK, ATTACK)
    elif component == "metadata":
        visuals.metadata([(ATTACK, ATTACK)])
    elif component == "chips":
        visuals.chips([ATTACK])
    elif component == "prediction":
        visuals.prediction_card(SimpleNamespace(prediction=ATTACK, model=ATTACK))
    elif component == "empty":
        visuals.empty_state(ATTACK, ATTACK)
    else:
        visuals.topbar(ATTACK, Connection())
    parser = Elements()
    parser.feed("".join(output))
    assert not {"img", "script", "iframe"}.intersection(parser.tags)
    assert not any(name.startswith("on") for name, _ in parser.attributes)
    assert ATTACK in "".join(parser.text) or ATTACK.upper() in "".join(parser.text)


def test_badge_tone_cannot_inject_attributes():
    parser = Elements()
    parser.feed(visuals.badge(ATTACK, ATTACK))
    assert not any(name.startswith("on") for name, _ in parser.attributes)
    assert ("class", "cg-badge cg-caution") in parser.attributes
    assert ATTACK in "".join(parser.text)


def test_class_colors_and_probability_values_remain_consistent():
    probabilities = {"Normal": 0.1, "DoS": 0.2, "DDoS": 0.3, "Reconnaissance": 0.4}
    figure = charts.probabilities(probabilities)
    assert list(figure.data[0].x) == list(probabilities.values())
    assert list(figure.data[0].y) == list(probabilities)
    assert figure.data[0].orientation == "h"
    assert list(figure.data[0].marker.color) == list(CLASS_COLORS.values())
    frame = pd.DataFrame(
        {"Predicted records": [1, 2, 3, 4], "Percentage": [10, 20, 30, 40]},
        index=list(probabilities),
    )
    distribution = charts.distribution(frame)
    assert list(distribution.data[0].y) == [1, 2, 3, 4]
    assert list(distribution.data[0].marker.color) == list(CLASS_COLORS.values())


def test_theme_is_local_and_respects_reduced_motion():
    css = (Path(__file__).parents[2] / "src/cyberguard/dashboard/theme.css").read_text()
    assert "prefers-reduced-motion:reduce" in css
    assert "animation:none!important" in css
    assert "st-emotion-cache" not in css
    assert "@import" not in css and "url(" not in css


def test_redesigned_input_preserves_custom_null_and_port_tokens(monkeypatch):
    info = ModelInfoResponse(
        model="fixture",
        model_type="fixture",
        required_features=["proto", "sport", "dport"],
        supported_classes=list(CLASS_COLORS),
        probabilities_available=False,
        artifact_sha256=None,
        preprocessing_contract_version=None,
        warning="Experimental fixture",
    )
    monkeypatch.setattr(
        APIClient, "check_connection", lambda self: Connection(info, 2, live=True)
    )
    seen = []

    def predict(self, record):
        seen.append(record)
        return PredictionResponse(
            prediction="Normal", probabilities=None, model="fixture", warning=ATTACK
        )

    monkeypatch.setattr(APIClient, "predict", predict)
    app = AppTest.from_string("""
from cyberguard.dashboard.api_client import APIClient
from cyberguard.dashboard.pages import test_lab
client=APIClient()
test_lab.render(client, client.check_connection(), None, None)
""").run()
    app.selectbox[0].select("Custom").run()
    next(w for w in app.text_input if w.label == "Custom protocol").input("58")
    next(w for w in app.text_input if w.label == "Source port").input("0x50")
    next(w for w in app.text_input if w.label == "Destination port").input("-1")
    next(w for w in app.checkbox if w.label == "Protocol: JSON null").check().run()
    next(b for b in app.button if b.label == "Analyze traffic").click().run()
    assert not app.exception
    assert seen == [{"proto": None, "sport": "0x50", "dport": "-1"}]
    assert any("&lt;script&gt;" in element.proto.body for element in app.get("html"))
