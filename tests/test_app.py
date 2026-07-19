"""The Streamlit dashboard preloads the sample report and renders cleanly."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parent.parent / "app.py")


@pytest.fixture()
def app() -> AppTest:
    # The dashboard imports the scapy and scikit-learn agents and renders
    # several charts on every run, so the default timeout is too tight.
    return AppTest.from_file(APP, default_timeout=90).run()


def test_dashboard_renders(app: AppTest) -> None:
    assert not app.exception
    assert app.title[0].value == "Network Threat Analyzer"


def test_demo_report_loads_without_a_click(app: AppTest) -> None:
    # Regression: the dashboard used to open on a landing page and hide its
    # sample report behind a "Load Demo Data" button that a first-time visitor
    # can easily miss.
    assert any("Demo mode" in caption.value for caption in app.caption)
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Total Threats"] == "6"
    assert metrics["Critical"] == "2"


def test_footer_points_at_the_portfolio(app: AppTest) -> None:
    assert any("github.com/eugen-goebel" in block.value for block in app.markdown)
