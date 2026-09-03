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


def test_severity_metrics_add_up_to_the_total(app: AppTest) -> None:
    # Regression: only Critical and High were shown, so the header read
    # 2 + 3 against a total of 6 and the missing threats were unaccounted for.
    metrics = {m.label: m.value for m in app.metric}
    severities = ["Critical", "High", "Medium", "Low"]
    for label in severities:
        assert label in metrics, f"severity card missing: {label}"
    assert sum(int(metrics[label]) for label in severities) == int(metrics["Total Threats"])


def test_source_ip_column_is_summarised_not_truncated(app: AppTest) -> None:
    # Regression: 15 SYN-flood sources were joined into one string that the
    # table cut mid-address, which reads like a corrupted value.
    from app import _format_source_ips

    many = [f"172.16.0.{i}" for i in range(1, 16)]
    assert _format_source_ips(many) == "172.16.0.1, 172.16.0.2 +13 more"
    assert _format_source_ips(["10.0.0.1"]) == "10.0.0.1"
    assert _format_source_ips([]) == "N/A"


def test_sensitivity_slider_sits_in_the_sidebar_with_help(app: AppTest) -> None:
    # Regression: st.sidebar.slider inside `with st.sidebar.expander(...)`
    # bypassed the expander, and the bare value 0.05 carried no explanation.
    sliders = [s for s in app.sidebar.slider]
    assert len(sliders) == 1
    assert sliders[0].label == "Anomaly Sensitivity"
    assert sliders[0].help


def test_footer_points_at_the_portfolio(app: AppTest) -> None:
    assert any("github.com/eugen-goebel" in block.value for block in app.markdown)
