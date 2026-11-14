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


# --- upload limits ----------------------------------------------------------


def test_total_upload_size_over_the_limit_gets_a_clear_message() -> None:
    # Regression: the uploader accepts several files and its limit applies per
    # file, so ten files could still add up to gigabytes.
    from types import SimpleNamespace

    from app import MAX_TOTAL_UPLOAD_MB, _upload_size_error

    mb = 1024 * 1024
    small = [SimpleNamespace(size=10 * mb), SimpleNamespace(size=10 * mb)]
    assert _upload_size_error(small) is None
    exactly = [SimpleNamespace(size=MAX_TOTAL_UPLOAD_MB * mb)]
    assert _upload_size_error(exactly) is None

    message = _upload_size_error([SimpleNamespace(size=30 * mb), SimpleNamespace(size=30 * mb)])
    assert "60.0 MB" in message
    assert f"{MAX_TOTAL_UPLOAD_MB} MB" in message


def test_oversized_upload_is_rejected_before_any_analysis() -> None:
    mb = 1024 * 1024
    blob = b"\x00" * (20 * mb)
    at = AppTest.from_file(APP, default_timeout=90).run()
    at.file_uploader[0].set_value(
        [(f"cap{i}.pcap", blob, "application/octet-stream") for i in range(3)]
    )
    at.run()

    assert not at.exception
    assert len(at.error) == 1
    assert "60.0 MB" in at.error[0].value
    assert not at.metric, "no analysis should have run"


def test_truncated_capture_shows_a_warning_next_to_the_results(monkeypatch) -> None:
    from agents import pcap_parser

    class SmallParser(pcap_parser.PcapParser):
        def __init__(self):
            super().__init__(max_packets=100)

    monkeypatch.setattr(pcap_parser, "PcapParser", SmallParser)
    sample = Path(APP).parent / "data" / "sample_capture.pcap"
    at = AppTest.from_file(APP, default_timeout=90).run()
    at.file_uploader[0].set_value(
        ("sample_capture.pcap", sample.read_bytes(), "application/octet-stream")
    )
    at.run()

    assert not at.exception
    assert any("truncated" in w.value and "100" in w.value for w in at.warning)
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Packets Analyzed"] == "100"


def test_streamlit_config_sets_the_per_file_upload_limit() -> None:
    # Regression: without .streamlit/config.toml Streamlit allows 200 MB per file.
    import tomllib

    config = Path(APP).parent / ".streamlit" / "config.toml"
    limit = tomllib.loads(config.read_text())["server"]["maxUploadSize"]
    assert 0 < limit <= 25


@pytest.mark.parametrize("name", ["../escaped.pcap", "{base}/escaped.pcap"])
def test_upload_name_cannot_write_outside_the_temp_dir(tmp_path, monkeypatch, name) -> None:
    # Regression: the file was written to os.path.join(tmpdir, uf.name), and
    # Streamlit does not sanitize that name. "../x" or an absolute path from a
    # crafted request put the upload anywhere the app may write.
    import tempfile

    base = tmp_path / "base"
    base.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(base))
    sample = Path(APP).parent / "data" / "sample_capture.pcap"

    at = AppTest.from_file(APP, default_timeout=90).run()
    at.file_uploader[0].set_value(
        (name.format(base=base), sample.read_bytes(), "application/octet-stream")
    )
    at.run()

    assert not at.exception
    assert not (base / "escaped.pcap").exists()
    assert {m.label: m.value for m in at.metric}.get("Packets Analyzed")


def _upload_pcap_and_log(log_name: str, log_bytes: bytes) -> AppTest:
    data = Path(APP).parent / "data"
    pcap = (data / "sample_capture.pcap").read_bytes()
    at = AppTest.from_file(APP, default_timeout=90).run()
    at.file_uploader[0].set_value(
        [
            ("sample_capture.pcap", pcap, "application/octet-stream"),
            (log_name, log_bytes, "text/plain"),
        ]
    )
    return at.run()


def _sample_packet_count() -> str:
    # Read from the file itself, so the tests do not break whenever the sample data changes.
    from agents.pcap_parser import PcapParser

    sample = Path(APP).parent / "data" / "sample_capture.pcap"
    return str(PcapParser(max_packets=None).parse(str(sample)).packet_count)


def test_pcap_plus_syslog_upload_analyzes_without_an_exception() -> None:
    # Regression: uploading a PCAP together with a syslog file crashed with
    # "ValueError: Invalid isoformat string: 'Mar 15 10:00:27'".
    log = (Path(APP).parent / "data" / "sample_syslog.log").read_bytes()
    at = _upload_pcap_and_log("sample_syslog.log", log)

    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Packets Analyzed"] == _sample_packet_count()


def test_pcap_plus_apache_upload_with_login_attempts_analyzes_without_an_exception() -> None:
    # Regression: the HTTP brute force rule parsed the raw Apache timestamp.
    lines = [
        f'172.16.0.9 - - [15/Mar/2026:10:00:{i:02d} +0100] "POST /api/login HTTP/1.1" 401 10 "-" "x"\n'
        for i in range(12)
    ]
    at = _upload_pcap_and_log("access.log", "".join(lines).encode())

    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Packets Analyzed"] == _sample_packet_count()


# --- anomaly score chart ------------------------------------------------------


def _anomaly_chart_rows(at: AppTest) -> list[dict]:
    """Rows behind the Anomaly Scores chart, or [] when the page has no such chart."""

    import pyarrow as pa

    for chart in at.get("vega_lite_chart"):
        proto = chart.proto
        if '"Decision"' not in proto.spec:
            continue
        table = pa.ipc.open_stream(proto.datasets[0].data.data).read_all()
        return table.to_pylist()
    return []


def _sample_run_windows() -> tuple[int, int]:
    """Window count and flagged-window count of the sample PCAP + syslog, run directly."""
    from agents.anomaly_detector import AnomalyDetector
    from agents.feature_extractor import FeatureExtractor
    from agents.log_parser import LogParser
    from agents.pcap_parser import PcapParser

    data = Path(APP).parent / "data"
    parsed = PcapParser().parse(str(data / "sample_capture.pcap"))
    log = LogParser.for_capture(parsed).parse(str(data / "sample_syslog.log"))
    matrix = FeatureExtractor().extract(parsed, log)
    result = AnomalyDetector(sensitivity=0.05).analyze(matrix)
    return len(result.windows), sum(w.flagged for w in result.windows)


def test_demo_anomaly_chart_marks_the_flagged_window(app: AppTest) -> None:
    from agents.mock_data import get_mock_anomaly_windows, get_mock_timeline

    rows = _anomaly_chart_rows(app)
    assert len(rows) == len(get_mock_timeline()) == len(get_mock_anomaly_windows())
    flagged = [r["Time"] for r in rows if r["Decision"] == "Flagged by ensemble"]
    assert flagged == ["10:03"]


def test_pcap_plus_syslog_anomaly_chart_has_every_window_and_no_altair_warning() -> None:
    # Regression: the chart only held the windows the ensemble flagged. The sample
    # PCAP + syslog flags none, so it was empty and altair warned "I don't know
    # how to infer vegalite type from 'empty'".
    import warnings

    log = (Path(APP).parent / "data" / "sample_syslog.log").read_bytes()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        at = _upload_pcap_and_log("sample_syslog.log", log)

    assert not at.exception
    assert not [w for w in caught if "vegalite type" in str(w.message)]
    assert not [i for i in at.info if "No anomaly scores" in i.value]
    rows = _anomaly_chart_rows(at)
    assert rows, "the anomaly chart has no data"
    windows, flagged = _sample_run_windows()
    assert len(rows) == windows
    assert sum(r["Decision"] == "Flagged by ensemble" for r in rows) == flagged
    assert all(0.0 <= r["Score"] <= 1.0 for r in rows)


def test_pcap_alone_marks_the_windows_detect_reports() -> None:
    # The chart marking must be the ensemble's own decision, so it has to equal
    # the alerts of detect().
    from agents.anomaly_detector import AnomalyDetector
    from agents.feature_extractor import FeatureExtractor
    from agents.pcap_parser import PcapParser

    sample = Path(APP).parent / "data" / "sample_capture.pcap"
    at = AppTest.from_file(APP, default_timeout=90).run()
    at.file_uploader[0].set_value(
        ("sample_capture.pcap", sample.read_bytes(), "application/octet-stream")
    )
    at.run()

    parsed = PcapParser().parse(str(sample))
    matrix = FeatureExtractor().extract(parsed, None)
    alerts = AnomalyDetector(sensitivity=0.05).detect(matrix)

    assert not at.exception
    rows = _anomaly_chart_rows(at)
    marked = {r["Time"]: r["Score"] for r in rows if r["Decision"] == "Flagged by ensemble"}
    assert alerts, "the sample capture alone should produce an anomaly alert"
    assert marked == {a.time_window_start: a.anomaly_score for a in alerts}


def test_capture_too_short_for_scoring_shows_a_hint_instead_of_a_chart(tmp_path) -> None:
    from scapy.all import IP, TCP, wrpcap

    packets = []
    for i in range(3):  # three one-minute windows, fewer than the models need
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
        pkt.time = 1_773_568_800 + i * 60
        packets.append(pkt)
    short = tmp_path / "short.pcap"
    wrpcap(str(short), packets)

    at = AppTest.from_file(APP, default_timeout=90).run()
    at.file_uploader[0].set_value(("short.pcap", short.read_bytes(), "application/octet-stream"))
    at.run()

    assert not at.exception
    hints = [i.value for i in at.info if "No anomaly scores" in i.value]
    assert len(hints) == 1
    assert "at least 5" in hints[0]
    assert _anomaly_chart_rows(at) == []
