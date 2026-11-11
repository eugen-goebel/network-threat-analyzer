"""Tests for the bundled sample data: one shared timeline across PCAP, syslog and Apache."""

import random
import time
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from agents.feature_extractor import FeatureExtractor
from agents.log_parser import LogParser
from agents.pcap_parser import PcapParser

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data"

# Measured on the shipped samples: 184 of 186 syslog and 305 of 306 Apache entries
# fall inside the packet windows (the misses are entries in the first 1.7 s, before
# the first packet). A one-hour shift, the bug this guards against,
# gives 0. 95% leaves room for another seed but fails on any real misalignment.
MIN_SHARE_IN_WINDOWS = 0.95


@pytest.mark.parametrize("log_name", ["sample_syslog.log", "sample_apache.log"])
def test_sample_log_entries_fall_into_the_packet_windows(log_name):
    capture = PcapParser(max_packets=None).parse(str(SAMPLE_DIR / "sample_capture.pcap"))
    log_result = LogParser.for_capture(capture).parse(str(SAMPLE_DIR / log_name))
    matrix = FeatureExtractor(window_seconds=60).extract(capture, log_result)

    # Same window schema as the feature extractor: [start, start + window_seconds).
    starts = [datetime.fromisoformat(s) for s in matrix.window_starts]
    end = starts[-1] + timedelta(seconds=matrix.window_seconds)
    times = [datetime.fromisoformat(e.timestamp) for e in log_result.entries]
    inside = sum(1 for t in times if starts[0] <= t < end)

    assert len(times) > 100
    assert inside / len(times) >= MIN_SHARE_IN_WINDOWS


@pytest.mark.parametrize("zone", ["America/New_York", "Asia/Kolkata"])
def test_generator_output_does_not_depend_on_the_machine_time_zone(zone, tmp_path, monkeypatch):
    from data import generate_samples

    def generate(target: Path) -> dict[str, bytes]:
        target.mkdir()
        generate_samples.generate_pcap(str(target / "sample_capture.pcap"))
        generate_samples.generate_syslog(str(target / "sample_syslog.log"))
        generate_samples.generate_apache(str(target / "sample_apache.log"))
        return {p.name: p.read_bytes() for p in target.iterdir()}

    try:
        monkeypatch.setenv("TZ", "UTC")
        time.tzset()
        reference = generate(tmp_path / "reference")

        monkeypatch.setenv("TZ", zone)
        time.tzset()
        other = generate(tmp_path / "other")
    finally:
        monkeypatch.undo()
        time.tzset()

    assert other == reference


def test_generator_output_does_not_depend_on_the_global_random_state_or_call_order(tmp_path):
    # Every section has its own seeded generator. A change to one section, or a
    # different global seed or order of the files, must not move any other value.
    from data import generate_samples

    generate_samples.generate_apache(str(tmp_path / "apache_first.log"))
    generate_samples.generate_syslog(str(tmp_path / "syslog_first.log"))
    generate_samples.generate_pcap(str(tmp_path / "pcap_first.pcap"))
    rng_state = random.getstate()
    try:
        random.seed(12345)
        generate_samples.generate_pcap(str(tmp_path / "sample_capture.pcap"))
        generate_samples.generate_syslog(str(tmp_path / "sample_syslog.log"))
        generate_samples.generate_apache(str(tmp_path / "sample_apache.log"))
    finally:
        random.setstate(rng_state)

    for first, again in [
        ("pcap_first.pcap", "sample_capture.pcap"),
        ("syslog_first.log", "sample_syslog.log"),
        ("apache_first.log", "sample_apache.log"),
    ]:
        assert (tmp_path / first).read_bytes() == (tmp_path / again).read_bytes(), again
