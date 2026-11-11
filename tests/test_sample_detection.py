"""The bundled sample capture must trigger the rules the README says it triggers."""

from pathlib import Path

import pytest

from agents.pcap_parser import PcapParser
from agents.rule_engine import RuleEngine
from rules.ddos import WINDOW_SECONDS

SAMPLE_PCAP = Path(__file__).resolve().parent.parent / "data" / "sample_capture.pcap"


@pytest.fixture(scope="module")
def sample_alerts():
    capture = PcapParser(max_packets=None).parse(str(SAMPLE_PCAP))
    return RuleEngine().analyze(capture, None)


def test_sample_capture_triggers_the_syn_flood_rule(sample_alerts):
    # The rule needs more than 100 SYN-only packets from more than 5 sources to one
    # target in one fixed 10 s window. A burst that straddles a window edge is split
    # and never reaches that, so this also guards the position of the burst.
    floods = [a for a in sample_alerts if a.rule_name == "syn_flood"]

    assert len(floods) == 1
    flood = floods[0]
    assert flood.dest_ips == ["10.0.0.1"]
    assert len(flood.source_ips) > 5
    assert all(ip.startswith("172.16.0.") for ip in flood.source_ips)
    packets = flood.evidence["packets_per_second"] * WINDOW_SECONDS
    assert packets > 100


def test_sample_capture_triggers_the_port_scan_and_beaconing_rules(sample_alerts):
    scans = [a for a in sample_alerts if a.rule_name == "vertical_port_scan"]
    assert [a.source_ips for a in scans] == [["192.168.1.100"]]

    # Only the 60 s check-in is a beacon; the port scan and the flood are bursts.
    beacons = [a for a in sample_alerts if a.rule_name == "beaconing"]
    assert [(a.source_ips, a.dest_ips) for a in beacons] == [(["192.168.1.50"], ["198.51.100.1"])]


def test_sample_syn_flood_is_not_reported_twice(sample_alerts):
    assert not [a for a in sample_alerts if a.rule_name == "http_flood"]
