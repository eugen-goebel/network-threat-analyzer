"""Tests for the log file parser agent."""

import warnings
from datetime import datetime

import pytest

from agents.log_parser import LogParser
from models.network import PacketRecord, ParseResult


@pytest.fixture
def tmp_syslog(tmp_path):
    content = (
        "Mar 15 10:00:01 server sshd[1234]: Accepted publickey for admin from 192.168.1.10 port 22 ssh2\n"
        "Mar 15 10:00:05 server CRON[5678]: (root) CMD (/usr/bin/check)\n"
        "Mar 15 10:00:10 server sshd[1235]: Failed password for root from 10.99.88.77 port 44231 ssh2\n"
        "Mar 15 10:00:11 server sshd[1235]: Failed password for root from 10.99.88.77 port 44232 ssh2\n"
        "Mar 15 10:00:15 server kernel: [42000.123] eth0: link up\n"
        "Mar 15 10:00:20 server sshd[1236]: Failed password for invalid user test from 203.0.113.50 port 22\n"
    )
    path = tmp_path / "test.log"
    path.write_text(content)
    return str(path)


@pytest.fixture
def tmp_apache_log(tmp_path):
    content = (
        '192.168.1.10 - - [15/Mar/2026:10:00:01 +0100] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0"\n'
        '192.168.1.11 - - [15/Mar/2026:10:00:02 +0100] "GET /about HTTP/1.1" 200 3210 "-" "Mozilla/5.0"\n'
        '10.99.88.77 - - [15/Mar/2026:10:00:05 +0100] "GET /../../etc/passwd HTTP/1.1" 403 199 "-" "curl/7.68"\n'
        '203.0.113.50 - - [15/Mar/2026:10:00:10 +0100] "GET /wp-admin HTTP/1.1" 404 0 "-" "Nmap"\n'
        '192.168.1.12 - - [15/Mar/2026:10:00:15 +0100] "POST /api/data HTTP/1.1" 500 0 "-" "Mozilla/5.0"\n'
    )
    path = tmp_path / "access.log"
    path.write_text(content)
    return str(path)


@pytest.fixture
def parser():
    return LogParser()


def test_parse_syslog_entry_count(parser, tmp_syslog):
    result = parser.parse(tmp_syslog)
    assert result.entry_count == 6


def test_parse_syslog_format_detection(parser, tmp_syslog):
    result = parser.parse(tmp_syslog)
    assert result.log_format == "syslog"


def test_parse_syslog_severity(parser, tmp_syslog):
    result = parser.parse(tmp_syslog)
    failed_entries = [e for e in result.entries if "Failed password" in e.message]
    assert len(failed_entries) == 3
    for entry in failed_entries:
        assert entry.severity == "high"


def test_parse_syslog_error_entries(parser, tmp_syslog):
    result = parser.parse(tmp_syslog)
    assert len(result.error_entries) == 3


def test_parse_apache_entry_count(parser, tmp_apache_log):
    result = parser.parse(tmp_apache_log)
    assert result.entry_count == 5


def test_parse_apache_format_detection(parser, tmp_apache_log):
    result = parser.parse(tmp_apache_log)
    assert result.log_format == "apache"


def test_parse_apache_severity(parser, tmp_apache_log):
    result = parser.parse(tmp_apache_log)
    traversal_entries = [e for e in result.entries if "etc/passwd" in e.message]
    assert len(traversal_entries) == 1
    assert traversal_entries[0].severity == "high"


def test_parse_file_not_found(parser):
    with pytest.raises(FileNotFoundError):
        parser.parse("/nonexistent/path/to/log.log")


# --- timestamp normalization -------------------------------------------------
# Regression: timestamps were copied raw ("Mar 15 10:00:27", "15/Mar/2026:...")
# while the rules and the feature extractor expect ISO 8601 with a timezone.


def test_syslog_timestamp_is_iso_utc_with_the_given_year(tmp_syslog):
    result = LogParser(year=2026).parse(tmp_syslog)
    assert result.entries[0].timestamp == "2026-03-15T10:00:01+00:00"
    assert result.time_range == "2026-03-15T10:00:01+00:00 \u2013 2026-03-15T10:00:20+00:00"


def test_syslog_year_is_part_of_the_result_not_the_clock(tmp_syslog):
    assert LogParser(year=2031).parse(tmp_syslog).entries[0].timestamp.startswith("2031-03-15")


def test_syslog_single_digit_day_is_padded_with_spaces(tmp_path):
    path = tmp_path / "syslog.log"
    path.write_text("Mar  5 07:08:09 server CRON[1]: (root) CMD (/usr/bin/check)\n")
    entry = LogParser(year=2026).parse(str(path)).entries[0]
    assert entry.timestamp == "2026-03-05T07:08:09+00:00"


def test_apache_timestamp_keeps_its_utc_offset(tmp_apache_log):
    result = LogParser().parse(tmp_apache_log)
    assert result.entries[0].timestamp == "2026-03-15T10:00:01+01:00"
    assert result.entries[-1].timestamp == "2026-03-15T10:00:15+01:00"


def test_every_parsed_timestamp_is_timezone_aware(parser, tmp_syslog, tmp_apache_log):
    entries = parser.parse(tmp_syslog).entries + parser.parse(tmp_apache_log).entries
    assert entries
    for entry in entries:
        assert datetime.fromisoformat(entry.timestamp).utcoffset() is not None


def test_syslog_leap_day_parses_without_a_deprecation_warning(tmp_path):
    # strptime without a year in the format warns about Feb 29 on Python 3.13+.
    path = tmp_path / "syslog.log"
    path.write_text("Feb 29 12:00:00 server CRON[1]: (root) CMD (/usr/bin/check)\n")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        entry = LogParser(year=2028).parse(str(path)).entries[0]
    assert entry.timestamp == "2028-02-29T12:00:00+00:00"


def test_lines_with_an_unreadable_timestamp_are_skipped_not_fatal(tmp_path):
    syslog = tmp_path / "syslog.log"
    syslog.write_text(
        "Mar 15 10:00:01 server CRON[1]: good line\n"
        "Mar 15 99:99:99 server CRON[1]: impossible time\n"
        "Feb 29 12:00:00 server CRON[1]: no leap day in 2026\n"
    )
    result = LogParser(year=2026).parse(str(syslog))
    assert [e.message for e in result.entries] == ["good line"]
    assert result.entry_count == 1

    apache = tmp_path / "access.log"
    apache.write_text(
        '10.0.0.1 - - [15/Mar/2026:10:00:01 +0100] "GET / HTTP/1.1" 200 1 "-" "x"\n'
        '10.0.0.2 - - [32/Mar/2026:10:00:01 +0100] "GET / HTTP/1.1" 200 1 "-" "x"\n'
    )
    result = LogParser().parse(str(apache))
    assert [e.source_ip for e in result.entries] == ["10.0.0.1"]


def _capture(first_timestamp: str | None) -> ParseResult:
    packets = []
    if first_timestamp:
        packets.append(
            PacketRecord(
                timestamp=first_timestamp,
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                src_port=1,
                dst_port=2,
                protocol="TCP",
                size=60,
            )
        )
    return ParseResult(
        source_file="x.pcap",
        file_type="pcap",
        packet_count=len(packets),
        time_range="",
        unique_src_ips=len(packets),
        unique_dst_ips=len(packets),
        protocol_distribution={},
        packets=packets,
        flows=[],
    )


def test_for_capture_takes_the_syslog_year_from_the_first_packet(tmp_syslog):
    parser = LogParser.for_capture(_capture("2031-03-15T09:00:00+00:00"))
    assert parser.year == 2031
    assert parser.parse(tmp_syslog).entries[0].timestamp == "2031-03-15T10:00:01+00:00"


def test_for_capture_without_packets_falls_back_to_the_default_year():
    assert LogParser.for_capture(_capture(None)).year is None
