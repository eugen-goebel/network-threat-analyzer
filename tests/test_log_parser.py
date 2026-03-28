"""Tests for the log file parser agent."""

import pytest

from agents.log_parser import LogParser


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
