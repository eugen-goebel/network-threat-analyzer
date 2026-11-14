"""Tests for the web attack rules: directory traversal and recon scanning."""

from pathlib import Path

import pytest

from agents.log_parser import LogParser
from agents.rule_engine import RuleEngine
from agents.threat_classifier import ThreatClassifier
from models.network import LogEntry, ParseResult
from rules import web_attacks

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data"

# Five known probe paths; each one is a recon hit on its own.
PROBES = ["/.env", "/wp-admin", "/phpmyadmin", "/backup.sql", "/server-status"]


@pytest.fixture
def engine():
    return RuleEngine()


@pytest.fixture
def empty_capture():
    return ParseResult(
        source_file="none.pcap",
        file_type="pcap",
        packet_count=0,
        time_range="",
        unique_src_ips=0,
        unique_dst_ips=0,
        protocol_distribution={},
        packets=[],
        flows=[],
    )


def _apache_line(ip: str, second: int, status: int, path: str, method: str = "GET") -> str:
    minute, sec = divmod(second, 60)
    return f'{ip} - - [15/Mar/2026:10:{minute:02d}:{sec:02d} +0100] "{method} {path} HTTP/1.1" {status} 10 "-" "x"\n'


def _parse(tmp_path, lines: list[str]):
    path = tmp_path / "access.log"
    path.write_text("".join(lines))
    return LogParser().parse(str(path))


def _detect(tmp_path, lines: list[str], rule_name: str | None = None):
    alerts = web_attacks.detect([], _parse(tmp_path, lines).entries)
    return [a for a in alerts if rule_name is None or a.rule_name == rule_name]


# --- directory traversal: which paths count -----------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "/../../etc/passwd",
        "/cgi-bin/../../etc/passwd",
        "/..%2f..%2fetc/shadow",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/%2E%2E/%2E%2E/ETC/PASSWD",
        # double and triple encoding
        "/..%252f..%252fetc/passwd",
        "/%252e%252e%252f%252e%252e%252fetc/passwd",
        "/%25252e%25252e/etc/passwd",
        # backslash, plain and encoded (also double)
        "/..\\..\\windows\\win.ini",
        "/..%5c..%5cwindows/win.ini",
        "/..%255c..%255cetc/passwd",
        # filter evasion: "....//" survives a filter that strips "../" once
        "/....//....//etc/passwd",
        "/....//....//app/config.php",
        "/..;/..;/etc/passwd",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/app/config.php",
        "/%c0%ae%c0%ae%c0%afapp/config.php",
        # query string
        "/download?file=../../etc/passwd",
        "/download?file=%2e%2e%2f%2e%2e%2fsecret.txt",
        "/view?page=../secret.txt",
        "/view?page=..%5csecret.txt",
        "/dl?path=etc/passwd",
        # system files without "..": the target alone is enough
        "/etc/passwd",
        "/etc/shadow",
        "/static/etc/hosts",
        "/windows/win.ini",
        "/proc/self/environ",
        # NUL byte tail cannot hide the file
        "/../../etc/passwd%00.jpg",
        # Border case, decided: it never leaves the web root, but no browser or curl
        # sends a ".." segment, so someone crafted it.
        "/docs/../index.html",
        "/images/..",
    ],
)
def test_traversal_paths_are_recognised(target):
    assert web_attacks._is_traversal(target)


@pytest.mark.parametrize(
    "target",
    [
        "/",
        "/catalog",
        "/docs/index.html",
        "/api/v1/users?id=1&sort=name",
        "/files/report..pdf",
        "/img/photo.v1.2.jpg",
        "/search?q=wait...",
        "/search?q=a..b",
        "/.well-known/acme-challenge/token",
        "/etc",
        "/blog/etc/passwd-explained",
        "/blog/etc/hosts-file-guide",
        "/etcetera/passwd",
        "/winning.ini",
        "/100%25-off",
        "/broken%zzescape",
        "/a%20b/c",
    ],
)
def test_normal_paths_are_not_traversal(target):
    assert not web_attacks._is_traversal(target)


# --- directory traversal: alerts ----------------------------------------------


def test_one_traversal_request_raises_an_alert(tmp_path):
    alerts = _detect(tmp_path, [_apache_line("10.99.88.77", 1, 403, "/../../etc/passwd")])

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_name == "directory_traversal"
    assert alert.category == "WEB_ATTACK"
    assert alert.severity == "high"
    assert alert.source_ips == ["10.99.88.77"]
    assert alert.evidence["attempts"] == 1
    assert alert.evidence["successful_responses"] == 0


def test_traversal_is_reported_for_any_status_and_counts_2xx(tmp_path):
    lines = [
        _apache_line("10.99.88.77", 1, 403, "/../../etc/passwd"),
        _apache_line("10.99.88.77", 2, 200, "/..%2f..%2fetc/shadow"),
        _apache_line("10.99.88.77", 3, 404, "/../../etc/hosts", method="POST"),
    ]
    alert = _detect(tmp_path, lines)[0]

    assert alert.evidence["attempts"] == 3
    assert alert.evidence["successful_responses"] == 1
    assert alert.evidence["status_counts"] == {"200": 1, "403": 1, "404": 1}
    assert "1 answered 2xx" in alert.description


def test_traversal_gives_one_alert_per_source_ip(tmp_path):
    lines = [
        _apache_line("10.99.88.77", 1, 403, "/../../etc/passwd"),
        _apache_line("10.99.88.77", 2, 403, "/..%2f..%2fetc/shadow"),
        _apache_line("10.99.88.78", 3, 403, "/../../etc/passwd"),
        _apache_line("192.168.1.20", 4, 200, "/docs"),
    ]
    alerts = _detect(tmp_path, lines)

    assert sorted(a.source_ips[0] for a in alerts) == ["10.99.88.77", "10.99.88.78"]
    assert {a.source_ips[0]: a.evidence["attempts"] for a in alerts} == {
        "10.99.88.77": 2,
        "10.99.88.78": 1,
    }


def test_normal_requests_raise_no_web_alert(tmp_path):
    lines = [
        _apache_line("192.168.1.10", i, status, path)
        for i, (status, path) in enumerate(
            [(200, "/"), (200, "/catalog"), (301, "/docs"), (304, "/assets/style.css")] * 10
        )
    ]
    assert _detect(tmp_path, lines) == []


def test_ssh_lines_and_malformed_messages_are_ignored():
    entries = [
        LogEntry(
            timestamp="2026-03-15T10:00:00+01:00",
            source_ip="10.99.88.77",
            message="Failed password for root from 10.99.88.77 port 22 ssh2",
            severity="high",
            service="sshd",
        ),
        LogEntry(
            timestamp="2026-03-15T10:00:01+01:00",
            source_ip="10.99.88.77",
            message="GET /../../etc/passwd",  # no arrow and status
            severity="high",
            service="httpd",
        ),
    ]
    assert web_attacks.detect([], entries) == []
    assert web_attacks.detect([], []) == []


# --- recon scanning: which paths count ----------------------------------------


@pytest.mark.parametrize(
    ("target", "normalised"),
    [
        ("/.env", "/.env"),
        ("/.env.local", "/.env.local"),
        ("/app/.env", "/app/.env"),
        ("/%2eenv", "/.env"),
        ("/.git/", "/.git"),
        ("/.git/config", "/.git/config"),
        ("/.svn/entries", "/.svn/entries"),
        ("/.DS_Store", "/.ds_store"),
        ("/.htaccess", "/.htaccess"),
        ("/wp-admin", "/wp-admin"),
        ("/WP-ADMIN/", "/wp-admin"),
        ("/wp-admin/install.php", "/wp-admin/install.php"),
        ("/wp-login.php", "/wp-login.php"),
        ("/blog/xmlrpc.php", "/blog/xmlrpc.php"),
        ("/phpmyadmin/index.php", "/phpmyadmin/index.php"),
        ("/pma", "/pma"),
        ("/admin", "/admin"),
        ("/admin/?x=1", "/admin"),
        ("/administrator", "/administrator"),
        ("/config", "/config"),
        ("/config.php", "/config.php"),
        ("/backup", "/backup"),
        ("/backup.sql", "/backup.sql"),
        ("/db/dump.sql.gz", "/db/dump.sql.gz"),
        ("/index.php.bak", "/index.php.bak"),
        ("/phpinfo.php", "/phpinfo.php"),
        ("/info.php", "/info.php"),
        ("/server-status", "/server-status"),
        ("/web.config", "/web.config"),
    ],
)
def test_recon_paths_are_recognised(target, normalised):
    assert web_attacks._recon_path(target) == normalised


@pytest.mark.parametrize(
    "target",
    [
        "/",
        "/catalog",
        "/products",
        "/contact",
        "/assets/style.css",
        "/robots.txt",
        "/sitemap.xml",
        "/wp-content/uploads/",
        "/.well-known/security.txt",
        # whole segments only, no substring or prefix match
        "/administrators-guide",
        "/admin-guide",
        "/adminer",
        "/environment",
        "/envelope.png",
        "/backups-policy",
        "/blog/sql-tips",
        "/gitlab",
        "/sqlite-vs-postgres",
        # "admin" and "config" count only at the start of the path
        "/docs/admin",
        "/api/config",
        # health checks and API docs are not in the list
        "/actuator/health",
        "/swagger.json",
        "/graphql",
    ],
)
def test_normal_paths_are_not_recon(target):
    assert web_attacks._recon_path(target) is None


# --- recon scanning: thresholds ------------------------------------------------


def _probe_lines(paths, ip="203.0.113.50", start=0, step=2, status=404):
    return [_apache_line(ip, start + i * step, status, p) for i, p in enumerate(paths)]


def test_five_distinct_probe_paths_raise_an_alert(tmp_path):
    alerts = _detect(tmp_path, _probe_lines(PROBES), "recon_scanning")

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.category == "WEB_RECON"
    assert alert.severity == "medium"
    assert alert.source_ips == ["203.0.113.50"]
    assert alert.evidence["unique_paths"] == 5
    assert alert.evidence["requests"] == 5
    assert alert.evidence["status_counts"] == {"404": 5}


def test_four_distinct_probe_paths_are_below_the_threshold(tmp_path):
    assert _detect(tmp_path, _probe_lines(PROBES[:4])) == []


def test_repeating_one_probe_path_does_not_count_as_a_scan(tmp_path):
    lines = _probe_lines(["/wp-admin"] * 100, step=0)
    assert _detect(tmp_path, lines) == []


def test_path_case_and_query_do_not_make_a_path_distinct(tmp_path):
    paths = ["/admin", "/Admin/", "/admin?a=1", "/ADMIN", "/admin?b=2", "/admin/"]
    assert _detect(tmp_path, _probe_lines(paths)) == []


def test_window_edge_is_60_seconds_inclusive(tmp_path):
    inside = _probe_lines(PROBES, step=15)  # 0, 15, 30, 45, 60
    outside = _probe_lines(PROBES[:4], step=15) + [_apache_line("203.0.113.50", 61, 404, PROBES[4])]

    assert len(_detect(tmp_path, inside, "recon_scanning")) == 1
    assert _detect(tmp_path, outside) == []


def test_a_slow_scan_stays_below_the_window(tmp_path):
    assert _detect(tmp_path, _probe_lines(PROBES, step=30)) == []


def test_a_burst_later_in_the_log_is_found(tmp_path):
    # Slow hits first, then five paths in a few seconds.
    lines = _probe_lines(PROBES[:3], step=120) + _probe_lines(
        ["/admin", "/config", "/info.php", "/pma", "/.git/HEAD"], start=500, step=1
    )
    assert len(_detect(tmp_path, lines, "recon_scanning")) == 1


def test_403_and_404_both_count_but_other_statuses_do_not(tmp_path):
    mixed = [
        _apache_line("203.0.113.50", i, s, p)
        for i, (p, s) in enumerate(zip(PROBES, [403, 404] * 3, strict=False))
    ]
    answered = _probe_lines(PROBES, status=200)
    redirected = _probe_lines(PROBES, status=301)
    four_and_one_found = _probe_lines(PROBES[:4]) + [
        _apache_line("203.0.113.50", 9, 200, PROBES[4])
    ]

    assert len(_detect(tmp_path, mixed, "recon_scanning")) == 1
    assert _detect(tmp_path, answered) == []
    assert _detect(tmp_path, redirected) == []
    assert _detect(tmp_path, four_and_one_found) == []


def test_unknown_404_paths_are_not_recon(tmp_path):
    # A crawler hitting dead links, or a broken site: many 404, none a known probe.
    paths = [f"/catalog/item-{i}" for i in range(30)] + ["/catalog", "/old-page", "/contact"]
    assert _detect(tmp_path, _probe_lines(paths, step=1)) == []


def test_recon_is_counted_per_source_ip(tmp_path):
    # Six distinct probe paths in total, but no single source reaches five.
    lines = _probe_lines(PROBES[:3], ip="203.0.113.50") + _probe_lines(
        PROBES[3:] + ["/admin"], ip="203.0.113.51"
    )
    assert _detect(tmp_path, lines) == []

    lines += _probe_lines(PROBES, ip="203.0.113.52")
    alerts = _detect(tmp_path, lines)
    assert [a.source_ips for a in alerts] == [["203.0.113.52"]]


def test_two_scanning_sources_give_two_alerts(tmp_path):
    lines = _probe_lines(PROBES, ip="203.0.113.50") + _probe_lines(PROBES, ip="203.0.113.51")
    alerts = _detect(tmp_path, lines, "recon_scanning")

    assert sorted(a.source_ips[0] for a in alerts) == ["203.0.113.50", "203.0.113.51"]


def test_traversal_requests_are_not_counted_as_recon(tmp_path):
    # "/admin/../../x" is a traversal request, reported by its own rule. It must not
    # also fill up the recon count with paths such as "/admin/..".
    paths = [
        "/admin/../../etc/hosts",
        "/config/../../a",
        "/backup/../../b",
        "/pma/../../c",
        "/.env/../..",
    ]
    alerts = _detect(tmp_path, _probe_lines(paths, ip="10.99.88.77", status=404))

    assert [a.rule_name for a in alerts] == ["directory_traversal"]


def test_one_source_can_trigger_both_rules(tmp_path):
    lines = _probe_lines(PROBES, ip="10.99.88.77") + [
        _apache_line("10.99.88.77", 20, 403, "/../../etc/passwd")
    ]
    alerts = _detect(tmp_path, lines)

    assert sorted(a.rule_name for a in alerts) == ["directory_traversal", "recon_scanning"]


# --- rule engine and classifier ------------------------------------------------


def test_engine_runs_the_web_rules_and_sorts_by_severity(engine, empty_capture, tmp_path):
    lines = _probe_lines(PROBES) + [_apache_line("10.99.88.77", 1, 403, "/../../etc/passwd")]
    alerts = engine.analyze(empty_capture, log_result=_parse(tmp_path, lines))

    assert [(a.rule_name, a.severity) for a in alerts] == [
        ("directory_traversal", "high"),
        ("recon_scanning", "medium"),
    ]


def test_engine_without_a_log_raises_no_web_alert(engine, empty_capture):
    assert engine.analyze(empty_capture, log_result=None) == []


def test_alerts_are_classified_with_category_title_and_advice(engine, empty_capture, tmp_path):
    lines = _probe_lines(PROBES) + [_apache_line("10.99.88.77", 1, 403, "/../../etc/passwd")]
    alerts = engine.analyze(empty_capture, log_result=_parse(tmp_path, lines))
    report = ThreatClassifier().classify(alerts, [], 0, "", 0.0)

    by_category = {t.category: t for t in report.threats}
    assert set(by_category) == {"WEB_ATTACK", "WEB_RECON"}

    traversal = by_category["WEB_ATTACK"]
    assert traversal.title == "Directory Traversal from 10.99.88.77"
    assert traversal.severity_label == "high"
    assert traversal.severity_score == 60
    assert traversal.source_ips == ["10.99.88.77"]
    assert traversal.detection_method == "rule"
    assert traversal.recommendations

    recon = by_category["WEB_RECON"]
    assert recon.title == "Recon Scanning from 203.0.113.50"
    assert recon.severity_label == "medium"
    assert recon.severity_score == 40
    assert recon.recommendations
    assert recon.recommendations != traversal.recommendations


def test_one_source_with_both_patterns_stays_two_threats(engine, empty_capture, tmp_path):
    # The classifier merges threats with the same category and sources. The two web
    # rules have different categories, so one source with both keeps both findings.
    lines = _probe_lines(PROBES, ip="10.99.88.77") + [
        _apache_line("10.99.88.77", 20, 403, "/../../etc/passwd")
    ]
    alerts = engine.analyze(empty_capture, log_result=_parse(tmp_path, lines))
    report = ThreatClassifier().classify(alerts, [], 0, "", 0.0)

    assert sorted(t.title for t in report.threats) == [
        "Directory Traversal from 10.99.88.77",
        "Recon Scanning from 10.99.88.77",
    ]


# --- sample data ----------------------------------------------------------------


@pytest.fixture(scope="module")
def sample_apache():
    return LogParser().parse(str(SAMPLE_DIR / "sample_apache.log"))


def test_sample_apache_log_triggers_traversal_for_the_readme_ip(sample_apache):
    alerts = web_attacks.detect([], sample_apache.entries)
    traversal = [a for a in alerts if a.rule_name == "directory_traversal"]

    assert [a.source_ips for a in traversal] == [["10.99.88.77"]]
    assert traversal[0].evidence["attempts"] == 15
    assert traversal[0].evidence["status_counts"] == {"403": 15}


def test_sample_apache_log_triggers_recon_for_the_readme_ip(sample_apache):
    alerts = web_attacks.detect([], sample_apache.entries)
    recon = [a for a in alerts if a.rule_name == "recon_scanning"]

    assert [a.source_ips for a in recon] == [["203.0.113.50"]]
    assert recon[0].evidence["unique_paths"] >= 5
    assert recon[0].evidence["status_counts"] == {"404": recon[0].evidence["requests"]}

    # The README names /wp-admin, /.env and /.git as the probes in the sample.
    probed = {
        web_attacks._recon_path(e.message.split(" ")[1])
        for e in sample_apache.entries
        if e.source_ip == "203.0.113.50"
    }
    assert {"/wp-admin", "/.env", "/.git/config"} <= probed


def test_sample_apache_normal_traffic_raises_no_web_alert(sample_apache):
    attackers = {"10.99.88.77", "203.0.113.50"}
    normal = [e for e in sample_apache.entries if e.source_ip not in attackers]

    assert len(normal) > 200
    assert web_attacks.detect([], normal) == []


def test_sample_pipeline_reports_both_web_threats(engine, empty_capture, sample_apache):
    alerts = engine.analyze(empty_capture, log_result=sample_apache)
    report = ThreatClassifier().classify(alerts, [], 0, "", 0.0)

    titles = {t.title for t in report.threats if t.category in ("WEB_ATTACK", "WEB_RECON")}
    assert titles == {
        "Directory Traversal from 10.99.88.77",
        "Recon Scanning from 203.0.113.50",
    }


def test_sample_syslog_raises_no_web_alert():
    syslog = LogParser(year=2026).parse(str(SAMPLE_DIR / "sample_syslog.log"))
    assert web_attacks.detect([], syslog.entries) == []
