"""Brute force detection — SSH and HTTP login attempts."""

import re
from collections import defaultdict
from datetime import datetime, timedelta

from models.network import LogEntry, PacketRecord
from models.threats import RuleAlert

# Apache entries are stored as "METHOD PATH \u2192 STATUS" (see LogParser._parse_apache).
_HTTP_MESSAGE_RE = re.compile(r"^(\S+) (\S+) \u2192 (\d{3})$")
_FAILED_LOGIN_STATUSES = {"401", "403"}
# A login path has one of these as a whole word. The path is split at "/", "-", "_",
# "." and camelCase humps, so "/wp-login.php", "/api/v1/auth/login" and "/api/userLogin"
# match, while "/author" or "/authors/list" do not (a substring check on "auth" would
# hit them). Two neighbouring words are also tried joined, for "/sign-in" and "/log-in".
# "/blog/login-tips" does match: the word is there, and the POST plus 401/403 filter
# keeps such hits rare.
_LOGIN_WORDS = frozenset({"login", "signin", "logon", "auth", "authenticate", "oauth", "token"})
_PATH_WORD_SPLIT_RE = re.compile(r"[/\-_.]+|(?<=[a-z0-9])(?=[A-Z])")

# Per-IP: one source needs 10 failed logins in 60s.
_HTTP_IP_THRESHOLD = 10
# Distributed: 20 failed logins on one path in 60s from at least 3 sources. Twice the
# per-IP threshold, so a few users mistyping a password do not trigger it, and 3 sources
# so that one or two noisy IPs stay with the per-IP rule. Heuristic, not calibrated.
_HTTP_DISTRIBUTED_ATTEMPTS = 20
_HTTP_DISTRIBUTED_MIN_SOURCES = 3
_HTTP_WINDOW_SECONDS = 60


def _find_bursts(timestamps: list[datetime], threshold: int, window_seconds: int = 60):
    """Yield (count, duration) for bursts exceeding threshold within the window."""
    if len(timestamps) < threshold:
        return
    sorted_ts = sorted(timestamps)
    for i, start in enumerate(sorted_ts):
        end_limit = start + timedelta(seconds=window_seconds)
        burst = [t for t in sorted_ts[i:] if t <= end_limit]
        if len(burst) >= threshold:
            duration = (burst[-1] - burst[0]).total_seconds()
            yield len(burst), duration
            return  # one alert per source is enough


def detect(packets: list[PacketRecord], log_entries: list[LogEntry]) -> list[RuleAlert]:
    """Run brute force detection rules against log entries."""
    alerts: list[RuleAlert] = []

    if not log_entries:
        return alerts

    # --- SSH brute force ---
    ssh_by_src: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in log_entries:
        if "ssh" in entry.service.lower() and entry.severity == "high":
            ssh_by_src[entry.source_ip].append(entry)

    for src_ip, entries in ssh_by_src.items():
        timestamps = [datetime.fromisoformat(e.timestamp) for e in entries]
        for count, duration in _find_bursts(timestamps, threshold=5):
            alerts.append(
                RuleAlert(
                    rule_name="ssh_brute_force",
                    severity="high",
                    category="BRUTE_FORCE",
                    description=f"SSH brute force from {src_ip}: {count} failed attempts in {duration:.0f}s",
                    source_ips=[src_ip],
                    dest_ips=[],
                    timestamps=[e.timestamp for e in entries],
                    evidence={
                        "attack_type": "ssh",
                        "attempts": count,
                        "duration_seconds": duration,
                        "target_service": "sshd",
                    },
                )
            )

    # --- HTTP brute force ---
    # A failed login is a POST to a login/auth path answered with 401 or 403. The
    # status is read from the message, not from entry.severity: severity feeds
    # error_entries and the ML features, and 5xx (server error) is not a failed login.
    failed_logins: list[tuple[LogEntry, str]] = []
    for entry in log_entries:
        path = _failed_login_path(entry)
        if path is not None:
            failed_logins.append((entry, path))

    http_by_src: dict[str, list[LogEntry]] = defaultdict(list)
    for entry, _path in failed_logins:
        http_by_src[entry.source_ip].append(entry)

    for src_ip, entries in http_by_src.items():
        timestamps = [datetime.fromisoformat(e.timestamp) for e in entries]
        for count, _duration in _find_bursts(
            timestamps, threshold=_HTTP_IP_THRESHOLD, window_seconds=_HTTP_WINDOW_SECONDS
        ):
            paths = list({_extract_path(e.message) for e in entries})
            alerts.append(
                RuleAlert(
                    rule_name="http_brute_force",
                    severity="high",
                    category="BRUTE_FORCE",
                    description=f"HTTP login brute force from {src_ip}: {count} attempts",
                    source_ips=[src_ip],
                    dest_ips=[],
                    timestamps=[e.timestamp for e in entries],
                    evidence={
                        "attack_type": "http_login",
                        "attempts": count,
                        "paths_targeted": paths,
                    },
                )
            )

    # --- Distributed HTTP brute force ---
    # Many sources, each below the per-IP threshold, hitting the same login path.
    # The same burst can also raise per-IP alerts for sources that are loud enough;
    # both are reported on purpose (different rule_name, different source_ips).
    http_by_path: dict[str, list[LogEntry]] = defaultdict(list)
    for entry, path in failed_logins:
        http_by_path[path].append(entry)

    for path, entries in http_by_path.items():
        burst = _find_distributed_burst(entries)
        if burst is None:
            continue
        ips = sorted({e.source_ip for e in burst})
        start = datetime.fromisoformat(burst[0].timestamp)
        end = datetime.fromisoformat(burst[-1].timestamp)
        duration = (end - start).total_seconds()
        alerts.append(
            RuleAlert(
                rule_name="http_distributed_brute_force",
                severity="high",
                category="BRUTE_FORCE",
                description=(
                    f"Distributed HTTP login brute force on {path}: "
                    f"{len(burst)} failed attempts from {len(ips)} sources in {duration:.0f}s"
                ),
                source_ips=ips,
                dest_ips=[],
                timestamps=[e.timestamp for e in burst],
                evidence={
                    "attack_type": "http_login_distributed",
                    "attempts": len(burst),
                    "unique_sources": len(ips),
                    "duration_seconds": duration,
                    "paths_targeted": [path],
                },
            )
        )

    return alerts


def _failed_login_path(entry: LogEntry) -> str | None:
    """Return the path if the entry is a failed login (POST to login/auth, 401/403)."""
    match = _HTTP_MESSAGE_RE.match(entry.message)
    if match is None:
        return None
    method, target, status = match.groups()
    path = target.split("?")[0]
    if method != "POST" or status not in _FAILED_LOGIN_STATUSES:
        return None
    if not _is_login_path(path):
        return None
    return path


def _is_login_path(path: str) -> bool:
    """True if a whole word of the path, or two neighbouring words joined, is a login word."""
    words = [w.lower() for w in _PATH_WORD_SPLIT_RE.split(path) if w]
    joined = {a + b for a, b in zip(words, words[1:], strict=False)}
    return not _LOGIN_WORDS.isdisjoint(words) or not _LOGIN_WORDS.isdisjoint(joined)


def _find_distributed_burst(entries: list[LogEntry]) -> list[LogEntry] | None:
    """First window of failed logins big enough and from enough distinct sources."""
    ordered = sorted(entries, key=lambda e: datetime.fromisoformat(e.timestamp))
    times = [datetime.fromisoformat(e.timestamp) for e in ordered]
    for i, start in enumerate(times):
        end_limit = start + timedelta(seconds=_HTTP_WINDOW_SECONDS)
        burst = [e for e, t in zip(ordered[i:], times[i:], strict=True) if t <= end_limit]
        if (
            len(burst) >= _HTTP_DISTRIBUTED_ATTEMPTS
            and len({e.source_ip for e in burst}) >= _HTTP_DISTRIBUTED_MIN_SOURCES
        ):
            return burst
    return None


def _extract_path(message: str) -> str:
    """Best-effort extraction of the URL path from a log message."""
    for token in message.split():
        if token.startswith("/"):
            return token.split("?")[0]
    return "/unknown"
