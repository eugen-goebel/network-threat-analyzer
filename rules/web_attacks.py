"""Web attack detection on Apache logs: directory traversal and recon scanning."""

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from urllib.parse import unquote_to_bytes

from models.network import LogEntry, PacketRecord
from models.threats import RuleAlert
from rules.brute_force import _HTTP_MESSAGE_RE

CATEGORY_TRAVERSAL = "WEB_ATTACK"
CATEGORY_RECON = "WEB_RECON"

# Directory traversal has no threshold: one request is enough. Browsers and curl
# resolve ".." before they send a request, so a ".." segment in a log line was crafted
# on purpose, and nobody has a legitimate reason to ask a web server for /etc/passwd.
# The rule does not look at the status: a 403 is a blocked attempt, a 200 may be a
# leak. Both are reported, the 2xx count goes into the evidence.

# Recon scanning: 5 different probe paths within 60s. One or two hits are a mistyped
# URL or a stray bot, and a person who opens /admin by hand rarely probes five known
# paths in a minute. Distinct paths count, not requests, so reloading /admin 100
# times does not trigger it. Heuristic, not calibrated; a slow scan (one path every
# 15s or more) stays below it.
_RECON_MIN_PATHS = 5
_RECON_WINDOW_SECONDS = 60
# A probe that finds something answers 200 or 3xx; the rule wants the ones that failed.
_RECON_STATUSES = {"403", "404"}

# Overlong UTF-8 forms that old servers decoded to "." "/" "\" (CVE-2001-0333 style).
_OVERLONG_UTF8 = ((b"\xc0\xae", b"."), (b"\xc0\xaf", b"/"), (b"\xc1\x9c", b"\\"))
# Enough for %252e (double) and %25252e (triple); a path that still changes after
# four rounds is not worth following.
_MAX_DECODE_ROUNDS = 4

# Paths are compared as whole segments, never as substrings: "/catalog" or
# "/admin-guide" must not look like "/admin" (same lesson as _LOGIN_WORDS).
_SEGMENT_SPLIT_RE = re.compile(r"[/?&=]")  # path and query values
_PATH_SPLIT_RE = re.compile(r"/")
_DOTS_ONLY_RE = re.compile(r"\.{2,}")
# "etc" followed by one of these, and "proc/self", are system files.
_ETC_FILES = frozenset({"passwd", "shadow", "group", "gshadow", "hosts", "sudoers"})
_SYSTEM_FILE_NAMES = frozenset({"win.ini", "boot.ini"})

# Recon names that are suspicious wherever they appear in the path.
_RECON_ANYWHERE = frozenset(
    {
        ".git",
        ".svn",
        ".hg",
        ".env",
        ".htaccess",
        ".htpasswd",
        ".ds_store",
        ".aws",
        ".ssh",
        "wp-login.php",
        "wp-config.php",
        "xmlrpc.php",
        "phpinfo.php",
        "adminer.php",
        "web.config",
    }
)
# Recon names that only count as the first segment: "/admin" is a probe, while
# "/docs/admin" or "/api/config" may be a real page.
_RECON_ROOT = frozenset(
    {
        "admin",
        "administrator",
        "wp-admin",
        "phpmyadmin",
        "pma",
        "myadmin",
        "cpanel",
        "console",
        "config",
        "config.php",
        "configuration.php",
        "backup",
        "backups",
        "server-status",
        "server-info",
        "info.php",
        "test.php",
    }
)
# Left-over files: database dumps and editor or backup copies.
_RECON_SUFFIXES = (".sql", ".sql.gz", ".bak", ".old", ".orig", ".swp")


def detect(packets: list[PacketRecord], log_entries: list[LogEntry]) -> list[RuleAlert]:
    """Run web attack rules against Apache log entries (one alert per source IP)."""
    traversal: dict[str, list[tuple[LogEntry, str, str]]] = defaultdict(list)
    recon: dict[str, list[tuple[LogEntry, str, str]]] = defaultdict(list)

    for entry in log_entries:
        match = _HTTP_MESSAGE_RE.match(entry.message)
        if match is None:
            continue
        _method, target, status = match.groups()
        if _is_traversal(target):
            traversal[entry.source_ip].append((entry, target, status))
        elif status in _RECON_STATUSES:
            # A traversal request is reported by its own rule, not counted twice.
            path = _recon_path(target)
            if path is not None:
                recon[entry.source_ip].append((entry, path, status))

    alerts: list[RuleAlert] = []
    for src_ip, hits in traversal.items():
        alerts.append(_traversal_alert(src_ip, hits))
    for src_ip, hits in recon.items():
        if _has_recon_burst(hits):
            alerts.append(_recon_alert(src_ip, hits))
    return alerts


def _decode(target: str) -> str:
    """Percent-decode (repeatedly, for double encoding), lowercase, and use '/' only."""
    data = target.encode("utf-8")
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote_to_bytes(data)
        if decoded == data:
            break
        data = decoded
    for overlong, plain in _OVERLONG_UTF8:
        data = data.replace(overlong, plain)
    return data.decode("utf-8", errors="replace").lower().replace("\\", "/")


def _segments(text: str, splitter: re.Pattern[str]) -> list[str]:
    """Split into non-empty segments; ';params' and anything after a NUL byte are cut off."""
    segments = []
    for part in splitter.split(text):
        part = part.split("\x00", 1)[0].split(";", 1)[0]
        if part:
            segments.append(part)
    return segments


def _is_traversal(target: str) -> bool:
    """True if the decoded path or query has a '..' segment or names a system file.

    The query counts too: "/download?file=../../etc/passwd" is the common form.
    Runs of three or more dots are included, for "....//" which beats filters that
    strip "../" once. "/docs/../index.html" counts as well: it stays inside the web
    root, but no real client sends it, so it is still a crafted request.
    """
    segments = _segments(_decode(target), _SEGMENT_SPLIT_RE)
    for i, segment in enumerate(segments):
        nxt = segments[i + 1] if i + 1 < len(segments) else ""
        if (
            _DOTS_ONLY_RE.fullmatch(segment)
            or segment in _SYSTEM_FILE_NAMES
            or (segment == "etc" and nxt in _ETC_FILES)
            or (segment == "proc" and nxt == "self")
        ):
            return True
    return False


def _recon_path(target: str) -> str | None:
    """Return the normalised path (no query, lowercase, decoded) if it is a known probe."""
    path = _decode(target.split("?", 1)[0])
    segments = _segments(path, _PATH_SPLIT_RE)
    if not segments:
        return None
    last = segments[-1]
    if (
        any(s in _RECON_ANYWHERE or s.startswith(".env.") for s in segments)
        or segments[0] in _RECON_ROOT
        or last.endswith(_RECON_SUFFIXES)
    ):
        return "/" + "/".join(segments)
    return None


def _has_recon_burst(hits: list[tuple[LogEntry, str, str]]) -> bool:
    """True if some 60s window holds at least _RECON_MIN_PATHS distinct probe paths."""
    timed = sorted((datetime.fromisoformat(e.timestamp), path) for e, path, _s in hits)
    window = timedelta(seconds=_RECON_WINDOW_SECONDS)
    in_window: Counter[str] = Counter()
    left = 0
    for when, path in timed:
        in_window[path] += 1
        while when - timed[left][0] > window:
            in_window[timed[left][1]] -= 1
            if in_window[timed[left][1]] == 0:
                del in_window[timed[left][1]]
            left += 1
        if len(in_window) >= _RECON_MIN_PATHS:
            return True
    return False


def _traversal_alert(src_ip: str, hits: list[tuple[LogEntry, str, str]]) -> RuleAlert:
    hits = sorted(hits, key=lambda h: datetime.fromisoformat(h[0].timestamp))
    statuses = Counter(status for _e, _t, status in hits)
    successful = sum(n for status, n in statuses.items() if status.startswith("2"))
    paths = list(dict.fromkeys(target for _e, target, _s in hits))
    description = f"Directory traversal from {src_ip}: {len(hits)} request(s)"
    if successful:
        description += f", {successful} answered 2xx"
    return RuleAlert(
        rule_name="directory_traversal",
        # A direct exploitation attempt, so high. Not critical: the log cannot show
        # that a file was read (a 200 can also be a catch-all error page).
        severity="high",
        category=CATEGORY_TRAVERSAL,
        description=description,
        source_ips=[src_ip],
        dest_ips=[],
        timestamps=[e.timestamp for e, _t, _s in hits],
        evidence={
            "attack_type": "directory_traversal",
            "attempts": len(hits),
            "unique_paths": len(paths),
            "successful_responses": successful,
            "status_counts": dict(sorted(statuses.items())),
            "paths_targeted": paths[:20],
        },
    )


def _recon_alert(src_ip: str, hits: list[tuple[LogEntry, str, str]]) -> RuleAlert:
    hits = sorted(hits, key=lambda h: datetime.fromisoformat(h[0].timestamp))
    paths = sorted({path for _e, path, _s in hits})
    statuses = Counter(status for _e, _p, status in hits)
    start = datetime.fromisoformat(hits[0][0].timestamp)
    end = datetime.fromisoformat(hits[-1][0].timestamp)
    duration = (end - start).total_seconds()
    return RuleAlert(
        rule_name="recon_scanning",
        # Probing, not an attack: every probe failed (403/404), so medium.
        severity="medium",
        category=CATEGORY_RECON,
        description=(
            f"Recon scanning from {src_ip}: {len(paths)} known probe paths "
            f"in {len(hits)} requests over {duration:.0f}s"
        ),
        source_ips=[src_ip],
        dest_ips=[],
        timestamps=[e.timestamp for e, _p, _s in hits],
        evidence={
            "attack_type": "recon_scan",
            "requests": len(hits),
            "unique_paths": len(paths),
            "duration_seconds": duration,
            "status_counts": dict(sorted(statuses.items())),
            "paths_targeted": paths[:20],
        },
    )
