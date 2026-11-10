"""Log file parser — handles syslog and Apache/Nginx access log formats."""

import os
import re
from datetime import datetime, timezone

from models.network import LogEntry, LogParseResult, ParseResult

_SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[\d+\])?\s*:\s*(.*)"
)
_APACHE_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d{3})\s+(\d+)'
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SYSLOG_MONTHS = {
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
}
_SCAN_PATHS = {"/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config"}


class LogParser:
    """Parse log files into entries whose timestamps are ISO 8601 with a UTC offset.

    Downstream rules and the feature extractor compare log times with packet
    times, which are timezone-aware UTC, so every entry is normalized here.
    Lines whose timestamp cannot be read are skipped, like lines that do not
    match the format at all.
    """

    def __init__(self, year: int | None = None):
        # Syslog (RFC 3164) timestamps carry no year. Without an explicit year
        # the current UTC year is used, so pass one whenever it is known.
        self.year = year

    @classmethod
    def for_capture(cls, parse_result: ParseResult) -> "LogParser":
        """Build a parser that takes the syslog year from the first captured packet."""
        if not parse_result.packets:
            return cls()
        return cls(year=datetime.fromisoformat(parse_result.packets[0].timestamp).year)

    def parse(self, filepath: str) -> LogParseResult:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")

        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        fmt = self._detect_format(lines)
        if fmt == "syslog":
            return self._parse_syslog(lines, filepath)
        return self._parse_apache(lines, filepath)

    def _detect_format(self, lines: list[str]) -> str:
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Check syslog: starts with month abbreviation
            first_token = stripped.split()[0] if stripped.split() else ""
            if first_token in _SYSLOG_MONTHS:
                return "syslog"
            # Check apache combined
            if _APACHE_RE.match(stripped):
                return "apache"
        raise ValueError("Unsupported log format")

    def _parse_syslog(self, lines: list[str], filepath: str) -> LogParseResult:
        entries: list[LogEntry] = []

        for line in lines:
            m = _SYSLOG_RE.match(line.strip())
            if not m:
                continue

            raw_ts, hostname, service, message = m.groups()
            timestamp = self._normalize_syslog_ts(raw_ts)
            if timestamp is None:
                continue
            severity = self._syslog_severity(message)
            ip_match = _IP_RE.search(message)
            source_ip = ip_match.group(0) if ip_match else hostname

            entries.append(
                LogEntry(
                    timestamp=timestamp,
                    source_ip=source_ip,
                    message=message,
                    severity=severity,
                    service=service,
                    raw_line=line.strip(),
                )
            )

        error_entries = [e for e in entries if e.severity in ("critical", "high")]
        time_range = self._time_range(entries)

        return LogParseResult(
            source_file=filepath,
            log_format="syslog",
            entry_count=len(entries),
            time_range=time_range,
            entries=entries,
            error_entries=error_entries,
        )

    def _parse_apache(self, lines: list[str], filepath: str) -> LogParseResult:
        entries: list[LogEntry] = []

        for line in lines:
            m = _APACHE_RE.match(line.strip())
            if not m:
                continue

            ip, raw_ts, method, path, status, _bytes = m.groups()
            timestamp = self._normalize_apache_ts(raw_ts)
            if timestamp is None:
                continue
            severity = self._apache_severity(status, path)
            message = f"{method} {path} \u2192 {status}"

            entries.append(
                LogEntry(
                    timestamp=timestamp,
                    source_ip=ip,
                    message=message,
                    severity=severity,
                    service="httpd",
                    raw_line=line.strip(),
                )
            )

        error_entries = [e for e in entries if e.severity in ("critical", "high", "medium")]
        time_range = self._time_range(entries)

        return LogParseResult(
            source_file=filepath,
            log_format="apache",
            entry_count=len(entries),
            time_range=time_range,
            entries=entries,
            error_entries=error_entries,
        )

    def _normalize_syslog_ts(self, raw: str) -> str | None:
        """Turn 'Mar  5 10:00:27' into '<year>-03-05T10:00:27+00:00'.

        Syslog has no zone either, so UTC is assumed (same as the packet times).
        The year goes into the string before parsing: strptime without a year
        defaults to 1900 and warns about Feb 29 on Python 3.13+.
        """
        year = self.year if self.year is not None else datetime.now(timezone.utc).year
        try:
            parsed = datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        return parsed.replace(tzinfo=timezone.utc).isoformat()

    @staticmethod
    def _normalize_apache_ts(raw: str) -> str | None:
        """Turn '15/Mar/2026:10:00:00 +0100' into '2026-03-15T10:00:00+01:00'."""
        try:
            return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").isoformat()
        except ValueError:
            return None

    @staticmethod
    def _syslog_severity(message: str) -> str:
        lower = message.lower()
        if "segfault" in lower or "kernel panic" in lower:
            return "critical"
        if "failed password" in lower or "authentication failure" in lower:
            return "high"
        if "error" in lower:
            return "medium"
        if "warning" in lower:
            return "low"
        return "info"

    @staticmethod
    def _apache_severity(status: str, path: str) -> str:
        if ".." in path or "etc/passwd" in path or "etc/shadow" in path:
            return "high"
        if status.startswith("5"):
            return "medium"
        if status in ("403", "404"):
            for scan in _SCAN_PATHS:
                if scan in path:
                    return "low"
        return "info"

    @staticmethod
    def _time_range(entries: list[LogEntry]) -> str:
        if not entries:
            return ""
        return f"{entries[0].timestamp} \u2013 {entries[-1].timestamp}"
