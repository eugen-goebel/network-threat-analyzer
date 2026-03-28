"""Brute force detection — SSH and HTTP login attempts."""

from collections import defaultdict
from datetime import datetime, timedelta

from models.network import PacketRecord, LogEntry
from models.threats import RuleAlert


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
            alerts.append(RuleAlert(
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
            ))

    # --- HTTP brute force ---
    http_by_src: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in log_entries:
        if (
            "POST" in entry.message
            and ("login" in entry.message.lower() or "auth" in entry.message.lower())
            and entry.severity != "info"
        ):
            http_by_src[entry.source_ip].append(entry)

    for src_ip, entries in http_by_src.items():
        timestamps = [datetime.fromisoformat(e.timestamp) for e in entries]
        for count, duration in _find_bursts(timestamps, threshold=10):
            paths = list({_extract_path(e.message) for e in entries})
            alerts.append(RuleAlert(
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
            ))

    return alerts


def _extract_path(message: str) -> str:
    """Best-effort extraction of the URL path from a log message."""
    for token in message.split():
        if token.startswith("/"):
            return token.split("?")[0]
    return "/unknown"
