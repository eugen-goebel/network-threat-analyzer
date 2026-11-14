"""Small formatting helpers shared by the dashboard and the report charts."""

from datetime import datetime


def short_time(ts: str) -> str:
    """'2026-03-15T09:03:01.675+00:00' -> '09:03:01' for axis labels; other text stays."""
    try:
        return datetime.fromisoformat(ts).strftime("%H:%M:%S")
    except ValueError:
        return ts
