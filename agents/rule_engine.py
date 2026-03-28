"""Rule engine — dispatches parsed traffic data to all detection rule modules."""

from models.network import ParseResult, LogParseResult
from models.threats import RuleAlert
from rules import port_scan, ddos, brute_force, suspicious_connections

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class RuleEngine:
    """Runs all detection rules and aggregates alerts."""

    def analyze(
        self,
        parse_result: ParseResult,
        log_result: LogParseResult | None = None,
    ) -> list[RuleAlert]:
        """Dispatch traffic data to rule modules and return sorted alerts."""
        alerts: list[RuleAlert] = []

        alerts.extend(port_scan.detect(parse_result.packets, parse_result.flows))
        alerts.extend(ddos.detect(parse_result.packets, parse_result.flows))
        alerts.extend(
            brute_force.detect(
                parse_result.packets,
                log_result.entries if log_result else [],
            )
        )
        alerts.extend(
            suspicious_connections.detect(parse_result.packets, parse_result.flows)
        )

        alerts.sort(key=lambda a: SEVERITY_ORDER.get(a.severity, 99))
        return alerts
