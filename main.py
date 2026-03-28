"""Network Threat Analyzer — detect port scans, DDoS attacks, brute force, and anomalous traffic."""

import argparse
import sys
import os

from dotenv import load_dotenv

load_dotenv()

from agents.orchestrator import ThreatAnalysisOrchestrator

BANNER = """
╔══════════════════════════════════════╗
║      NETWORK THREAT ANALYZER         ║
║  Multi-agent threat detection pipeline║
╚══════════════════════════════════════╝
"""


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Network Threat Analyzer — multi-agent threat detection pipeline",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="PCAP or log files to analyze",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run with sample data",
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Output directory",
    )

    args = parser.parse_args()

    try:
        orchestrator = ThreatAnalysisOrchestrator(output_dir=args.output)

        if args.demo:
            orchestrator.run_demo()
        elif args.files:
            orchestrator.run(args.files)
        else:
            parser.print_help()

    except FileNotFoundError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
