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
    parser.add_argument(
        "--format",
        choices=["docx", "pdf"],
        default="docx",
        help="Report output format (default: docx)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Capture live network traffic instead of reading files",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface for live capture (e.g., en0, eth0)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Capture duration in seconds (default: 30, max: 300)",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=10000,
        help="Maximum number of packets to capture (default: 10000)",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default="",
        dest="bpf_filter",
        help="BPF filter for live capture (e.g., 'tcp port 80')",
    )
    parser.add_argument(
        "--save-pcap",
        type=str,
        default=None,
        help="Save live capture to a PCAP file",
    )

    args = parser.parse_args()

    try:
        orchestrator = ThreatAnalysisOrchestrator(
            output_dir=args.output,
            report_format=args.format,
        )

        if args.live:
            orchestrator.run_live(
                interface=args.interface,
                duration=args.duration,
                max_packets=args.max_packets,
                bpf_filter=args.bpf_filter,
                save_path=args.save_pcap,
            )
        elif args.demo:
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
