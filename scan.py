#!/usr/bin/env python3
"""
TCP Port Scanner Tool - CLI Entry Point
A Python-based multi-threaded TCP network reconnaissance and service discovery tool.

Usage:
    py scan.py <target> [options]

Examples:
    py scan.py 127.0.0.1 -p 80,443,8080
    py scan.py localhost --top 20 -b
    py scan.py scanme.nmap.org -p 1-1024 -w 150 --json report.json
"""

import argparse
import sys
import os

# Ensure package imports work regardless of current directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.core import PortScanner
from scanner.parser import (
    InvalidPortSpecificationError,
    TargetResolutionError,
    parse_ports,
    resolve_target,
)
from scanner.reporter import (
    ConsoleReporter,
    export_csv,
    export_json,
    export_text,
)


def build_parser() -> argparse.ArgumentParser:
    """Construct command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description="TCP Port Scanner - Multi-threaded Network Reconnaissance & Service Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  py scan.py 127.0.0.1 -p 80,443,8080
  py scan.py localhost --top 20 --banner
  py scan.py 192.168.1.1 -p 1-1024 -w 150 -t 0.8
  py scan.py example.com -p common --json scan_results.json
        """,
    )

    parser.add_argument(
        "target",
        nargs="?",
        default="127.0.0.1",
        help="Target host to scan (IPv4 address or FQDN, e.g. 127.0.0.1 or example.com). Default: 127.0.0.1",
    )

    parser.add_argument(
        "--web",
        action="store_true",
        help="Launch the interactive browser Web Dashboard GUI on http://localhost:5000",
    )

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument(
        "-p",
        "--ports",
        help=(
            "Port specification: single (80), list (22,80,443), range (1-1000), "
            "or preset ('top20', 'top100', 'common', 'all'). Default: common (1-1024)"
        ),
        default=None,
    )
    port_group.add_argument(
        "--top",
        type=int,
        choices=[20, 100],
        help="Quick shortcut to scan top N most common ports (20 or 100)",
        default=None,
    )

    parser.add_argument(
        "-w",
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent worker threads (default: 100)",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Socket connection timeout in seconds (default: 1.0)",
    )

    parser.add_argument(
        "-b",
        "--banner",
        action="store_true",
        help="Enable active banner grabbing and service fingerprinting",
    )

    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Display all ports in output table (default: open ports only)",
    )

    parser.add_argument(
        "-j",
        "--json",
        metavar="FILE",
        help="Export structured scan results to a JSON file",
    )

    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Export human-readable report to a text file or CSV (.csv)",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colored output in terminal",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress banner and live progress; print only final results",
    )

    return parser


def main():
    """Main CLI execution flow."""
    parser = build_parser()
    args = parser.parse_args()

    if args.web:
        from web import start_server
        start_server(port=5000, open_browser=True)
        return

    reporter = ConsoleReporter(
        color_enabled=not args.no_color,
        quiet=args.quiet,
    )

    reporter.print_banner()

    # Step 1: Resolve target
    try:
        target_ip, target_host = resolve_target(args.target)
    except TargetResolutionError as exc:
        print(reporter.colors.red(f"\n[!] Target Error: {exc}"))
        sys.exit(1)

    # Step 2: Parse ports
    try:
        ports = parse_ports(port_arg=args.ports, top_n=args.top)
    except InvalidPortSpecificationError as exc:
        print(reporter.colors.red(f"\n[!] Port Specification Error: {exc}"))
        sys.exit(1)

    # Step 3: Print scan metadata
    reporter.print_scan_start(
        target_host=target_host,
        target_ip=target_ip,
        port_count=len(ports),
        threads=args.threads,
        timeout=args.timeout,
    )

    # Step 4: Execute scanner
    scanner = PortScanner(
        target_ip=target_ip,
        target_host=target_host,
        ports=ports,
        timeout=args.timeout,
        max_threads=args.threads,
        grab_banners=args.banner,
    )

    try:
        summary = scanner.run(progress_callback=reporter.update_progress)
    except KeyboardInterrupt:
        reporter.clear_progress()
        print(reporter.colors.yellow("\n[!] Scan interrupted by user (Ctrl+C). Terminating safely."))
        sys.exit(130)

    # Step 5: Render results
    reporter.print_results_table(summary, show_all=args.all)
    reporter.print_summary_card(summary)

    # Step 6: Export results if requested
    if args.json:
        try:
            export_json(summary, args.json)
            print(reporter.colors.green(f"[+] JSON report saved to: {args.json}"))
        except OSError as exc:
            print(reporter.colors.red(f"[!] Failed to save JSON report: {exc}"))

    if args.output:
        try:
            if args.output.lower().endswith(".csv"):
                export_csv(summary, args.output)
            else:
                export_text(summary, args.output)
            print(reporter.colors.green(f"[+] Report saved to: {args.output}"))
        except OSError as exc:
            print(reporter.colors.red(f"[!] Failed to save report: {exc}"))


if __name__ == "__main__":
    main()
