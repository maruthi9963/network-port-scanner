"""
Reporting and Output Formatting Module.
Provides ANSI color styling, real-time progress indicators, formatted tables,
and report exporters (JSON, CSV, Plain Text).
"""

import csv
import json
import os
import sys
import time
from typing import List, Optional

from .core import ScanResult, ScanSummary


# Initialize Windows ANSI color support if on Windows
def _enable_windows_vt_mode():
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            # STD_OUTPUT_HANDLE = -11
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


_enable_windows_vt_mode()


class TerminalColors:
    """ANSI color codes for formatted terminal output."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled and sys.stdout.isatty()

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, text: str) -> str:
        return self._wrap("91", text)

    def green(self, text: str) -> str:
        return self._wrap("92", text)

    def yellow(self, text: str) -> str:
        return self._wrap("93", text)

    def blue(self, text: str) -> str:
        return self._wrap("94", text)

    def magenta(self, text: str) -> str:
        return self._wrap("95", text)

    def cyan(self, text: str) -> str:
        return self._wrap("96", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)


BANNER_ART = r"""
  ____            _   ____                                  
 |  _ \ ___  _ __| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __ 
 | |_) / _ \| '__| __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/ (_) | |  | |_ ___) | (_| (_| | | | | | | |  __/ |   
 |_|   \___/|_|   \__|____/ \___\__,_|_| |_|_| |_|\___|_|   
          Python Socket Reconnaissance & Port Scanner v1.0
"""


class ConsoleReporter:
    """Manages CLI visual representation and scan progress rendering."""

    def __init__(self, color_enabled: bool = True, quiet: bool = False):
        self.colors = TerminalColors(enabled=color_enabled)
        self.quiet = quiet
        self._last_progress_len = 0

    def print_banner(self):
        """Display tool banner and legal disclaimer."""
        if self.quiet:
            return
        print(self.colors.cyan(BANNER_ART))
        print(self.colors.dim("=" * 68))
        print(self.colors.yellow("  [*] Legal Notice: Only scan targets you are authorized to test."))
        print(self.colors.dim("=" * 68))
        print()

    def print_scan_start(
        self,
        target_host: str,
        target_ip: str,
        port_count: int,
        threads: int,
        timeout: float,
    ):
        """Display initial scan parameters."""
        if self.quiet:
            return
        print(f"{self.colors.bold('Target Host:')}   {self.colors.cyan(target_host)}")
        print(f"{self.colors.bold('Target IPv4:')}   {self.colors.cyan(target_ip)}")
        print(f"{self.colors.bold('Ports to Scan:')} {self.colors.bold(str(port_count))} ports")
        print(f"{self.colors.bold('Concurrency:')}   {threads} worker threads (timeout: {timeout}s)")
        print(f"{self.colors.bold('Started At:')}    {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(self.colors.dim("-" * 68))
        print()

    def update_progress(self, completed: int, total: int, latest: ScanResult):
        """Render single-line animated progress bar."""
        if self.quiet or not sys.stdout.isatty():
            return

        percent = (completed / total) * 100 if total > 0 else 100
        bar_length = 25
        filled_length = int(bar_length * completed // total) if total > 0 else bar_length
        bar = "█" * filled_length + "░" * (bar_length - filled_length)

        status_text = (
            f"\r[Scanning] [{bar}] {percent:5.1f}% ({completed}/{total}) "
            f"| Port {latest.port:<5} -> "
        )
        if latest.state == "OPEN":
            status_text += self.colors.green("OPEN ")
        elif latest.state == "CLOSED":
            status_text += self.colors.dim("CLOSED")
        else:
            status_text += self.colors.yellow("FILTERED")

        # Clear remnants from previous line if any
        pad = max(0, self._last_progress_len - len(status_text))
        sys.stdout.write(status_text + (" " * pad))
        sys.stdout.flush()
        self._last_progress_len = len(status_text)

    def clear_progress(self):
        """Clear progress line before printing final summary."""
        if sys.stdout.isatty() and not self.quiet:
            sys.stdout.write("\r" + " " * (self._last_progress_len + 10) + "\r")
            sys.stdout.flush()

    def print_results_table(self, summary: ScanSummary, show_all: bool = False):
        """Print a structured, aligned table of open or all ports."""
        self.clear_progress()

        results_to_display = (
            summary.results if show_all else summary.open_results
        )

        if not results_to_display:
            print(self.colors.yellow("\n  [!] No open ports identified in the specified range."))
            return

        print()
        header = f"{'PORT':<10} {'STATE':<12} {'SERVICE':<32} {'LATENCY':<12}"
        has_banners = any(r.banner for r in results_to_display)
        if has_banners:
            header += f" {'BANNER / VERSION'}"

        print(self.colors.bold(header))
        print(self.colors.dim("-" * (len(header) + (25 if has_banners else 0))))

        for r in results_to_display:
            port_str = f"{r.port}/tcp"
            
            if r.state == "OPEN":
                state_str = self.colors.green(f"{r.state:<12}")
            elif r.state == "CLOSED":
                state_str = self.colors.dim(f"{r.state:<12}")
            else:
                state_str = self.colors.yellow(f"{r.state:<12}")

            service_str = f"{r.service:<32}"
            latency_str = f"{r.latency_ms:6.2f} ms"

            line = f"{port_str:<10} {state_str} {service_str} {latency_str:<12}"
            if has_banners:
                banner_str = self.colors.cyan(r.banner or "-")
                line += f" {banner_str}"

            print(line)

    def print_summary_card(self, summary: ScanSummary):
        """Display final statistics and scan duration."""
        rate = summary.total_ports / summary.duration_seconds if summary.duration_seconds > 0 else 0
        print()
        print(self.colors.dim("=" * 68))
        print(f" {self.colors.bold('SCAN METRICS SUMMARY')}")
        print(self.colors.dim("-" * 68))
        print(f"  Target:              {summary.target_host} ({summary.target_ip})")
        print(f"  Duration:            {summary.duration_seconds:.2f} seconds")
        print(f"  Scan Speed:          {rate:.1f} ports/second")
        print(f"  Total Ports Scanned: {summary.total_ports}")
        print(f"  Open Ports Found:    {self.colors.green(str(summary.open_count))}")
        print(f"  Closed Ports:        {summary.closed_count}")
        print(f"  Filtered / Dropped:  {summary.filtered_count}")
        print(self.colors.dim("=" * 68))
        print()


def export_json(summary: ScanSummary, filepath: str):
    """Serialize scan results to a structured JSON file."""
    data = {
        "target": {
            "host": summary.target_host,
            "ip": summary.target_ip,
        },
        "metrics": {
            "total_ports": summary.total_ports,
            "open_count": summary.open_count,
            "closed_count": summary.closed_count,
            "filtered_count": summary.filtered_count,
            "duration_seconds": round(summary.duration_seconds, 2),
            "start_time": summary.start_time,
            "end_time": summary.end_time,
        },
        "results": [
            {
                "port": r.port,
                "protocol": "tcp",
                "state": r.state,
                "service": r.service,
                "latency_ms": r.latency_ms,
                "banner": r.banner,
            }
            for r in summary.results
        ],
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def export_csv(summary: ScanSummary, filepath: str):
    """Serialize scan results to a standard CSV file."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Port", "Protocol", "State", "Service", "Latency_ms", "Banner"])
        for r in summary.results:
            writer.writerow([r.port, "tcp", r.state, r.service, r.latency_ms, r.banner or ""])


def export_text(summary: ScanSummary, filepath: str):
    """Write human-readable scan report to a text file."""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"PORT SCAN REPORT\n")
        f.write(f"Target: {summary.target_host} ({summary.target_ip})\n")
        f.write(f"Duration: {summary.duration_seconds:.2f}s | Total Ports: {summary.total_ports}\n")
        f.write(f"Open: {summary.open_count} | Closed: {summary.closed_count} | Filtered: {summary.filtered_count}\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'PORT':<10} {'STATE':<12} {'SERVICE':<30} {'LATENCY':<12} {'BANNER'}\n")
        f.write("-" * 80 + "\n")
        for r in summary.results:
            banner = r.banner or "-"
            f.write(f"{r.port:<10} {r.state:<12} {r.service:<30} {r.latency_ms:<12.2f} {banner}\n")
