"""
Core Port Scanning Engine.
Implements multi-threaded TCP connect scan, latency measurement, and result aggregation.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import errno
import socket
import time
from typing import Callable, List, Optional

from .banner import grab_banner
from .services import get_service_name


# Connection error codes indicating closed ports across platforms
# 10061 = WSAECONNREFUSED (Windows), 111 = ECONNREFUSED (Linux/macOS)
CLOSED_ERRNOS = {
    errno.ECONNREFUSED if hasattr(errno, "ECONNREFUSED") else 111,
    10061,
}

# Error codes indicating timeout / filtered ports
# 10060 = WSAETIMEDOUT (Windows), 110 = ETIMEDOUT (Linux/macOS)
TIMEOUT_ERRNOS = {
    errno.ETIMEDOUT if hasattr(errno, "ETIMEDOUT") else 110,
    10060,
}


@dataclass
class ScanResult:
    """Represents the scan outcome for a single port."""
    port: int
    state: str  # "OPEN", "CLOSED", "FILTERED"
    service: str
    latency_ms: float = 0.0
    banner: Optional[str] = None
    error_code: int = 0


@dataclass
class ScanSummary:
    """Aggregated results and performance metrics for a scan session."""
    target_host: str
    target_ip: str
    total_ports: int
    open_count: int = 0
    closed_count: int = 0
    filtered_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    results: List[ScanResult] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.end_time - self.start_time)

    @property
    def open_results(self) -> List[ScanResult]:
        return [r for r in self.results if r.state == "OPEN"]


class PortScanner:
    """
    High-performance multi-threaded TCP Port Scanner.
    Utilizes standard BSD socket 3-way handshakes to detect open services.
    """

    def __init__(
        self,
        target_ip: str,
        target_host: str,
        ports: List[int],
        timeout: float = 1.0,
        max_threads: int = 100,
        grab_banners: bool = False,
    ):
        self.target_ip = target_ip
        self.target_host = target_host
        self.ports = ports
        self.timeout = timeout
        self.max_threads = min(max_threads, max(1, len(ports)))
        self.grab_banners = grab_banners

    def scan_port(self, port: int) -> ScanResult:
        """
        Scan a single TCP port using a full 3-way handshake connect_ex attempt.
        """
        service_name = get_service_name(port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        start_time = time.perf_counter()
        try:
            sock.connect((self.target_ip, port))
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            banner = None
            if self.grab_banners:
                banner = grab_banner(self.target_ip, port, timeout=self.timeout)

            return ScanResult(
                port=port,
                state="OPEN",
                service=service_name,
                latency_ms=round(elapsed_ms, 2),
                banner=banner,
                error_code=0,
            )
        except (ConnectionRefusedError, ConnectionResetError):
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                port=port,
                state="CLOSED",
                service=service_name,
                latency_ms=round(elapsed_ms, 2),
                error_code=10061,
            )
        except (TimeoutError, socket.timeout):
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return ScanResult(
                port=port,
                state="FILTERED",
                service=service_name,
                latency_ms=round(elapsed_ms, 2),
                error_code=10060,
            )
        except OSError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            code = getattr(exc, "winerror", getattr(exc, "errno", -1))
            state = "CLOSED" if code in CLOSED_ERRNOS else "FILTERED"
            return ScanResult(
                port=port,
                state=state,
                service=service_name,
                latency_ms=round(elapsed_ms, 2),
                error_code=code,
            )
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def run(
        self,
        progress_callback: Optional[Callable[[int, int, ScanResult], None]] = None,
    ) -> ScanSummary:
        """
        Execute multi-threaded scan across all configured ports.

        Args:
            progress_callback: Optional callable (completed_count, total_count, latest_result)
        """
        summary = ScanSummary(
            target_host=self.target_host,
            target_ip=self.target_ip,
            total_ports=len(self.ports),
            start_time=time.time(),
        )

        completed = 0
        total = len(self.ports)
        results: List[ScanResult] = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port for port in self.ports
            }

            try:
                for future in as_completed(future_to_port):
                    result = future.result()
                    results.append(result)
                    completed += 1

                    if result.state == "OPEN":
                        summary.open_count += 1
                    elif result.state == "CLOSED":
                        summary.closed_count += 1
                    else:
                        summary.filtered_count += 1

                    if progress_callback:
                        progress_callback(completed, total, result)

            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

        summary.end_time = time.time()
        # Sort results by port number for consistent reporting
        summary.results = sorted(results, key=lambda r: r.port)
        return summary
