"""
Tests for scanner.core and scanner.banner modules.
"""

import socket
import threading
import time
import unittest

from scanner.banner import sanitize_banner
from scanner.core import PortScanner, ScanResult, ScanSummary


class TestBannerSanitization(unittest.TestCase):
    """Test suite for banner parsing and sanitization."""

    def test_http_banner_with_server_header(self):
        raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n"
        banner = sanitize_banner(raw)
        self.assertIn("nginx/1.24.0", banner)

    def test_ssh_banner(self):
        raw = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
        banner = sanitize_banner(raw)
        self.assertEqual(banner, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")

    def test_empty_banner(self):
        self.assertEqual(sanitize_banner(b""), "")


class TestPortScannerLive(unittest.TestCase):
    """Functional tests using a local mock TCP socket server."""

    @classmethod
    def setUpClass(cls):
        # Create an ephemeral listening socket
        cls.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.server_sock.bind(("127.0.0.1", 0))
        cls.server_sock.listen(5)
        cls.open_port = cls.server_sock.getsockname()[1]
        cls.stop_server = False

        def server_loop():
            cls.server_sock.settimeout(0.5)
            while not cls.stop_server:
                try:
                    conn, _ = cls.server_sock.accept()
                    conn.sendall(b"SSH-2.0-MockServer_1.0\r\n")
                    time.sleep(0.05)
                    conn.close()
                except (socket.timeout, OSError):
                    pass

        cls.thread = threading.Thread(target=server_loop, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.stop_server = True
        try:
            cls.server_sock.close()
        except OSError:
            pass

    def test_scan_open_port(self):
        # Find an unallocated/closed port
        closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed_sock.bind(("127.0.0.1", 0))
        closed_port = closed_sock.getsockname()[1]
        closed_sock.close()

        scanner = PortScanner(
            target_ip="127.0.0.1",
            target_host="localhost",
            ports=[self.open_port, closed_port],
            timeout=1.0,
            max_threads=2,
            grab_banners=True,
        )

        summary = scanner.run()
        self.assertEqual(summary.total_ports, 2)
        self.assertEqual(summary.open_count, 1)

        open_res = next(r for r in summary.results if r.port == self.open_port)
        self.assertEqual(open_res.state, "OPEN")
        self.assertGreater(open_res.latency_ms, 0.0)
        self.assertIsNotNone(open_res.banner)
        self.assertIn("MockServer", open_res.banner)

        closed_res = next(r for r in summary.results if r.port == closed_port)
        self.assertIn(closed_res.state, ["CLOSED", "FILTERED"])


if __name__ == "__main__":
    unittest.main()
