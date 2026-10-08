"""
Tests for scanner.parser module.
"""

import unittest
from scanner.parser import (
    InvalidPortSpecificationError,
    TargetResolutionError,
    parse_ports,
    resolve_target,
)
from scanner.services import TOP_20_PORTS, TOP_100_PORTS


class TestPortParser(unittest.TestCase):
    """Test suite for port specification parsing."""

    def test_default_ports(self):
        ports = parse_ports(None)
        self.assertEqual(len(ports), 1024)
        self.assertEqual(ports[0], 1)
        self.assertEqual(ports[-1], 1024)

    def test_single_port(self):
        ports = parse_ports("80")
        self.assertEqual(ports, [80])

    def test_port_range(self):
        ports = parse_ports("80-83")
        self.assertEqual(ports, [80, 81, 82, 83])

    def test_port_list(self):
        ports = parse_ports("22, 80, 443")
        self.assertEqual(ports, [22, 80, 443])

    def test_mixed_range_and_list(self):
        ports = parse_ports("21, 80-82, 443")
        self.assertEqual(ports, [21, 80, 81, 82, 443])

    def test_deduplication_and_sorting(self):
        ports = parse_ports("443, 80, 80, 443, 22")
        self.assertEqual(ports, [22, 80, 443])

    def test_preset_top20(self):
        ports = parse_ports("top20")
        self.assertEqual(ports, sorted(set(TOP_20_PORTS)))

    def test_preset_top100(self):
        ports = parse_ports("top100")
        self.assertEqual(ports, sorted(set(TOP_100_PORTS)))

    def test_shortcut_top_argument(self):
        ports = parse_ports(top_n=20)
        self.assertEqual(ports, sorted(set(TOP_20_PORTS)))

    def test_out_of_bounds_ports(self):
        with self.assertRaises(InvalidPortSpecificationError):
            parse_ports("0")
        with self.assertRaises(InvalidPortSpecificationError):
            parse_ports("65536")
        with self.assertRaises(InvalidPortSpecificationError):
            parse_ports("80-70000")

    def test_inverted_range(self):
        with self.assertRaises(InvalidPortSpecificationError):
            parse_ports("100-50")

    def test_malformed_string(self):
        with self.assertRaises(InvalidPortSpecificationError):
            parse_ports("abc")
        with self.assertRaises(InvalidPortSpecificationError):
            parse_ports("80-abc")


class TestTargetResolver(unittest.TestCase):
    """Test suite for target resolution."""

    def test_resolve_ipv4_literal(self):
        ip, host = resolve_target("127.0.0.1")
        self.assertEqual(ip, "127.0.0.1")

    def test_resolve_with_url_prefix(self):
        ip, host = resolve_target("http://127.0.0.1:8080/dashboard")
        self.assertEqual(ip, "127.0.0.1")

    def test_empty_target_raises_error(self):
        with self.assertRaises(TargetResolutionError):
            resolve_target("   ")

    def test_nonexistent_domain_raises_error(self):
        with self.assertRaises(TargetResolutionError):
            resolve_target("nonexistent-domain-that-does-not-exist-12345.xyz")


if __name__ == "__main__":
    unittest.main()
