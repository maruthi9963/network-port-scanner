"""
Tests for scanner.services module.
"""

import unittest
from scanner.services import KNOWN_SERVICES, TOP_20_PORTS, TOP_100_PORTS, get_service_name


class TestServices(unittest.TestCase):
    """Test suite for service identification."""

    def test_known_services_lookup(self):
        self.assertIn("HTTP", get_service_name(80))
        self.assertIn("HTTPS", get_service_name(443))
        self.assertIn("SSH", get_service_name(22))
        self.assertIn("MySQL", get_service_name(3306))
        self.assertIn("Redis", get_service_name(6379))
        self.assertIn("PostgreSQL", get_service_name(5432))

    def test_unknown_port_fallback(self):
        # Port 65432 is typically unassigned
        service = get_service_name(65432)
        self.assertIsInstance(service, str)
        self.assertTrue(len(service) > 0)

    def test_top_ports_validity(self):
        self.assertEqual(len(TOP_20_PORTS), 20)
        self.assertEqual(len(TOP_100_PORTS), 100)
        for port in TOP_20_PORTS + TOP_100_PORTS:
            self.assertGreaterEqual(port, 1)
            self.assertLessEqual(port, 65535)


if __name__ == "__main__":
    unittest.main()
