"""
Unit Tests for Assignment 2 — Port Scanner
"""

import unittest
from assignment2_101564963 import PortScanner, common_ports


class TestPortScanner(unittest.TestCase):

    def test_scanner_initialization(self):
        """Test that PortScanner initializes correctly."""
        # here I create a scanner with localhost
        scanner = PortScanner("127.0.0.1")

        # check if target is set correctly
        self.assertEqual(scanner.target, "127.0.0.1")

        # check if results list starts empty
        self.assertEqual(scanner.scan_results, [])

    def test_get_open_ports_filters_correctly(self):
        """Test that only open ports are returned."""
        # create scanner object
        scanner = PortScanner("127.0.0.1")

        # manually adding some fake scan results
        scanner.scan_results = [
            (22, "Open", "SSH"),
            (23, "Closed", "Telnet"),
            (80, "Open", "HTTP")
        ]

        # get only open ports
        result = scanner.get_open_ports()

        # should return only 2 open ports
        self.assertEqual(len(result), 2)

    def test_common_ports_dict(self):
        """Test that dictionary values are correct."""
        # checking if common ports map correctly
        self.assertEqual(common_ports[80], "HTTP")
        self.assertEqual(common_ports[22], "SSH")

    def test_invalid_target(self):
        """Test that empty target is rejected."""
        # create scanner with valid target
        scanner = PortScanner("127.0.0.1")

        # try to set invalid empty target
        scanner.target = ""

        # target should remain unchanged
        self.assertEqual(scanner.target, "127.0.0.1")


if __name__ == "__main__":
    unittest.main()