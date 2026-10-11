#!/usr/bin/env python3
"""Unit tests for PySniffer."""

import io
import unittest
from contextlib import redirect_stdout

from scapy.all import IP, TCP, UDP, ICMP

from sniffer import (
    PacketProcessor,
    TCPProcessor,
    UDPProcessor,
    ICMPProcessor,
    Sniffer
)


class TestPacketProcessor(unittest.TestCase):
    """Test the base packet processor."""

    def test_process_not_implemented(self):
        """Check that the base processor requires an implementation."""
        processor = PacketProcessor()

        with self.assertRaises(NotImplementedError):
            processor.process(None)


class TestTCPProcessor(unittest.TestCase):
    """Test TCP packet processing without live network traffic."""

    def setUp(self):
        """Create a TCP processor for each test."""
        self.processor = TCPProcessor()

    def test_tcp_ip_and_port(self):
        """Check that TCP processing extracts IPs and ports."""
        packet = (
            IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=12345, dport=80, flags="S")
        )

        output = io.StringIO()

        with redirect_stdout(output):
            self.processor.process(packet)

        result = output.getvalue()

        self.assertIn("1.1.1.1", result)
        self.assertIn("2.2.2.2", result)
        self.assertIn("12345", result)
        self.assertIn("80", result)
        self.assertIn("Flags:", result)

    def test_tcp_output_format(self):
        """Check the expected TCP output."""
        packet = (
            IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=12345, dport=80, flags="S")
        )

        output = io.StringIO()

        with redirect_stdout(output):
            self.processor.process(packet)

        self.assertEqual(
            output.getvalue().strip(),
            "[TCP] 1.1.1.1:12345 -> "
            "2.2.2.2:80 | Flags: S"
        )

    def test_tcp_without_ip(self):
        """Check that a TCP layer without IP is ignored."""
        packet = TCP(sport=12345, dport=80)

        output = io.StringIO()

        with redirect_stdout(output):
            self.processor.process(packet)

        self.assertEqual(output.getvalue(), "")


class TestUDPProcessor(unittest.TestCase):
    """Test UDP packet processing."""

    def test_udp_addresses(self):
        """Check that UDP processing extracts IP addresses."""
        packet = (
            IP(src="1.1.1.1", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
        )

        output = io.StringIO()

        with redirect_stdout(output):
            UDPProcessor().process(packet)

        result = output.getvalue()

        self.assertIn("[UDP]", result)
        self.assertIn("1.1.1.1", result)
        self.assertIn("8.8.8.8", result)


class TestICMPProcessor(unittest.TestCase):
    """Test ICMP packet processing."""

    def test_icmp_addresses(self):
        """Check that ICMP processing extracts IP addresses."""
        packet = (
            IP(src="1.1.1.1", dst="8.8.8.8")
            / ICMP()
        )

        output = io.StringIO()

        with redirect_stdout(output):
            ICMPProcessor().process(packet)

        result = output.getvalue()

        self.assertIn("[ICMP]", result)
        self.assertIn("1.1.1.1", result)
        self.assertIn("8.8.8.8", result)


class TestSniffer(unittest.TestCase):
    """Test the sniffer without capturing network traffic."""

    def test_initial_statistics(self):
        """Check that protocol counters start at zero."""
        sniffer = Sniffer(None, None, None)

        self.assertEqual(sniffer.stats["TCP"], 0)
        self.assertEqual(sniffer.stats["UDP"], 0)
        self.assertEqual(sniffer.stats["ICMP"], 0)

    def test_tcp_statistics(self):
        """Check that TCP packets update the TCP counter."""
        sniffer = Sniffer(None, None, None)

        packet = (
            IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(dport=80)
        )

        sniffer._update_stats(packet)

        self.assertEqual(sniffer.stats["TCP"], 1)
        self.assertEqual(sniffer.stats["UDP"], 0)
        self.assertEqual(sniffer.stats["ICMP"], 0)


if __name__ == "__main__":
    unittest.main()
