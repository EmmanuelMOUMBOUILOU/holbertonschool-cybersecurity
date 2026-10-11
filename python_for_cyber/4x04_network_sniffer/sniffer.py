#!/usr/bin/env python3
"""Capture, analyze, and save network packets using protocol strategies."""

import argparse

from scapy.all import sniff

try:
    from scapy.utils import PcapWriter
except ImportError:
    PcapWriter = None


class PacketProcessor:
    """Base class for network packet processors."""

    def process(self, packet):
        """Process a network packet."""
        raise NotImplementedError(
            "Subclasses must implement process()"
        )


class TCPProcessor(PacketProcessor):
    """Process TCP packets."""

    def process(self, packet):
        """Display TCP addresses, ports, and flags."""
        if not packet.haslayer("IP"):
            return

        ip = packet["IP"]
        tcp = packet["TCP"]

        print(
            f"[TCP] {ip.src}:{tcp.sport} -> "
            f"{ip.dst}:{tcp.dport} | Flags: {tcp.flags}"
        )


class UDPProcessor(PacketProcessor):
    """Process UDP packets."""

    def process(self, packet):
        """Display UDP source and destination addresses."""
        if not packet.haslayer("IP"):
            return

        ip = packet["IP"]

        print(f"[UDP] {ip.src} -> {ip.dst}")


class ICMPProcessor(PacketProcessor):
    """Process ICMP packets."""

    def process(self, packet):
        """Display ICMP source and destination addresses."""
        if not packet.haslayer("IP"):
            return

        ip = packet["IP"]

        print(f"[ICMP] {ip.src} -> {ip.dst}")


class Sniffer:
    """Capture packets and delegate processing to protocol strategies."""

    def __init__(self, interface, filter_str, output_file):
        """Initialize capture configuration and protocol processors."""
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = False
        self.pcap_writer = None

        self.processors = {
            "TCP": TCPProcessor(),
            "UDP": UDPProcessor(),
            "ICMP": ICMPProcessor()
        }

    def _process_packet(self, packet):
        """Save packets and delegate protocol processing."""
        if self.pcap_writer is not None:
            self.pcap_writer.write(packet)

        if hasattr(packet, "haslayer"):
            for protocol, processor in self.processors.items():
                if packet.haslayer(protocol):
                    processor.process(packet)
                    break

        if self.verbose:
            from scapy.all import hexdump
            hexdump(packet)

    def start(self):
        """Start packet capture and close resources on exit."""
        print("[INFO] PySniffer initialized.")

        try:
            if self.output_file:
                if PcapWriter is None:
                    raise RuntimeError(
                        "PCAP writing requires scapy.utils.PcapWriter"
                    )

                self.pcap_writer = PcapWriter(
                    self.output_file,
                    append=True,
                    sync=True
                )

            sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._process_packet,
                store=False
            )

        except KeyboardInterrupt:
            print("[INFO] Stopping capture...")

        except OSError as error:
            print(f"[ERROR] Packet capture failed: {error}")
            raise SystemExit(1)

        finally:
            if self.pcap_writer is not None:
                self.pcap_writer.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PySniffer - Network packet analyzer"
    )

    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to capture packets from"
    )

    parser.add_argument(
        "-f",
        "--filter",
        help="BPF filter expression for packet capture"
    )

    parser.add_argument(
        "--write",
        metavar="FILE",
        help="Save captured packets to a PCAP file"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Display hexadecimal packet dumps"
    )

    args = parser.parse_args()

    sniffer = Sniffer(
        args.interface,
        args.filter,
        args.write
    )

    sniffer.verbose = args.verbose
    sniffer.start()
