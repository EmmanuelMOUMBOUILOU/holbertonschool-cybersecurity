#!/usr/bin/env python3
"""Capture, analyze, and save network packets using protocol strategies."""

import argparse

from scapy.all import sniff


class PacketProcessor:
    """Define the common interface for packet processors."""

    def process(self, packet):
        """Process a packet using a protocol-specific implementation."""
        raise NotImplementedError(
            "Subclasses must implement the process method"
        )


class TCPProcessor(PacketProcessor):
    """Process TCP packets."""

    def process(self, packet):
        """Display TCP addresses, ports, and flags."""
        src = packet["IP"].src
        dst = packet["IP"].dst
        sport = packet["TCP"].sport
        dport = packet["TCP"].dport
        flags = packet["TCP"].flags

        print(
            f"[TCP] {src}:{sport} -> {dst}:{dport} "
            f"| Flags: {flags}"
        )


class UDPProcessor(PacketProcessor):
    """Process UDP packets."""

    def process(self, packet):
        """Display UDP source and destination addresses."""
        src = packet["IP"].src
        dst = packet["IP"].dst

        print(f"[UDP] {src} -> {dst}")


class ICMPProcessor(PacketProcessor):
    """Process ICMP packets."""

    def process(self, packet):
        """Display ICMP source and destination addresses."""
        src = packet["IP"].src
        dst = packet["IP"].dst

        print(f"[ICMP] {src} -> {dst}")


class Sniffer:
    """Manage network capture and delegate protocol processing."""

    def __init__(self, interface, filter_str, output_file):
        """Initialize capture settings and protocol processors."""
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

    def start(self):
        """Start packet capture and close resources on shutdown."""
        print("[INFO] PySniffer initialized.")

        try:
            if self.output_file:
                from scapy.utils import PcapWriter

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
                self.pcap_writer = None

    def _process_packet(self, packet):
        """Save packets and delegate processing to protocol strategies."""
        if self.pcap_writer is not None:
            self.pcap_writer.write(packet)

        if hasattr(packet, "haslayer") and packet.haslayer("IP"):
            for protocol, processor in self.processors.items():
                if packet.haslayer(protocol):
                    processor.process(packet)
                    break

        if self.verbose:
            from scapy.all import hexdump

            hexdump(packet)


def main():
    """Parse command-line arguments and start PySniffer."""
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
        help="Display hexadecimal dumps of captured packets"
    )

    args = parser.parse_args()

    sniffer = Sniffer(
        args.interface,
        args.filter,
        args.write
    )

    sniffer.verbose = args.verbose
    sniffer.start()


if __name__ == "__main__":
    main()
