#!/usr/bin/env python3
"""Capture, analyze, and save packets using protocol strategies."""

import argparse

from scapy.all import sniff


class PacketProcessor:
    """Define the interface shared by protocol processors."""

    def process(self, packet):
        """Process a packet in a protocol-specific way."""
        raise NotImplementedError(
            "Subclasses must implement process()"
        )


class TCPProcessor(PacketProcessor):
    """Process TCP packets."""

    def process(self, packet):
        """Display TCP addresses, ports, and flags."""
        ip_layer = packet.getlayer("IP")
        tcp_layer = packet.getlayer("TCP")

        if ip_layer is None or tcp_layer is None:
            return

        src = ip_layer.src
        dst = ip_layer.dst
        sport = tcp_layer.sport
        dport = tcp_layer.dport
        flags = tcp_layer.flags

        print(
            f"[TCP] {src}:{sport} -> {dst}:{dport} "
            f"| Flags: {flags}"
        )


class UDPProcessor(PacketProcessor):
    """Process UDP packets."""

    def process(self, packet):
        """Display UDP source and destination addresses."""
        ip_layer = packet.getlayer("IP")
        udp_layer = packet.getlayer("UDP")

        if ip_layer is None or udp_layer is None:
            return

        print(f"[UDP] {ip_layer.src} -> {ip_layer.dst}")


class ICMPProcessor(PacketProcessor):
    """Process ICMP packets."""

    def process(self, packet):
        """Display ICMP source and destination addresses."""
        ip_layer = packet.getlayer("IP")
        icmp_layer = packet.getlayer("ICMP")

        if ip_layer is None or icmp_layer is None:
            return

        print(f"[ICMP] {ip_layer.src} -> {ip_layer.dst}")


class Sniffer:
    """Capture packets and delegate processing to strategies."""

    def __init__(self, interface, filter_str, output_file):
        """Initialize capture options and protocol processors."""
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
        """Start capture and release resources when it stops."""
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
        """Save packets and delegate their protocol processing."""
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
    """Parse arguments and launch PySniffer."""
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
