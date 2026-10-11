#!/usr/bin/env python3
"""Capture, analyze, and save network packets using a Sniffer class."""

import argparse

try:
    from scapy.all import sniff
except ImportError:
    sniff = None


class Sniffer:
    """Manage network packet capture and processing."""

    def __init__(self, interface, filter_str, output_file):
        """Initialize the sniffer configuration."""
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = False
        self.pcap_writer = None

    def start(self):
        """Start packet capture and release resources on shutdown."""
        print("[INFO] PySniffer initialized.")

        try:
            if self.output_file:
                from scapy.utils import PcapWriter

                self.pcap_writer = PcapWriter(
                    self.output_file,
                    append=True,
                    sync=True
                )

            if sniff is None:
                raise ImportError(
                    "Scapy is required to capture network packets"
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
        """Save packets and display protocol and hexadecimal details."""
        if self.pcap_writer is not None:
            self.pcap_writer.write(packet)

        if hasattr(packet, "haslayer") and packet.haslayer("IP"):
            src = packet["IP"].src
            dst = packet["IP"].dst

            if packet.haslayer("TCP"):
                sport = packet["TCP"].sport
                dport = packet["TCP"].dport
                flags = packet["TCP"].flags

                print(
                    f"[TCP] {src}:{sport} -> {dst}:{dport} "
                    f"| Flags: {flags}"
                )

            elif packet.haslayer("UDP"):
                print(f"[UDP] {src} -> {dst}")

            elif packet.haslayer("ICMP"):
                print(f"[ICMP] {src} -> {dst}")

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
