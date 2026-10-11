#!/usr/bin/env python3
"""Capture, analyze, and optionally save network packets."""

import argparse

from scapy.all import sniff


class Sniffer:
    """Network packet sniffer with filtering and PCAP support."""

    def __init__(self, interface, filter_str, output_file):
        """Initialize capture settings."""
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = False
        self.pcap_writer = None

    def _process_packet(self, packet):
        """Save and analyze a captured packet."""
        if self.pcap_writer is not None:
            self.pcap_writer.write(packet)

        if not hasattr(packet, "haslayer"):
            return

        if packet.haslayer("IP"):
            src = packet["IP"].src
            dst = packet["IP"].dst

            if packet.haslayer("TCP"):
                tcp = packet["TCP"]
                print(
                    f"[TCP] {src}:{tcp.sport} -> {dst}:{tcp.dport} "
                    f"| Flags: {tcp.flags}"
                )
            elif packet.haslayer("UDP"):
                print(f"[UDP] {src} -> {dst}")
            elif packet.haslayer("ICMP"):
                print(f"[ICMP] {src} -> {dst}")

        if self.verbose:
            from scapy.all import hexdump
            hexdump(packet)

    def start(self):
        """Start packet capture and release resources afterward."""
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PySniffer - Network packet analyzer"
    )
    parser.add_argument("-i", "--interface")
    parser.add_argument("-f", "--filter")
    parser.add_argument("--write", metavar="FILE")
    parser.add_argument(
        "-v", "--verbose", action="store_true"
    )

    args = parser.parse_args()

    sniffer = Sniffer(
        args.interface,
        args.filter,
        args.write
    )
    sniffer.verbose = args.verbose
    sniffer.start()
