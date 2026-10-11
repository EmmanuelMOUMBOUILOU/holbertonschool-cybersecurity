#!/usr/bin/env python3
"""Capture, filter, analyze, and save network packets using Scapy."""

import argparse

from scapy.all import sniff


pcap_writer = None
verbose = False


def packet_handler(packet):
    """Save packets and display protocol details and optional hex dumps."""
    if pcap_writer is not None:
        pcap_writer.write(packet)

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

    if verbose:
        from scapy.all import hexdump
        hexdump(packet)


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
        help="Display hexadecimal dumps of captured packets"
    )

    args = parser.parse_args()
    verbose = args.verbose

    print("[INFO] PySniffer initialized.")

    try:
        if args.write:
            from scapy.utils import PcapWriter

            pcap_writer = PcapWriter(
                args.write,
                append=True,
                sync=True
            )

        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_handler,
            store=False
        )

    except KeyboardInterrupt:
        print("[INFO] Stopping capture...")

    except OSError as error:
        print(f"[ERROR] Packet capture failed: {error}")
        raise SystemExit(1)

    finally:
        if pcap_writer is not None:
            pcap_writer.close()
