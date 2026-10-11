#!/usr/bin/env python3
"""Capture and filter network traffic continuously using Scapy."""

import argparse

from scapy.all import sniff


def packet_handler(packet):
    """Display protocol information for captured IPv4 packets."""
    if packet.haslayer("IP"):
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

    args = parser.parse_args()

    print("[INFO] PySniffer initialized.")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_handler
        )
    except KeyboardInterrupt:
        print("[INFO] Stopping capture...")
    except OSError as error:
        print(f"[ERROR] Packet capture failed: {error}")
        raise SystemExit(1)
