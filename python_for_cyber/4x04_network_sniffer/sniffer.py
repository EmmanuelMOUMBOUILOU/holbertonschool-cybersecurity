#!/usr/bin/env python3
"""Capture network packets and display protocol details using Scapy."""

from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_handler(packet):
    """Display protocol information for captured IPv4 packets."""
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            flags = packet[TCP].flags

            print(
                f"[TCP] {src}:{sport} -> {dst}:{dport} "
                f"| Flags: {flags}"
            )

        elif packet.haslayer(UDP):
            print(f"[UDP] {src} -> {dst}")

        elif packet.haslayer(ICMP):
            print(f"[ICMP] {src} -> {dst}")


if __name__ == "__main__":
    print("[INFO] PySniffer initialized.")

    try:
        sniff(count=5, prn=packet_handler)
    except OSError as error:
        print(f"[ERROR] Packet capture failed: {error}")
        raise SystemExit(1)
