#!/usr/bin/env python3
"""Capture network packets and identify TCP, UDP, and ICMP protocols."""

from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_handler(packet):
    """Identify the protocol and display source and destination IPs."""
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            print(f"[TCP] {src} -> {dst}")
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
