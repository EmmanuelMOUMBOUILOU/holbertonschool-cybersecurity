#!/usr/bin/env python3
"""Capture and display network packets using Scapy."""

from scapy.all import sniff


def packet_handler(packet):
    """Print a one-line summary of a captured packet."""
    print(packet.summary())


if __name__ == "__main__":
    print("[INFO] PySniffer initialized.")

    try:
        sniff(count=5, prn=packet_handler)
    except OSError as error:
        print(f"[ERROR] Packet capture failed: {error}")
        raise SystemExit(1)
