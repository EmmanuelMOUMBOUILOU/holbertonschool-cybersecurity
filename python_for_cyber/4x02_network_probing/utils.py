#!/usr/bin/env python3
"""Port range, scan delay and randomization helpers."""

import ipaddress
import math
import random
import time


def apply_delay(delay: float) -> None:
    """Wait before a probe and print the original debug message."""
    if delay > 0:
        print(f"[DEBUG] Sleeping {delay}s before next packet...")
        time.sleep(delay)


def randomize_ports(ports: list) -> None:
    """Shuffle the list of ports in place."""
    random.shuffle(ports)


def valid_delay(delay: float) -> bool:
    """Check that a scan delay is finite and non-negative."""
    return math.isfinite(delay) and delay >= 0


def validate_interface(interface: str) -> bool:
    """Check that the selected source address is valid IPv4."""
    try:
        ipaddress.IPv4Address(interface)
        return True
    except ipaddress.AddressValueError:
        return False


def parse_port_range(port_range: str) -> tuple:
    """Return inclusive TCP port bounds from START-END notation."""
    parts = port_range.split("-")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ValueError("Port range must look like 1-1000.")

    start_port, end_port = (int(part) for part in parts)
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError("Port numbers must be between 1 and 65535.")

    return start_port, end_port
