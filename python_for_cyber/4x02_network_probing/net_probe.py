#!/usr/bin/env python3
"""NetProbe - network probing and service discovery tool."""

import socket


def check_port(ip: str, port: int) -> bool:
    """Return True if a TCP connection succeeds, otherwise False."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            return True
    except (OSError, ValueError, OverflowError):
        return False


def ping_sweep(subnet: str) -> list:
    """Return IPs with TCP port 80 open in a /24 subnet."""
    live_hosts = []

    for host in range(1, 255):
        ip = f"{subnet}.{host}"

        if check_port(ip, 80):
            live_hosts.append(ip)

    return live_hosts


def main() -> None:
    """Initialize the NetProbe command-line application."""
    print("NetProbe v1.0 initialized...")


if __name__ == "__main__":
    main()
