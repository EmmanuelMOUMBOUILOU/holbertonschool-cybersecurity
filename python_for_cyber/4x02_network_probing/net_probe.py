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


def main() -> None:
    """Initialize the NetProbe command-line application."""
    print("NetProbe v1.0 initialized...")


if __name__ == "__main__":
    main()
