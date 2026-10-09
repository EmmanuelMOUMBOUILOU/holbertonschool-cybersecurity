
#!/usr/bin/env python3
"""NetProbe - network probing and service discovery tool."""

import argparse
import socket

from reporter import build_json_report, save_json_report
from scanner import (
    check_port,
    check_vulnerability,
    get_banner,
    get_service_info,
    guess_service,
    parse_http_server,
    ping_sweep,
    resolve_hostname,
    scan_ports,
    scan_single_port,
    scan_udp,
)
from utils import parse_port_range, valid_delay, validate_interface


def main() -> None:
    """Parse CLI options, scan TCP ports, and optionally export JSON."""
    parser = argparse.ArgumentParser(description="NetProbe TCP scanner")
    parser.add_argument("-t", "--target", help="Authorized target IP")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Inclusive port range, e.g. 1-1000"
    )
    parser.add_argument("-o", "--output", help="Output JSON filename")
    parser.add_argument(
        "-d", "--delay", type=float, default=0.0,
        help="Delay in seconds before each scan attempt"
    )
    parser.add_argument(
        "-r", "--random", action="store_true", dest="randomize",
        help="Shuffle the port scan order"
    )
    parser.add_argument(
        "-i", "--interface", metavar="LOCAL_IP",
        help="Local IPv4 address to bind outgoing sockets"
    )

    args = parser.parse_args()
    print("NetProbe v1.0 initialized...")

    if not valid_delay(args.delay):
        parser.error("--delay must be a non-negative finite number")

    if args.interface is not None:
        if not validate_interface(args.interface):
            parser.error("--interface must be a valid local IPv4 address")

    if args.target is None:
        if (args.output or args.ports != "1-1024" or args.delay
                or args.randomize or args.interface is not None):
            parser.error("--target is required to scan ports")
        return

    try:
        start_port, end_port = parse_port_range(args.ports)
    except ValueError as error:
        parser.error(str(error))

    hostname = resolve_hostname(args.target)
    print(f"Target: {args.target} ({hostname})")

    if args.interface is not None:
        print(f"[INFO] Scanning from source IP: {args.interface}")

    results = scan_ports(
        args.target, start_port, end_port,
        delay=args.delay,
        randomize=args.randomize,
        interface=args.interface
    )

    if args.output:
        save_json_report(results, args.output)


if __name__ == "__main__":
    main()
