#!/usr/bin/env python3
"""NetProbe - network probing and service discovery tool."""

import argparse
import ipaddress
import json
import math
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


MAX_WORKERS = 50

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL"
}

VULNERABLE_SIGNATURES = [
    "vsftpd 2.3.4",
    "Apache 2.2.8",
    "Apache/2.2.8"
]


def check_port(
    ip: str,
    port: int,
    interface: Optional[str] = None
) -> bool:
    """Return True if the TCP connection succeeds, otherwise False."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if interface is not None:
                sock.bind((interface, 0))
            sock.connect((ip, port))
            return True
    except (OSError, ValueError, OverflowError):
        return False


def resolve_hostname(ip: str) -> str:
    """Return the reverse-DNS hostname or Unknown when unavailable."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (OSError, ValueError):
        return "Unknown"


def scan_udp(
    ip: str,
    port: int,
    interface: Optional[str] = None
) -> bool:
    """Return True for a UDP response or timeout (open/filtered)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            if interface is not None:
                sock.bind((interface, 0))
            sock.sendto(b"", (ip, port))

            try:
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                return True
            except ConnectionRefusedError:
                return False

    except (OSError, ValueError, OverflowError):
        return False


def ping_sweep(
    subnet: str,
    interface: Optional[str] = None
) -> list:
    """Return /24 hosts with TCP port 80 open."""
    live_hosts = []

    for host in range(1, 255):
        ip = f"{subnet}.{host}"
        if interface is None:
            is_open = check_port(ip, 80)
        else:
            is_open = check_port(ip, 80, interface)

        if is_open:
            live_hosts.append(ip)

    return live_hosts


def get_banner(
    ip: str,
    port: int,
    interface: Optional[str] = None
) -> str:
    """Connect to a TCP service and return its banner or Unknown."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if interface is not None:
                sock.bind((interface, 0))
            sock.connect((ip, port))

            if port in (80, 8000, 8080, 8888):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024)
            else:
                try:
                    banner = sock.recv(1024)
                except socket.timeout:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024)

            return banner.decode(
                "utf-8", errors="replace"
            ).strip() or "Unknown"

    except (OSError, ValueError, OverflowError):
        return "Unknown"


def guess_service(port: int) -> str:
    """Return a guessed service name or Unknown for an unmapped port."""
    service = COMMON_SERVICES.get(port)
    if service is None:
        return "Unknown"
    return f"{service} (Guessed)"


def get_service_info(
    ip: str,
    port: int,
    interface: Optional[str] = None
) -> str:
    """Return the service banner or a port-based service guess."""
    if interface is None:
        banner = get_banner(ip, port)
    else:
        banner = get_banner(ip, port, interface)

    if banner and banner.strip().lower() != "unknown":
        return banner.strip()

    return guess_service(port)


def check_vulnerability(banner: str) -> str:
    """Return a marker for known vulnerable banner signatures."""
    for signature in VULNERABLE_SIGNATURES:
        if signature.lower() in banner.lower():
            return "[VULNERABLE]"
    return ""


def scan_single_port(
    ip: str,
    port: int,
    delay: float = 0.0,
    interface: Optional[str] = None
) -> Optional[dict]:
    """Scan one TCP port after an optional delay."""
    if delay > 0:
        print(f"[DEBUG] Sleeping {delay}s before next packet...")
        time.sleep(delay)

    if interface is None:
        is_open = check_port(ip, port)
    else:
        is_open = check_port(ip, port, interface)

    if not is_open:
        return None

    if interface is None:
        service = get_service_info(ip, port)
    else:
        service = get_service_info(ip, port, interface)

    vulnerability = check_vulnerability(service)
    if vulnerability:
        service = f"{service} {vulnerability}"

    return {"port": port, "service": service}


def scan_ports(
    ip: str,
    start_port: int,
    end_port: int,
    delay: float = 0.0,
    randomize: bool = False,
    interface: Optional[str] = None
) -> list:
    """Scan TCP ports concurrently and return sorted open services."""
    results = []
    print(f"Scanning {ip} from {start_port} to {end_port}...")

    if not 1 <= start_port <= end_port <= 65535:
        print("[ERROR] Invalid port range.")
        return results

    if not math.isfinite(delay) or delay < 0:
        print("[ERROR] Delay must be a non-negative finite number.")
        return results

    ports = list(range(start_port, end_port + 1))
    if randomize:
        random.shuffle(ports)
        print("Scanning ports randomly...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        if interface is None:
            futures = [
                executor.submit(scan_single_port, ip, port, delay)
                for port in ports
            ]
        else:
            futures = [
                executor.submit(scan_single_port, ip, port, delay, interface)
                for port in ports
            ]

        for future in as_completed(futures):
            try:
                result = future.result()
            except (OSError, ValueError, OverflowError) as error:
                print(f"[ERROR] Port scan failed: {error}")
                continue

            if result is not None:
                results.append(result)
                print(
                    f"[+] Port {result['port']} Open: "
                    f"{result['service']}"
                )

    results.sort(key=lambda entry: entry["port"])
    return results


def parse_port_range(port_range: str) -> tuple:
    """Return inclusive TCP port bounds from START-END notation."""
    parts = port_range.split("-")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise ValueError("Port range must look like 1-1000.")

    start_port, end_port = (int(part) for part in parts)
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError("Port numbers must be between 1 and 65535.")

    return start_port, end_port


def build_json_report(results: list) -> list:
    """Convert scan results to JSON-ready open-port records."""
    report = []
    marker = " [VULNERABLE]"

    for result in results:
        service = result["service"]
        if service.endswith(marker):
            service = service[:-len(marker)]

        report.append({
            "port": result["port"],
            "state": "open",
            "service": service,
            "vulnerability": (
                "YES" if check_vulnerability(service) else "NO"
            )
        })

    return report


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

    if not math.isfinite(args.delay) or args.delay < 0:
        parser.error("--delay must be a non-negative finite number")

    if args.interface is not None:
        try:
            ipaddress.IPv4Address(args.interface)
        except ipaddress.AddressValueError:
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
        try:
            with open(args.output, "w", encoding="utf-8") as report_file:
                json.dump(build_json_report(results), report_file, indent=2)
                report_file.write("\n")
        except (OSError, TypeError, KeyError) as error:
            print(f"[ERROR] Could not export JSON report: {error}")
            return

        print(f"[*] Report saved: {args.output}")


if __name__ == "__main__":
    main()
