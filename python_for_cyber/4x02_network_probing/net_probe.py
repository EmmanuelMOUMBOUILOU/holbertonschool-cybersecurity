#!/usr/bin/env python3
"""NetProbe - network probing and service discovery tool."""

import argparse
import json
import math
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional


MAX_WORKERS = 50
SCAN_DELAY = 0.0

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
    """Return hosts with TCP port 80 open in the given /24 subnet."""
    live_hosts = []

    for host in range(1, 255):
        ip = f"{subnet}.{host}"

        if check_port(ip, 80):
            live_hosts.append(ip)

    return live_hosts


def get_banner(ip: str, port: int) -> str:
    """Connect to a TCP service and return its banner or Unknown."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
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
                "utf-8",
                errors="replace"
            ).strip() or "Unknown"

    except (OSError, ValueError, OverflowError):
        return "Unknown"


def guess_service(port: int) -> str:
    """Return a guessed service name or Unknown for an unmapped port."""
    service = COMMON_SERVICES.get(port)

    if service is None:
        return "Unknown"

    return f"{service} (Guessed)"


def get_service_info(ip: str, port: int) -> str:
    """Return the service banner or a port-based service guess."""
    banner = get_banner(ip, port)

    if banner and banner.strip().lower() != "unknown":
        return banner.strip()

    return guess_service(port)


def check_vulnerability(banner: str) -> str:
    """Return a vulnerability marker for known bad banner signatures."""
    for signature in VULNERABLE_SIGNATURES:
        if signature.lower() in banner.lower():
            return "[VULNERABLE]"

    return ""


def scan_single_port(
    ip: str,
    port: int,
    delay: float = 0.0
) -> Optional[dict]:
    """Optionally wait, then return service details for an open port."""
    if delay > 0:
        print(f"[DEBUG] Sleeping {delay}s before next packet...")
        time.sleep(delay)

    if not check_port(ip, port):
        return None

    service = get_service_info(ip, port)
    vulnerability = check_vulnerability(service)

    if vulnerability:
        service = f"{service} {vulnerability}"

    return {
        "port": port,
        "service": service
    }


def scan_ports(ip: str, start_port: int, end_port: int) -> list:
    """Scan ports with at most 50 workers using the configured delay."""
    results = []

    print(f"Scanning {ip} from {start_port} to {end_port}...")

    if not 1 <= start_port <= end_port <= 65535:
        print("[ERROR] Invalid port range.")
        return results

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []

        for port in range(start_port, end_port + 1):
            if SCAN_DELAY > 0:
                future = executor.submit(
                    scan_single_port, ip, port, SCAN_DELAY
                )
            else:
                future = executor.submit(
                    scan_single_port, ip, port
                )

            futures.append(future)

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
    """Read CLI options, scan authorized targets, and export JSON."""
    global SCAN_DELAY

    parser = argparse.ArgumentParser(description="NetProbe TCP scanner")

    parser.add_argument(
        "-t", "--target",
        help="Authorized target IP"
    )

    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Inclusive port range, e.g. 1-1000"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output JSON filename"
    )

    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.0,
        help="Seconds to wait before each worker scan attempt"
    )

    args = parser.parse_args()

    print("NetProbe v1.0 initialized...")

    if not math.isfinite(args.delay) or args.delay < 0:
        print("[ERROR] Delay must be a finite non-negative number.")
        return

    if args.target is None:
        if args.output or args.ports != "1-1024" or args.delay > 0:
            parser.error("--target is required to scan ports")
        return

    try:
        start_port, end_port = parse_port_range(args.ports)
    except ValueError as error:
        print(f"[ERROR] {error}")
        return

    SCAN_DELAY = args.delay

    results = scan_ports(args.target, start_port, end_port)

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
