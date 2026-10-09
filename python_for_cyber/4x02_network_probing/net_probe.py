#!/usr/bin/env python3
"""NetProbe - network probing and service discovery tool."""

import argparse
import json
import math
import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple


SERVICE_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

VULNERABLE_SIGNATURES = (
    "vsftpd 2.3.4", "openssh_4.", "apache/2.2.",
    "proftpd 1.3.3c", "samba 3.0.20", "distccd",
)


def check_port(ip: str, port: int) -> bool:
    """Return True when a TCP connection succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            return sock.connect_ex((ip, port)) == 0
    except (OSError, ValueError):
        return False


def ping_sweep(subnet: str) -> List[str]:
    """Probe hosts in a /24 network using common TCP ports."""
    prefix = subnet.split("/")[0].rsplit(".", 1)[0]
    if len(prefix.split(".")) != 3:
        raise ValueError("Expected a /24 IPv4 subnet")
    active = []
    for host in range(1, 255):
        ip = "{}.{}".format(prefix, host)
        if check_port(ip, 80) or check_port(ip, 443):
            active.append(ip)
    return active


def get_banner(ip: str, port: int) -> str:
    """Retrieve a best-effort TCP service banner."""
    try:
        with socket.create_connection((ip, port), timeout=1.0) as sock:
            sock.settimeout(1.0)
            if port in (80, 8080, 8000):
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            return sock.recv(1024).decode(
                "utf-8", errors="replace"
            ).strip()
    except (OSError, ValueError):
        return ""


def guess_service(port: int) -> str:
    """Guess the service associated with a TCP or UDP port."""
    return SERVICE_PORTS.get(port, "Unknown")


def check_vulnerability(banner: str) -> bool:
    """Check a banner against a small set of known risky versions."""
    banner_lower = banner.lower()
    return any(signature in banner_lower
               for signature in VULNERABLE_SIGNATURES)


def get_service_info(ip: str, port: int) -> Dict[str, object]:
    """Return the guessed service, banner, and vulnerability flag."""
    banner = get_banner(ip, port)
    return {
        "service": guess_service(port),
        "banner": banner,
        "vulnerable": check_vulnerability(banner),
    }


def scan_single_port(ip: str, port: int) -> Dict[str, object]:
    """Scan one TCP port and collect service information."""
    is_open = check_port(ip, port)
    result = {
        "port": port,
        "state": "open" if is_open else "closed",
        "service": guess_service(port),
        "vulnerable": False,
    }
    if is_open:
        info = get_service_info(ip, port)
        result.update(info)
        if result["vulnerable"]:
            result["marker"] = "[VULNERABLE]"
    return result


def scan_ports(ip: str, start_port: int, end_port: int,
               delay: float = 0.0, randomize: bool = False,
               max_workers: int = 50) -> List[Dict[str, object]]:
    """Scan a TCP port range using up to 50 threads."""
    if not 1 <= start_port <= end_port <= 65535:
        raise ValueError("Port range must be between 1 and 65535")
    if delay < 0 or not math.isfinite(delay):
        raise ValueError("Delay must be a finite nonnegative number")
    ports = list(range(start_port, end_port + 1))
    if randomize:
        random.shuffle(ports)
    results = []
    with ThreadPoolExecutor(
        max_workers=min(50, max(1, max_workers))
    ) as pool:
        futures = []
        for port in ports:
            futures.append(pool.submit(scan_single_port, ip, port))
            if delay:
                time.sleep(delay)
        for future in as_completed(futures):
            results.append(future.result())
    if not randomize:
        results.sort(key=lambda result: result["port"])
    return results


def parse_port_range(value: str) -> Tuple[int, int]:
    """Parse a port or an inclusive start-end port range."""
    parts = value.split("-", 1)
    try:
        start = int(parts[0])
        end = int(parts[1]) if len(parts) == 2 else start
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Invalid port range") from exc
    if not 1 <= start <= end <= 65535:
        raise argparse.ArgumentTypeError("Ports must be in 1-65535")
    return start, end


def build_json_report(ip: str, results: List[Dict[str, object]]) -> Dict:
    """Build a JSON-serializable scan report."""
    return {"target": ip, "results": results}


def scan_udp(ip: str, port: int) -> bool:
    """Return True for UDP open/open-filtered, False for errors."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.0)
            sock.connect((ip, port))
            sock.send(b"")
            sock.recv(1024)
            return True
    except socket.timeout:
        return True
    except (OSError, ValueError):
        return False


def main() -> None:
    """Run NetProbe from the command line."""
    parser = argparse.ArgumentParser(description="NetProbe TCP scanner")
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target IPv4 address or hostname"
    )
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        type=parse_port_range,
        help="Port or range (e.g. 20-80)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Save results as JSON"
    )
    parser.add_argument(
        "-d", "--delay", type=float, default=0.0,
        help="Delay between submitting port probes"
    )
    parser.add_argument(
        "-r", "--random", action="store_true",
        help="Randomize the port scan order"
    )
    args = parser.parse_args()
    start, end = args.ports
    try:
        results = scan_ports(
            args.target, start, end,
            delay=args.delay, randomize=args.random
        )
    except ValueError as exc:
        parser.error(str(exc))

    print("Target: {}".format(args.target))
    for result in results:
        line = "{port}/tcp {state} {service}".format(**result)
        if result.get("vulnerable"):
            line += " [VULNERABLE]"
        print(line)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as output_file:
            json.dump(
                build_json_report(args.target, results),
                output_file, indent=4
            )
            output_file.write("\n")


if __name__ == "__main__":
    main()