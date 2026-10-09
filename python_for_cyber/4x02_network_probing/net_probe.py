#!/usr/bin/env python3
"""NetProbe - network probing and service discovery tool."""

import socket
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
    """Return hosts with TCP port 80 open in a /24 subnet."""
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


def scan_single_port(ip: str, port: int) -> Optional[dict]:
    """Return an open port's service details or None if closed."""
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
    """Scan TCP ports concurrently and return sorted open services."""
    results = []

    print(f"Scanning {ip} from {start_port} to {end_port}...")

    if not 1 <= start_port <= end_port <= 65535:
        print("[ERROR] Invalid port range.")
        return results

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(scan_single_port, ip, port)
            for port in range(start_port, end_port + 1)
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


def main() -> None:
    """Initialize the NetProbe command-line application."""
    print("NetProbe v1.0 initialized...")


if __name__ == "__main__":
    main()
