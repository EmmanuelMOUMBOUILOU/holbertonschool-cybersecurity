
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


def scan_ports(ip: str, start_port: int, end_port: int) -> list:
    """Scan a TCP port range and return open ports with service banners."""
    results = []

    print(f"Scanning {ip} from {start_port} to {end_port}...")

    for port in range(start_port, end_port + 1):
        if check_port(ip, port):
            service = get_banner(ip, port)

            results.append({
                "port": port,
                "service": service
            })

            print(f"[+] Port {port} Open: {service}")

    return results


def main() -> None:
    """Initialize the NetProbe command-line application."""
    print("NetProbe v1.0 initialized...")


if __name__ == "__main__":
    main()
