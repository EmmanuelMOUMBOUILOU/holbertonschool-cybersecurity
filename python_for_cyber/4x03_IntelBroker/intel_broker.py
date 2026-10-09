#!/usr/bin/env python3
"""Collect and aggregate threat intelligence about an IP address."""

import argparse
import ipaddress
import subprocess
import xml.etree.ElementTree as ET

import requests


def query_virustotal(ip: str) -> dict:
    """Return VirusTotal JSON data for an IP, or {} on failure."""
    url = f"http://localhost:5000/virustotal/{ip}"

    try:
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            print(
                f"[ERROR] VirusTotal returned "
                f"HTTP {response.status_code}."
            )
            return {}

        data = response.json()

        if not isinstance(data, dict):
            print("[ERROR] Unexpected VirusTotal response format.")
            return {}

        return data

    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to the mock API server.")

    except requests.exceptions.Timeout:
        print("[ERROR] VirusTotal API request timed out.")

    except ValueError:
        print("[ERROR] Invalid JSON response from VirusTotal.")

    except requests.exceptions.RequestException as error:
        print(f"[ERROR] VirusTotal request failed: {error}")

    return {}


def query_abuseipdb(ip: str) -> dict:
    """Return AbuseIPDB JSON data for an IP, or {} on failure."""
    url = f"http://localhost:5000/abuseipdb/{ip}"

    try:
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            print(
                f"[ERROR] AbuseIPDB returned "
                f"HTTP {response.status_code}."
            )
            return {}

        data = response.json()

        if not isinstance(data, dict):
            print("[ERROR] Unexpected AbuseIPDB response format.")
            return {}

        return data

    except requests.exceptions.ConnectionError:
        print("[ERROR] Cannot connect to the mock API server.")

    except requests.exceptions.Timeout:
        print("[ERROR] AbuseIPDB API request timed out.")

    except ValueError:
        print("[ERROR] Invalid JSON response from AbuseIPDB.")

    except requests.exceptions.RequestException as error:
        print(f"[ERROR] AbuseIPDB request failed: {error}")

    return {}


def run_nmap(ip: str) -> str:
    """Run Nmap on ports 22 and 80 and return raw XML stdout.

    Raise RuntimeError if Nmap cannot run or exits unsuccessfully.
    """
    command = ["nmap", "-p", "22,80", ip, "-oX", "-"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

    except FileNotFoundError as error:
        raise RuntimeError(
            "Nmap is not installed or cannot be found."
        ) from error

    except OSError as error:
        raise RuntimeError(
            f"Unable to execute Nmap: {error}"
        ) from error

    if result.returncode != 0:
        message = result.stderr.strip()

        if not message:
            message = f"Exit code {result.returncode}"

        raise RuntimeError(f"Nmap scan failed: {message}")

    return result.stdout


def parse_nmap_xml(xml_data: str) -> list:
    """Return integer port IDs whose Nmap XML state is open.

    Return an empty list if the XML is invalid or has no open ports.
    """
    open_ports = []

    try:
        root = ET.fromstring(xml_data)

    except (ET.ParseError, TypeError) as error:
        print(f"[ERROR] Invalid Nmap XML: {error}")
        return []

    for port in root.findall(".//host/ports/port"):
        state = port.find("state")

        if state is None or state.get("state") != "open":
            continue

        port_id = port.get("portid")

        try:
            open_ports.append(int(port_id))

        except (TypeError, ValueError):
            continue

    return open_ports


class TargetDossier:
    """Store intelligence data collected for a target IP address."""

    def __init__(
        self,
        ip: str = "",
        vt_data: dict = None,
        abuse_data: dict = None,
        nmap_ports: list = None
    ) -> None:
        """Initialize a dossier with optional intelligence data."""
        self.ip = ip
        self.vt_data = {} if vt_data is None else vt_data
        self.abuse_data = {} if abuse_data is None else abuse_data
        self.nmap_ports = [] if nmap_ports is None else nmap_ports


def main() -> None:
    """Query three intelligence sources and display a target summary."""
    parser = argparse.ArgumentParser(
        description="IntelBroker - Threat Intelligence Aggregator"
    )

    parser.add_argument(
        "ip",
        help="Target IP address to investigate"
    )

    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        parser.error("Please provide a valid IP address.")

    dossier = TargetDossier(args.ip)

    print(f"[*] Investigating target: {dossier.ip}")

    print("[*] Querying VirusTotal...")
    dossier.vt_data = query_virustotal(dossier.ip)

    print("[*] Querying AbuseIPDB...")
    dossier.abuse_data = query_abuseipdb(dossier.ip)

    print("[*] Running Nmap...")
    try:
        xml_output = run_nmap(dossier.ip)
        dossier.nmap_ports = parse_nmap_xml(xml_output)

    except RuntimeError as error:
        print(f"[ERROR] {error}")

    print("\n===== TARGET DOSSIER =====")
    print(f"Target IP: {dossier.ip}")
    print(f"VirusTotal: {dossier.vt_data}")
    print(f"AbuseIPDB: {dossier.abuse_data}")
    print(f"Nmap Open Ports: {dossier.nmap_ports}")
    print("==========================")


if __name__ == "__main__":
    main()
