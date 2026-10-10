#!/usr/bin/env python3
"""Collect IP intelligence with asynchronous HTTP requests and Nmap."""

import argparse
import asyncio
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

import aiohttp


async def fetch_api(session: aiohttp.ClientSession, url: str) -> dict:
    """Fetch a JSON dictionary from a REST endpoint, or return {} on error."""
    try:
        async with session.get(url) as response:
            if response.status != 200:
                print(f"[ERROR] API returned HTTP {response.status}.")
                return {}

            data = await response.json()
            if not isinstance(data, dict):
                print("[ERROR] API response is not a JSON object.")
                return {}

            return data

    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as error:
        print(f"[ERROR] API request failed: {error}")
        return {}


async def _query_api(ip: str, service: str) -> dict:
    """Open an HTTP session and query a local mock intelligence service."""
    url = f"http://localhost:5000/{service}/{ip}"
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        return await fetch_api(session, url)


def query_virustotal(ip: str) -> dict:
    """Return VirusTotal mock data synchronously, or {} on failure."""
    return asyncio.run(_query_api(ip, "virustotal"))


def query_abuseipdb(ip: str) -> dict:
    """Return AbuseIPDB mock data synchronously, or {} on failure."""
    return asyncio.run(_query_api(ip, "abuseipdb"))


def run_nmap(ip: str) -> str:
    """Return raw Nmap XML for ports 22 and 80, or raise RuntimeError."""
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
    """Extract open port numbers from Nmap XML, or [] for invalid XML."""
    try:
        root = ET.fromstring(xml_data)
    except (ET.ParseError, TypeError) as error:
        print(f"[ERROR] Invalid Nmap XML: {error}")
        return []

    open_ports = []
    for port in root.findall(".//host/ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        try:
            open_ports.append(int(port.get("portid")))
        except (TypeError, ValueError):
            continue

    return open_ports


class TargetDossier:
    """Store IP address, VirusTotal, AbuseIPDB, and Nmap scan results."""

    def __init__(
        self,
        ip: str = "",
        vt_data: Optional[dict] = None,
        abuse_data: Optional[dict] = None,
        nmap_ports: Optional[list] = None
    ) -> None:
        """Initialize a dossier with optional intelligence results."""
        self.ip = ip
        self.vt_data = {} if vt_data is None else vt_data
        self.abuse_data = {} if abuse_data is None else abuse_data
        self.nmap_ports = [] if nmap_ports is None else nmap_ports


def main() -> None:
    """Collect three sources sequentially and print a target summary."""
    parser = argparse.ArgumentParser(
        description="IntelBroker - Threat Intelligence Aggregator"
    )
    parser.add_argument("ip", help="Target IP address to investigate")
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
