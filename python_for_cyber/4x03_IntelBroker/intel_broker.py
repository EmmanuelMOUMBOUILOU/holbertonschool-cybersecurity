
#!/usr/bin/env python3
"""Collect and aggregate IP intelligence using asynchronous API queries."""

import argparse
import asyncio
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

import aiohttp


async def fetch_api(session: aiohttp.ClientSession, url: str) -> dict:
    """Fetch a JSON dictionary from an API, or return {} on failure."""
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
    """Query one local intelligence API using an HTTP session."""
    url = f"http://localhost:5000/{service}/{ip}"
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        return await fetch_api(session, url)


def query_virustotal(ip: str) -> dict:
    """Return VirusTotal mock data, or {} on failure."""
    return asyncio.run(_query_api(ip, "virustotal"))


def query_abuseipdb(ip: str) -> dict:
    """Return AbuseIPDB mock data, or {} on failure."""
    return asyncio.run(_query_api(ip, "abuseipdb"))


async def gather_intel(ip: str) -> list:
    """Fetch VirusTotal, Shodan, and AbuseIPDB data concurrently."""
    base_url = "http://localhost:5000"
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        vt_task = fetch_api(
            session,
            f"{base_url}/virustotal/{ip}"
        )

        shodan_task = fetch_api(
            session,
            f"{base_url}/shodan/{ip}"
        )

        abuse_task = fetch_api(
            session,
            f"{base_url}/abuseipdb/{ip}"
        )

        results = await asyncio.gather(
            vt_task,
            shodan_task,
            abuse_task
        )

    return results


def run_nmap(ip: str) -> str:
    """Run Nmap on ports 22 and 80 and return its raw XML output."""
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
    """Return the open port numbers found in Nmap XML output."""
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
    """Store intelligence data and scan results for a target IP."""

    def __init__(
        self,
        ip: str = "",
        vt_data: Optional[dict] = None,
        abuse_data: Optional[dict] = None,
        nmap_ports: Optional[list] = None
    ) -> None:
        """Initialize the target dossier and its data containers."""
        self.ip = ip
        self.vt_data = {} if vt_data is None else vt_data
        self.abuse_data = {} if abuse_data is None else abuse_data
        self.nmap_ports = [] if nmap_ports is None else nmap_ports
        self.shodan_data = {}


def main() -> None:
    """Gather API intelligence, run Nmap, and print a summary."""
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
    print("[*] Querying VirusTotal, Shodan and AbuseIPDB...")

    results = asyncio.run(gather_intel(dossier.ip))

    dossier.vt_data = results[0]
    dossier.shodan_data = results[1]
    dossier.abuse_data = results[2]

    print("[*] Running Nmap...")

    try:
        xml_output = run_nmap(dossier.ip)
        dossier.nmap_ports = parse_nmap_xml(xml_output)

    except RuntimeError as error:
        print(f"[ERROR] {error}")

    print("\n===== TARGET DOSSIER =====")
    print(f"Target IP: {dossier.ip}")
    print(f"VirusTotal: {dossier.vt_data}")
    print(f"Shodan: {dossier.shodan_data}")
    print(f"AbuseIPDB: {dossier.abuse_data}")
    print(f"Nmap Open Ports: {dossier.nmap_ports}")
    print("==========================")


if __name__ == "__main__":
    main()
