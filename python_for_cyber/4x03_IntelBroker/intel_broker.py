#!/usr/bin/env python3
"""Collect asynchronous threat intelligence and export JSON reports."""

import argparse
import asyncio
import ipaddress
import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

import aiohttp


async def fetch_api(session: aiohttp.ClientSession, url: str) -> dict:
    """Fetch JSON from an API endpoint, or return {} on failure."""
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
    """Query a local mock API using a dedicated HTTP session."""
    url = f"http://localhost:5000/{service}/{ip}"
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        return await fetch_api(session, url)


def query_virustotal(ip: str) -> dict:
    """Return VirusTotal mock data synchronously."""
    return asyncio.run(_query_api(ip, "virustotal"))


def query_abuseipdb(ip: str) -> dict:
    """Return AbuseIPDB mock data synchronously."""
    return asyncio.run(_query_api(ip, "abuseipdb"))


async def gather_intel(ip: str) -> list:
    """Fetch VirusTotal, Shodan and AbuseIPDB data concurrently."""
    base_url = "http://localhost:5000"
    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        return await asyncio.gather(
            fetch_api(session, f"{base_url}/virustotal/{ip}"),
            fetch_api(session, f"{base_url}/shodan/{ip}"),
            fetch_api(session, f"{base_url}/abuseipdb/{ip}")
        )


def run_nmap(ip: str) -> str:
    """Run Nmap synchronously and return its XML output."""
    command = ["nmap", "-p", "22,80", ip, "-oX", "-"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
    except FileNotFoundError as error:
        raise RuntimeError("Nmap is not installed.") from error
    except OSError as error:
        raise RuntimeError(f"Unable to execute Nmap: {error}") from error

    if result.returncode != 0:
        message = result.stderr.strip() or str(result.returncode)
        raise RuntimeError(f"Nmap scan failed: {message}")

    return result.stdout


async def run_nmap_async(ip: str) -> str:
    """Run Nmap asynchronously and return its decoded XML output."""
    command = ["nmap", "-p", "22,80", ip, "-oX", "-"]

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
    except FileNotFoundError as error:
        raise RuntimeError("Nmap is not installed.") from error
    except OSError as error:
        raise RuntimeError(f"Unable to execute Nmap: {error}") from error

    if process.returncode != 0:
        message = stderr.decode("utf-8", errors="replace").strip()
        if not message:
            message = f"Exit code {process.returncode}"
        raise RuntimeError(f"Nmap scan failed: {message}")

    return stdout.decode("utf-8", errors="replace")


def parse_nmap_xml(xml_data: str) -> list:
    """Extract open TCP or UDP port IDs from Nmap XML."""
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
    """Store intelligence data and scan results for one IP address."""

    def __init__(
        self,
        ip: str = "",
        vt_data: Optional[dict] = None,
        abuse_data: Optional[dict] = None,
        nmap_ports: Optional[list] = None,
        shodan_data: Optional[dict] = None
    ) -> None:
        """Initialize the dossier with empty or supplied data."""
        self.ip = ip
        self.vt_data = {} if vt_data is None else vt_data
        self.abuse_data = {} if abuse_data is None else abuse_data
        self.nmap_ports = [] if nmap_ports is None else nmap_ports
        self.shodan_data = {} if shodan_data is None else shodan_data

    def to_report(self) -> dict:
        """Convert the complete dossier to a JSON-compatible dictionary."""
        timestamp = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")

        return {
            "target": self.ip,
            "timestamp": timestamp,
            "intelligence": {
                "virustotal": self.vt_data,
                "shodan": self.shodan_data,
                "abuseipdb": self.abuse_data,
                "nmap": {"open_ports": self.nmap_ports}
            }
        }


def save_report(dossier: TargetDossier, output: str) -> bool:
    """Write the dossier as JSON and report whether writing succeeded."""
    try:
        with open(output, "w", encoding="utf-8") as report_file:
            json.dump(
                dossier.to_report(),
                report_file,
                indent=2,
                ensure_ascii=False
            )
            report_file.write("\n")
    except OSError as error:
        print(f"[ERROR] Cannot save report: {error}")
        return False

    print(f"[OK] JSON report saved: {output}")
    return True


async def collect_target(ip: str) -> TargetDossier:
    """Run API queries and Nmap concurrently to build a dossier."""
    dossier = TargetDossier(ip)
    print("[*] Querying VirusTotal, Shodan and AbuseIPDB...")
    print("[*] Running Nmap asynchronously...")

    api_results, nmap_result = await asyncio.gather(
        gather_intel(ip),
        run_nmap_async(ip),
        return_exceptions=True
    )

    if isinstance(api_results, Exception):
        print(f"[ERROR] Intelligence queries failed: {api_results}")
    else:
        dossier.vt_data = api_results[0]
        dossier.shodan_data = api_results[1]
        dossier.abuse_data = api_results[2]

    if isinstance(nmap_result, Exception):
        print(f"[ERROR] {nmap_result}")
    else:
        dossier.nmap_ports = parse_nmap_xml(nmap_result)

    return dossier


def main() -> None:
    """Collect target intelligence, print it and optionally export JSON."""
    parser = argparse.ArgumentParser(
        description="IntelBroker - Threat Intelligence Aggregator"
    )
    parser.add_argument("ip", help="Target IP address to investigate")
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save the complete dossier as a JSON report"
    )
    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        parser.error("Please provide a valid IP address.")

    print(f"[*] Investigating target: {args.ip}")
    dossier = asyncio.run(collect_target(args.ip))

    print("\n===== TARGET DOSSIER =====")
    print(f"Target IP: {dossier.ip}")
    print(f"VirusTotal: {dossier.vt_data}")
    print(f"Shodan: {dossier.shodan_data}")
    print(f"AbuseIPDB: {dossier.abuse_data}")
    print(f"Nmap Open Ports: {dossier.nmap_ports}")
    print("==========================")

    if args.output and not save_report(dossier, args.output):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
