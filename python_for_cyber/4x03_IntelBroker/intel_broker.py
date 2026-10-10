#!/usr/bin/env python3
"""Collect IP intelligence asynchronously and cache API responses."""

import argparse
import asyncio
import ipaddress
import json
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

import aiohttp


CACHE_FILE = "cache.json"
CACHE_TTL = 3600
API_SERVICES = ("virustotal", "shodan", "abuseipdb")
SERVICE_NAMES = {
    "virustotal": "VirusTotal",
    "shodan": "Shodan",
    "abuseipdb": "AbuseIPDB"
}


async def fetch_api(session: aiohttp.ClientSession, url: str) -> dict:
    """Fetch API data, returning an unavailable error on failure."""
    try:
        async with session.get(url) as response:
            if response.status != 200:
                print(f"[ERROR] API returned HTTP {response.status}: {url}")
                return {"error": "Unavailable"}

            data = await response.json()

            if not isinstance(data, dict):
                print(f"[ERROR] Invalid API response: {url}")
                return {"error": "Unavailable"}

            return data

    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as error:
        print(f"[ERROR] API unavailable: {url}: {error}")
        return {"error": "Unavailable"}


def load_cache() -> dict:
    """Read the JSON cache, returning {} if it is missing or invalid."""
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as cache_file:
            cache = json.load(cache_file)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as error:
        print(f"[WARNING] Cannot read cache: {error}")
        return {}

    if not isinstance(cache, dict):
        print("[WARNING] Cache format is invalid.")
        return {}

    return cache


def save_cache(cache: dict) -> bool:
    """Save API responses to the JSON cache file."""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as cache_file:
            json.dump(cache, cache_file, indent=2)
            cache_file.write("\n")
    except (OSError, TypeError, ValueError) as error:
        print(f"[WARNING] Cannot save cache: {error}")
        return False

    return True


def get_cached_data(cache: dict, ip: str, service: str) -> Optional[dict]:
    """Return a cached API response if it is less than one hour old."""
    ip_cache = cache.get(ip)
    if not isinstance(ip_cache, dict):
        return None

    entry = ip_cache.get(service)
    if not isinstance(entry, dict):
        return None

    timestamp = entry.get("timestamp")
    data = entry.get("data")
    if isinstance(timestamp, bool):
        return None
    if not isinstance(timestamp, (int, float)):
        return None

    if not isinstance(data, dict) or not data:
        return None
    if data.get("error") == "Unavailable":
        return None

    age = time.time() - timestamp
    if 0 <= age < CACHE_TTL:
        return data

    return None


async def query_services(
    ip: str,
    services: list,
    semaphore: Optional[asyncio.Semaphore] = None,
    verbose: int = 0
) -> list:
    """Fetch uncached services with a maximum of five active requests."""
    cache = load_cache()
    results = [{} for _ in services]
    missing = []

    for index, service in enumerate(services):
        cached = get_cached_data(cache, ip, service)
        if cached is not None:
            print(f"[CACHE] Reusing {service} data for {ip}.")
            results[index] = cached
        else:
            missing.append((index, service))

    if not missing:
        return results

    if semaphore is None:
        semaphore = asyncio.Semaphore(5)

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:

        async def limited_fetch(service: str) -> dict:
            """Fetch one API while respecting the concurrency limit."""
            url = f"http://localhost:5000/{service}/{ip}"
            name = SERVICE_NAMES.get(service, service)

            async with semaphore:
                print(f"[+] Querying {name}...")
                started = time.perf_counter()
                try:
                    data = await fetch_api(session, url)
                except Exception as error:
                    print(f"[ERROR] Unexpected API failure: {url}: {error}")
                    data = {"error": "Unavailable"}

                if verbose >= 1:
                    status = "Unavailable" if data.get("error") else "OK"
                    print(f"[VERBOSE] {name} status: {status}")
                if verbose >= 2:
                    elapsed = time.perf_counter() - started
                    print(f"[VERBOSE] {name} duration: {elapsed:.2f}s")

                return data

        fetched = await asyncio.gather(
            *(limited_fetch(service) for _, service in missing)
        )

    updated = False
    for (index, service), data in zip(missing, fetched):
        results[index] = data
        if not isinstance(data, dict) or not data:
            continue
        if data.get("error") == "Unavailable":
            continue

        if not isinstance(cache.get(ip), dict):
            cache[ip] = {}

        cache[ip][service] = {
            "timestamp": time.time(),
            "data": data
        }
        updated = True

    if updated:
        save_cache(cache)

    return results


async def _query_api(ip: str, service: str) -> dict:
    """Query one API, reusing a fresh cached response if available."""
    results = await query_services(ip, [service])
    return results[0]


def query_virustotal(ip: str) -> dict:
    """Return VirusTotal data using the asynchronous API client."""
    return asyncio.run(_query_api(ip, "virustotal"))


def query_abuseipdb(ip: str) -> dict:
    """Return AbuseIPDB data using the asynchronous API client."""
    return asyncio.run(_query_api(ip, "abuseipdb"))


async def gather_intel(ip: str, verbose: int = 0) -> list:
    """Fetch cached intelligence with at most five simultaneous API calls."""
    semaphore = asyncio.Semaphore(5)
    return await query_services(ip, list(API_SERVICES), semaphore, verbose)


def run_nmap(ip: str) -> str:
    """Run Nmap synchronously and return its raw XML output."""
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
        message = (result.stderr or "").strip()
        if not message:
            message = f"Exit code {result.returncode}"
        raise RuntimeError(f"Nmap scan failed: {message}")

    return result.stdout


async def run_nmap_async(ip: str) -> str:
    """Run Nmap without blocking and return its decoded XML output."""
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
    """Store intelligence and Nmap results for a target IP address."""

    def __init__(
        self,
        ip: str = "",
        vt_data: Optional[dict] = None,
        abuse_data: Optional[dict] = None,
        nmap_ports: Optional[list] = None,
        shodan_data: Optional[dict] = None
    ) -> None:
        """Initialize the dossier with empty or supplied intelligence."""
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
    """Write the complete target dossier to a JSON report file."""
    try:
        with open(output, "w", encoding="utf-8") as report_file:
            json.dump(
                dossier.to_report(),
                report_file,
                indent=2,
                ensure_ascii=False
            )
            report_file.write("\n")
    except (OSError, TypeError, ValueError) as error:
        print(f"[ERROR] Cannot save report: {error}")
        return False

    print(f"[OK] JSON report saved: {output}")
    return True


async def collect_target(ip: str, verbose: int = 0) -> TargetDossier:
    """Collect API intelligence and Nmap results concurrently."""
    dossier = TargetDossier(ip)
    started = time.perf_counter()

    if verbose >= 1:
        print(f"[VERBOSE] Cache lifetime: {CACHE_TTL} seconds.")
        print("[VERBOSE] Maximum parallel API requests: 5.")

    print("[*] Collecting API intelligence...")
    print("[+] Running Nmap...")

    # Keep the original one-argument call for existing integrations.
    api_coro = gather_intel(ip) if not verbose else gather_intel(ip, verbose)
    api_results, nmap_result = await asyncio.gather(
        api_coro,
        run_nmap_async(ip),
        return_exceptions=True
    )

    if isinstance(api_results, Exception):
        print(f"[ERROR] Intelligence queries failed: {api_results}")
        dossier.vt_data = {"error": "Unavailable"}
        dossier.shodan_data = {"error": "Unavailable"}
        dossier.abuse_data = {"error": "Unavailable"}
    else:
        dossier.vt_data = api_results[0]
        dossier.shodan_data = api_results[1]
        dossier.abuse_data = api_results[2]

    if isinstance(nmap_result, Exception):
        print(f"[ERROR] {nmap_result}")
    else:
        dossier.nmap_ports = parse_nmap_xml(nmap_result)
        print("[+] Nmap finished.")

    if verbose >= 2:
        elapsed = time.perf_counter() - started
        print(f"[VERBOSE] Total collection time: {elapsed:.2f}s")

    return dossier


def format_intelligence(data: dict) -> str:
    """Display unavailable API sources without exposing error details."""
    if data.get("error") == "Unavailable":
        return "Unavailable"
    return str(data)


def main() -> None:
    """Collect an IP dossier, display it, and optionally export JSON."""
    parser = argparse.ArgumentParser(
        description="IntelBroker - Threat Intelligence Aggregator"
    )
    parser.add_argument("ip", help="Target IP address to investigate")
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save the complete dossier as a JSON report"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Show extra status messages (use -vv for timings)"
    )
    args = parser.parse_args()

    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        parser.error("Please provide a valid IP address.")

    print(f"[*] Investigating target: {args.ip}")
    if args.verbose:
        dossier = asyncio.run(collect_target(args.ip, args.verbose))
    else:
        dossier = asyncio.run(collect_target(args.ip))

    print("\n===== TARGET DOSSIER =====")
    print(f"Target IP: {dossier.ip}")
    print(f"VirusTotal: {format_intelligence(dossier.vt_data)}")
    print(f"Shodan: {format_intelligence(dossier.shodan_data)}")
    print(f"AbuseIPDB: {format_intelligence(dossier.abuse_data)}")
    print(f"Nmap Open Ports: {dossier.nmap_ports}")
    print("==========================")

    if args.output:
        if not save_report(dossier, args.output):
            raise SystemExit(1)
        print("[SUCCESS] Report generated.")
    else:
        print("[SUCCESS] Intelligence dossier ready.")


if __name__ == "__main__":
    main()
