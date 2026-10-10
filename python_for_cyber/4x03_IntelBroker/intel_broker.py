#!/usr/bin/env python3
"""Run the IntelBroker CLI and coordinate intelligence collection."""

import argparse
import asyncio
import ipaddress
import time

from api_client import (
    API_SERVICES,
    fetch_api,
    gather_intel,
    query_abuseipdb,
    query_services,
    query_virustotal,
    _query_api
)
from models import TargetDossier
from scanner import parse_nmap_xml, run_nmap, run_nmap_async
from utils import (
    CACHE_TTL,
    format_intelligence,
    get_cached_data,
    load_cache,
    save_cache,
    save_report
)


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
