#!/usr/bin/env python3
"""Query mock intelligence APIs asynchronously with caching and limits."""

import asyncio
import time
from typing import Optional

import aiohttp

from utils import get_cached_data, load_cache, save_cache


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
