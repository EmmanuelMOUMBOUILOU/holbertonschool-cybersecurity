#!/usr/bin/env python3
"""Query simulated threat intelligence APIs for IP information."""

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


if __name__ == "__main__":
    print(query_virustotal("1.2.3.4"))
    print(query_abuseipdb("1.2.3.4"))
