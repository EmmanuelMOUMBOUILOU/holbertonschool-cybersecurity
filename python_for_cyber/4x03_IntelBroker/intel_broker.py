#!/usr/bin/env python3
"""Query threat intelligence APIs, run Nmap, and parse XML results."""

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


if __name__ == "__main__":
    print(query_virustotal("1.2.3.4"))
    print(query_abuseipdb("1.2.3.4"))

    try:
        xml_output = run_nmap("127.0.0.1")
        print(xml_output)
        print("Open ports:", parse_nmap_xml(xml_output))

    except RuntimeError as error:
        print(f"[ERROR] {error}")
