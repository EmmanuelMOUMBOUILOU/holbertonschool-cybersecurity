#!/usr/bin/env python3
"""Execute Nmap scans and extract open ports from XML results."""

import asyncio
import subprocess
import xml.etree.ElementTree as ET


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
