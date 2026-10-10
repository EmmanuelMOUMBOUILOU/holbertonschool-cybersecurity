#!/usr/bin/env python3
"""Represent an IP intelligence dossier and its JSON report structure."""

from datetime import datetime, timezone
from typing import Optional


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
