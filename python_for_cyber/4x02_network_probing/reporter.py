#!/usr/bin/env python3
"""JSON report creation and file export."""

import json

from scanner import check_vulnerability


def build_json_report(results: list) -> list:
    """Convert scan results to JSON-ready open-port records."""
    report = []
    marker = " [VULNERABLE]"

    for result in results:
        service = result["service"]
        if service.endswith(marker):
            service = service[:-len(marker)]

        report.append({
            "port": result["port"],
            "state": "open",
            "service": service,
            "vulnerability": (
                "YES" if check_vulnerability(service) else "NO"
            )
        })

    return report


def save_json_report(results: list, filename: str) -> bool:
    """Write the JSON report and return True on success."""
    try:
        with open(filename, "w", encoding="utf-8") as report_file:
            json.dump(build_json_report(results), report_file, indent=2)
            report_file.write("\n")
    except (OSError, TypeError, KeyError) as error:
        print(f"[ERROR] Could not export JSON report: {error}")
        return False

    print(f"[*] Report saved: {filename}")
    return True
