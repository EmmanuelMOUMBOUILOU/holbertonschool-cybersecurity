#!/usr/bin/env python3
"""LogHunter - efficient streaming log analysis engine."""

import argparse
import re


APACHE_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'.*?\[(?P<date>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+'
    r'(?P<path>.*?)'
    r'(?:\s+HTTP/\d(?:\.\d+)?)?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"[^"]*"\s+"(?P<user_agent>[^"]*)")?'
)

SYSLOG_PATTERN = re.compile(
    r'^(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+'
    r'\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[^:]+):\s*'
    r'(?P<message>.*)$'
)

IP_PATTERN = re.compile(
    r'\b\d{1,3}(?:\.\d{1,3}){3}\b'
)

SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(
        r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1",
        re.IGNORECASE
    ),
    re.compile(r"drop\s+table", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
]

GEOIP_DB = {
    "1.2.3.4": "US",
    "5.6.7.8": "RU"
}

BOT_SIGNATURES = (
    "sqlmap",
    "nikto",
    "curl",
    "python"
)

BLACKLIST = {
    "10.0.0.1",
    "192.168.1.66"
}


class LogEntry:
    """Represent a normalized security log entry."""

    def __init__(
        self,
        ip: str = "",
        timestamp: str = "",
        service: str = "",
        message: str = "",
        raw_line: str = "",
        method: str = "",
        path: str = "",
        status=None,
        size=None,
        user_agent: str = "",
        source: str = ""
    ) -> None:
        """Initialize a normalized log entry."""
        self.ip = ip
        self.timestamp = timestamp
        self.service = service
        self.message = message
        self.raw_line = raw_line
        self.method = method
        self.path = path
        self.status = status
        self.size = size
        self.user_agent = user_agent
        self.source = source
        self.attack_type = None


def read_stream(file_path: str):
    """Yield one line at a time from a log file."""
    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line in log_file:
                yield line
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")


def parse_apache_line(line: str) -> dict:
    """Parse an Apache log line and return its extracted fields."""
    match = APACHE_PATTERN.search(line)

    if match is None:
        return None

    return match.groupdict()


def parse_syslog_line(line: str) -> dict:
    """Parse a Syslog line and return its extracted fields."""
    match = SYSLOG_PATTERN.search(line)

    if match is None:
        return None

    return match.groupdict()


def normalize_entry(
    parsed_dict: dict,
    log_type: str,
    raw_line: str = ""
) -> LogEntry:
    """Normalize parsed Apache or Syslog data into a LogEntry."""
    if log_type == "apache":
        try:
            status = int(parsed_dict.get("status", 0))
        except (TypeError, ValueError):
            status = 0

        return LogEntry(
            ip=parsed_dict.get("ip", ""),
            timestamp=parsed_dict.get("date", ""),
            service="http",
            message=parsed_dict.get("path", ""),
            raw_line=raw_line,
            method=parsed_dict.get("method", ""),
            path=parsed_dict.get("path", ""),
            status=status,
            size=parsed_dict.get("size"),
            user_agent=parsed_dict.get("user_agent") or "",
            source="apache"
        )

    if log_type == "syslog":
        message = parsed_dict.get("message", "")
        ip_match = IP_PATTERN.search(message)
        source_ip = ip_match.group(0) if ip_match else ""

        return LogEntry(
            ip=source_ip,
            timestamp=parsed_dict.get("date", ""),
            service="ssh",
            message=message,
            raw_line=raw_line,
            source="syslog"
        )

    return LogEntry(
        raw_line=raw_line,
        source=log_type
    )


def filter_logs(stream, status_codes=[404, 500]):
    """Yield entries whose HTTP status matches the requested codes."""
    for entry in stream:
        if getattr(entry, "status", None) in status_codes:
            yield entry


def enrich_ip(log_entry: LogEntry) -> LogEntry:
    """Add GeoIP country information to a normalized log entry."""
    log_entry.country = GEOIP_DB.get(log_entry.ip, "UNKNOWN")
    return log_entry


def analyze_user_agent(log_entry: LogEntry) -> LogEntry:
    """Detect known automated tool signatures in a log entry."""
    user_agent = getattr(log_entry, "user_agent", "")
    message = getattr(log_entry, "message", "")
    raw_line = getattr(log_entry, "raw_line", "")

    searchable_text = f"{user_agent} {message} {raw_line}".lower()

    log_entry.is_bot = any(
        signature in searchable_text
        for signature in BOT_SIGNATURES
    )

    return log_entry


def check_threat_intel(log_entry: LogEntry) -> LogEntry:
    """Set alert level based on known malicious IP addresses."""
    if log_entry.ip in BLACKLIST:
        log_entry.alert_level = "HIGH"
    else:
        log_entry.alert_level = "LOW"

    return log_entry


def detect_sqli(log_entry: LogEntry) -> LogEntry:
    """Detect SQL injection signatures in the request path."""
    path = getattr(log_entry, "path", "")

    for pattern in SQLI_PATTERNS:
        if pattern.search(path):
            log_entry.attack_type = "SQLi"
            break

    return log_entry


def detect_xss(log_entry: LogEntry) -> LogEntry:
    """Detect XSS without overwriting an existing attack type."""
    if getattr(log_entry, "attack_type", None) is not None:
        return log_entry

    path = getattr(log_entry, "path", "")

    for pattern in XSS_PATTERNS:
        if pattern.search(path):
            log_entry.attack_type = "XSS"
            break

    return log_entry


def main() -> None:
    """Parse, enrich, and analyze log entries."""
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")

    apache_count = 0
    syslog_count = 0
    suspicious_count = 0
    enriched_count = 0
    known_ip_count = 0
    bot_count = 0
    high_alert_count = 0
    sqli_count = 0
    xss_count = 0
    sample_entry = None

    for line in read_stream(args.file):
        apache_data = parse_apache_line(line)

        if apache_data is not None:
            apache_count += 1
            entry = normalize_entry(
                apache_data,
                "apache",
                line.rstrip("\n")
            )

            if sample_entry is None:
                sample_entry = entry

            for _ in filter_logs((entry,)):
                suspicious_count += 1

            enrich_ip(entry)
            enriched_count += 1

            if entry.country != "UNKNOWN":
                known_ip_count += 1

            analyze_user_agent(entry)

            if entry.is_bot:
                bot_count += 1

            check_threat_intel(entry)

            if entry.alert_level == "HIGH":
                high_alert_count += 1

            detect_sqli(entry)
            detect_xss(entry)

            if entry.attack_type == "SQLi":
                sqli_count += 1
            elif entry.attack_type == "XSS":
                xss_count += 1

            continue

        syslog_data = parse_syslog_line(line)

        if syslog_data is not None:
            syslog_count += 1
            entry = normalize_entry(
                syslog_data,
                "syslog",
                line.rstrip("\n")
            )

            if sample_entry is None:
                sample_entry = entry

            for _ in filter_logs((entry,)):
                suspicious_count += 1

            enrich_ip(entry)
            enriched_count += 1

            if entry.country != "UNKNOWN":
                known_ip_count += 1

            analyze_user_agent(entry)

            if entry.is_bot:
                bot_count += 1

            check_threat_intel(entry)

            if entry.alert_level == "HIGH":
                high_alert_count += 1

    if apache_count == 0 and syslog_count == 0:
        print("[!] No data to process. Exiting.")
        return

    total_parsed = apache_count + syslog_count

    print("--- Parsing ---")
    print(f"[*] Apache lines:  {apache_count}")
    print(f"[*] Syslog lines:  {syslog_count}")
    print(f"[*] Total parsed:  {total_parsed}")

    if sample_entry is not None:
        print("[*] Sample entry:")

        if sample_entry.service == "http":
            print(
                f"    ip={sample_entry.ip} | "
                f"service={sample_entry.service} | "
                f"status={sample_entry.status} | "
                f"path={sample_entry.path}"
            )
        else:
            print(
                f"    ip={sample_entry.ip} | "
                f"service={sample_entry.service} | "
                f"message={sample_entry.message}"
            )

    print("--- Filtering ---")
    print(f"[*] Suspicious (404, 500): {suspicious_count}")

    print("--- Enrichment ---")
    print(
        f"[*] GeoIP: {enriched_count} entries enriched "
        f"({known_ip_count} known IPs)"
    )
    print(f"[*] Bots detected: {bot_count}")

    print("--- Threat Intelligence ---")
    print(
        f"[*] HIGH alerts: {high_alert_count} "
        "entries from blacklisted IPs"
    )

    print("--- Attack Detection ---")
    print(f"[*] SQLi attempts: {sqli_count}")
    print(f"[*] XSS attempts:  {xss_count}")


if __name__ == "__main__":
    main()
