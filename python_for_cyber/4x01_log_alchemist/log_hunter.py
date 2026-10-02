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


class LogEntry:
    """Represent a normalized security log entry."""

    def __init__(
        self,
        ip: str,
        timestamp: str,
        service: str,
        message: str,
        raw_line: str
    ) -> None:
        """Initialize a normalized log entry."""
        self.ip = ip
        self.timestamp = timestamp
        self.service = service
        self.message = message
        self.raw_line = raw_line


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
        entry = LogEntry(
            ip=parsed_dict.get("ip", ""),
            timestamp=parsed_dict.get("date", ""),
            service="http",
            message=parsed_dict.get("path", ""),
            raw_line=raw_line
        )

        entry.method = parsed_dict.get("method", "")
        entry.path = parsed_dict.get("path", "")

        try:
            entry.status = int(parsed_dict.get("status", 0))
        except (TypeError, ValueError):
            entry.status = 0

        entry.user_agent = parsed_dict.get("user_agent") or ""

        return entry

    if log_type == "syslog":
        message = parsed_dict.get("message", "")
        ip_match = IP_PATTERN.search(message)
        source_ip = ip_match.group(0) if ip_match else ""

        return LogEntry(
            ip=source_ip,
            timestamp=parsed_dict.get("date", ""),
            service="ssh",
            message=message,
            raw_line=raw_line
        )

    return LogEntry(
        ip="",
        timestamp="",
        service="",
        message="",
        raw_line=raw_line
    )


def main() -> None:
    """Parse, normalize, and summarize Apache and Syslog lines."""
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")

    apache_count = 0
    syslog_count = 0
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


if __name__ == "__main__":
    main()
