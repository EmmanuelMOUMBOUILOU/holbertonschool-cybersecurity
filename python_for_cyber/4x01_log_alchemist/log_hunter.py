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
)

SYSLOG_PATTERN = re.compile(
    r'^(?P<date>[A-Z][a-z]{2}\s+\d{1,2}\s+'
    r'\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>[^:]+):\s*'
    r'(?P<message>.*)$'
)


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


def main() -> None:
    """Parse arguments and analyze Apache and Syslog lines."""
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")

    apache_count = 0
    syslog_count = 0

    for line in read_stream(args.file):
        apache_data = parse_apache_line(line)

        if apache_data is not None:
            apache_count += 1
            continue

        syslog_data = parse_syslog_line(line)

        if syslog_data is not None:
            syslog_count += 1

    if apache_count == 0 and syslog_count == 0:
        print("[!] No data to process. Exiting.")
        return

    total_parsed = apache_count + syslog_count

    print("--- Parsing ---")
    print(f"[*] Apache lines:  {apache_count}")
    print(f"[*] Syslog lines:  {syslog_count}")
    print(f"[*] Total parsed:  {total_parsed}")


if __name__ == "__main__":
    main()
