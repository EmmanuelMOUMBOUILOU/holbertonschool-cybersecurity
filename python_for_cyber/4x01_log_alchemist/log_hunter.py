#!/usr/bin/env python3
"""LogHunter - efficient streaming log analysis engine."""

import argparse
import json
import multiprocessing
import re
from collections import Counter, defaultdict, deque
from datetime import datetime


PARALLEL_CHUNK_SIZE = 5000

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
    re.compile(r"onerror\s*=", re.IGNORECASE),
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


def iter_normalized_entries(file_path: str):
    """Yield normalized Apache and Syslog entries from a file."""
    for line in read_stream(file_path):
        apache_data = parse_apache_line(line)

        if apache_data is not None:
            yield normalize_entry(
                apache_data,
                "apache",
                line.rstrip("\n")
            )
            continue

        syslog_data = parse_syslog_line(line)

        if syslog_data is not None:
            yield normalize_entry(
                syslog_data,
                "syslog",
                line.rstrip("\n")
            )


def filter_logs(stream, status_codes=[404, 500]):
    """Yield entries whose HTTP status matches requested codes."""
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


def process_entry(log_entry: LogEntry) -> LogEntry:
    """Enrich and detect threats on one normalized log entry."""
    enrich_ip(log_entry)
    analyze_user_agent(log_entry)
    check_threat_intel(log_entry)
    detect_sqli(log_entry)
    detect_xss(log_entry)

    return log_entry


def iter_processed_entries(file_path: str):
    """Yield fully processed entries sequentially."""
    for entry in iter_normalized_entries(file_path):
        yield process_entry(entry)


def process_chunk(lines):
    """Parse, normalize, enrich, and detect a chunk of log lines."""
    results = []

    for line in lines:
        apache_data = parse_apache_line(line)

        if apache_data is not None:
            entry = normalize_entry(
                apache_data,
                "apache",
                line.rstrip("\n")
            )

            enrich_ip(entry)
            analyze_user_agent(entry)
            check_threat_intel(entry)
            detect_sqli(entry)
            detect_xss(entry)

            results.append(entry)
            continue

        syslog_data = parse_syslog_line(line)

        if syslog_data is not None:
            entry = normalize_entry(
                syslog_data,
                "syslog",
                line.rstrip("\n")
            )

            enrich_ip(entry)
            analyze_user_agent(entry)
            check_threat_intel(entry)
            detect_sqli(entry)
            detect_xss(entry)

            results.append(entry)

    return results


def parallel_analyze(file_path, num_workers, chunk_size):
    """Analyze a log file using multiprocessing workers."""
    if num_workers <= 0:
        return list(iter_processed_entries(file_path))

    if chunk_size <= 0:
        chunk_size = PARALLEL_CHUNK_SIZE

    merged_results = []
    pending_chunks = []
    batch_size = max(num_workers * 2, 1)

    try:
        with multiprocessing.Pool(
            processes=num_workers
        ) as pool:
            with open(
                file_path,
                "r",
                encoding="utf-8"
            ) as log_file:
                chunk = []

                for line in log_file:
                    chunk.append(line)

                    if len(chunk) >= chunk_size:
                        pending_chunks.append(chunk)
                        chunk = []

                    if len(pending_chunks) >= batch_size:
                        batch_results = pool.map(
                            process_chunk,
                            pending_chunks
                        )

                        for result in batch_results:
                            merged_results.extend(result)

                        pending_chunks = []

                if chunk:
                    pending_chunks.append(chunk)

                if pending_chunks:
                    batch_results = pool.map(
                        process_chunk,
                        pending_chunks
                    )

                    for result in batch_results:
                        merged_results.extend(result)

    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return []

    return merged_results


def detect_bruteforce(entries):
    """Yield brute-force alerts for IPs with more than five failures."""
    failure_counts = Counter()

    for entry in entries:
        status = getattr(entry, "status", None)
        message = getattr(entry, "message", "")
        ip = getattr(entry, "ip", "")

        if not ip:
            continue

        if str(status) == "401" or "Failed password" in message:
            failure_counts[ip] += 1

    for ip, count in failure_counts.items():
        if count > 5:
            yield {
                "ip": ip,
                "count": count,
                "alert_type": "BRUTE_FORCE"
            }


def parse_timestamp(timestamp: str):
    """Parse Apache or Syslog timestamps into datetime objects."""
    try:
        parsed = datetime.strptime(
            timestamp,
            "%d/%b/%Y:%H:%M:%S %z"
        )
        return parsed.replace(tzinfo=None)
    except ValueError:
        pass

    try:
        return datetime.strptime(
            timestamp,
            "%b %d %H:%M:%S"
        )
    except ValueError:
        return None


def detect_burst(
    entries,
    window_seconds=60,
    threshold=10
):
    """Yield burst alerts using a sliding time window per IP."""
    windows = defaultdict(deque)
    alerted_ips = set()

    for entry in entries:
        ip = getattr(entry, "ip", "")
        timestamp = getattr(entry, "timestamp", "")

        if not ip or not timestamp:
            continue

        event_time = parse_timestamp(timestamp)

        if event_time is None:
            continue

        ip_window = windows[ip]

        while ip_window:
            age = (event_time - ip_window[0]).total_seconds()

            if age <= window_seconds:
                break

            ip_window.popleft()

        ip_window.append(event_time)

        if (
            len(ip_window) >= threshold
            and ip not in alerted_ips
        ):
            yield {
                "ip": ip,
                "count": len(ip_window),
                "window": window_seconds,
                "alert_type": "BURST"
            }
            alerted_ips.add(ip)


def correlate_events(entries):
    """Correlate scanning and SQL injection behavior by IP."""
    states = defaultdict(set)

    for entry in entries:
        ip = getattr(entry, "ip", "")

        if not ip:
            continue

        if str(getattr(entry, "status", None)) == "404":
            states[ip].add("scanner")

        if getattr(entry, "attack_type", None) == "SQLi":
            states[ip].add("sqli")

        if "scanner" in states[ip] and "sqli" in states[ip]:
            yield {
                "ip": ip,
                "stages": ["scanner", "sqli"],
                "alert_type": "CRITICAL INCIDENT"
            }

            states[ip].clear()


def export_report(alerts, filename, format="json"):
    """Export dict and LogEntry alerts to a JSON report."""
    if format.lower() != "json":
        raise ValueError("Unsupported report format")

    report_data = []

    for alert in alerts:
        if isinstance(alert, dict):
            report_data.append(alert)
        elif isinstance(alert, LogEntry):
            report_data.append(vars(alert).copy())
        else:
            raise TypeError(
                "Alerts must contain dict or LogEntry objects"
            )

    with open(filename, "w", encoding="utf-8") as report_file:
        json.dump(
            report_data,
            report_file,
            indent=2
        )
        report_file.write("\n")


def main() -> None:
    """Parse, analyze, correlate, and report log entries."""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "file",
        help="Path to the log file"
    )

    parser.add_argument(
        "--report",
        help="Export alerts to a JSON report"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Number of multiprocessing workers"
    )

    args = parser.parse_args()

    if args.workers < 0:
        parser.error("--workers must be 0 or greater")

    print("[*] LogHunter - Log Analysis Engine")

    if args.workers > 0:
        print(
            f"[*] Reading: {args.file} "
            f"(parallel: {args.workers} workers)"
        )

        processed_entries = parallel_analyze(
            args.file,
            args.workers,
            PARALLEL_CHUNK_SIZE
        )

        entries_source = processed_entries
    else:
        print(f"[*] Reading: {args.file}")

        processed_entries = None
        entries_source = iter_processed_entries(args.file)

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
    authentication_failures = []

    for entry in entries_source:
        if entry.source == "apache":
            apache_count += 1
        elif entry.source == "syslog":
            syslog_count += 1

        if sample_entry is None:
            sample_entry = entry

        if str(getattr(entry, "status", None)) in {
            "404",
            "500"
        }:
            suspicious_count += 1

        enriched_count += 1

        if getattr(entry, "country", "UNKNOWN") != "UNKNOWN":
            known_ip_count += 1

        if getattr(entry, "is_bot", False):
            bot_count += 1

        if getattr(entry, "alert_level", "LOW") == "HIGH":
            high_alert_count += 1

        if getattr(entry, "attack_type", None) == "SQLi":
            sqli_count += 1
        elif getattr(entry, "attack_type", None) == "XSS":
            xss_count += 1

        status = getattr(entry, "status", None)
        message = getattr(entry, "message", "")

        if (
            str(status) == "401"
            or "Failed password" in message
        ):
            authentication_failures.append(entry)

    if apache_count == 0 and syslog_count == 0:
        print("[!] No data to process. Exiting.")
        return

    brute_force_alerts = list(
        detect_bruteforce(authentication_failures)
    )

    brute_force_alerts = sorted(
        brute_force_alerts,
        key=lambda item: item["count"],
        reverse=True
    )

    if processed_entries is not None:
        burst_source = processed_entries
        correlation_source = processed_entries
    else:
        burst_source = iter_processed_entries(args.file)
        correlation_source = iter_processed_entries(args.file)

    burst_alerts = list(
        detect_burst(burst_source)
    )

    correlation_alerts = list(
        correlate_events(correlation_source)
    )

    all_alerts = (
        brute_force_alerts
        + burst_alerts
        + correlation_alerts
    )

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
    print(
        f"[*] Suspicious (404, 500): "
        f"{suspicious_count}"
    )

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

    print("--- Brute Force ---")
    print(
        f"[*] BRUTE_FORCE alerts: "
        f"{len(brute_force_alerts)}"
    )

    for alert in brute_force_alerts:
        print(
            f"    {alert['ip']}: "
            f"{alert['count']} failures"
        )

    print("--- Burst Detection ---")
    print(f"[*] BURST alerts: {len(burst_alerts)}")

    for alert in burst_alerts:
        print(
            f"    {alert['ip']}: "
            f"{alert['count']} requests in "
            f"{alert['window']}s window"
        )

    print("--- Correlation ---")
    print("[*] CRITICAL INCIDENTS:")

    for alert in correlation_alerts:
        print(
            f"    {alert['ip']}: "
            f"{' -> '.join(alert['stages'])}"
        )

    if args.report:
        try:
            export_report(
                all_alerts,
                args.report
            )

            print(
                f"[*] Report exported: "
                f"{args.report} "
                f"({len(all_alerts)} alerts)"
            )
        except (OSError, TypeError, ValueError) as error:
            print(
                f"[ERROR] Could not export report: "
                f"{error}"
            )
    else:
        print(f"[*] Total alerts: {len(all_alerts)}")
        print("[*] Use --report <file> to export.")


if __name__ == "__main__":
    main()
