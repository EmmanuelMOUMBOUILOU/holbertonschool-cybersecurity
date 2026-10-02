#!/usr/bin/env python3
"""LogHunter - efficient streaming log analysis engine."""

import argparse


def read_stream(file_path: str):
    """Yield one line at a time from a log file."""
    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            for line in log_file:
                yield line
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")


def main() -> None:
    """Parse arguments and count log lines from the input stream."""
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="Path to the log file")
    args = parser.parse_args()

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")

    line_count = 0

    for _ in read_stream(args.file):
        line_count += 1

    if line_count == 0:
        print("[!] No data to process. Exiting.")
        return

    print(f"[*] Lines read: {line_count}")


if __name__ == "__main__":
    main()
