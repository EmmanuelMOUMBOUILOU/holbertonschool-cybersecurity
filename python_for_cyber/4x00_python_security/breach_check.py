#!/usr/bin/env python3
"""BreachCheck command-line security tool."""

import argparse
import sys


def read_file(filename: str) -> list:
    """Read a file and return its lines as a list of strings."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {filename}", file=sys.stderr)
        sys.exit(1)


def clean_data(lines: list) -> list:
    """Clean raw input lines and return valid data entries."""
    clean_lines = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        clean_lines.append(line)

    return clean_lines


def main() -> None:
    """Parse command-line arguments and start BreachCheck."""
    parser = argparse.ArgumentParser(
        description="Analyze leaked credentials for weak passwords."
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        type=str,
        help="Input file path"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Output report file path"
    )

    args = parser.parse_args()

    print("BreachCheck v1.0 startup...")
    lines = read_file(args.file)
    clean_data(lines)


if __name__ == "__main__":
    main()