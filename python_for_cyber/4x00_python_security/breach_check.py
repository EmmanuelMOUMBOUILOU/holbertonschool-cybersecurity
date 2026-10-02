#!/usr/bin/env python3
"""BreachCheck command-line security tool."""

import argparse
import logging
import re
import sys


def setup_logging() -> None:
    """Configure console and file logging."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    file_handler = logging.FileHandler("breach_check.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def read_file(filename: str) -> list:
    """Read a file and return its lines as a list of strings."""
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return file.readlines()
    except FileNotFoundError:
        logging.error("File not found: %s", filename)
        sys.exit(1)
    except PermissionError:
        logging.error("Permission denied: %s", filename)
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


def validate_line(line: str) -> bool:
    """Return True if line follows a valid email:password format."""
    logging.debug("Starting regex check on line: %s", line)
    pattern = r"^[^@\s:]+@[^@\s:]+\.[^@\s:]+:[^:\s]+$"
    return re.fullmatch(pattern, line) is not None


def main() -> None:
    """Parse command-line arguments and run BreachCheck."""
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

    setup_logging()

    logging.info("Processing file: %s", args.file)

    lines = read_file(args.file)
    clean_lines = clean_data(lines)

    for line in clean_lines:
        validate_line(line)


if __name__ == "__main__":
    main()