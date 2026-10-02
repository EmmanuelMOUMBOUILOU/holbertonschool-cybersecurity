#!/usr/bin/env python3
"""BreachCheck command-line security tool."""

import argparse
import configparser
import logging
import sys

from utils import clean_data, hash_password, validate_line


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


def load_config(filename: str = "config.ini") -> configparser.ConfigParser:
    """Load the security configuration or exit if it is missing."""
    config = configparser.ConfigParser()

    if not config.read(filename):
        logging.error("config file missing")
        sys.exit(1)

    return config


def check_policy(password: str, min_length: int = 8) -> str:
    """Return WEAK or COMPLIANT according to password policy."""
    common_passwords = {"password", "123456"}

    if len(password) < min_length:
        return "WEAK"

    if password.isalpha():
        return "WEAK"

    if password in common_passwords:
        return "WEAK"

    return "COMPLIANT"


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

    config = load_config()
    salt = config.get("SECURITY", "Salt")
    min_length = config.getint("SECURITY", "MinLength")

    logging.debug("Security configuration loaded")
    logging.debug("Minimum password length: %d", min_length)
    logging.debug("Salt configured: %s", bool(salt))

    logging.info("Processing file: %s", args.file)

    lines = read_file(args.file)
    clean_lines = clean_data(lines)

    for line in clean_lines:
        validate_line(line)


if __name__ == "__main__":
    main()