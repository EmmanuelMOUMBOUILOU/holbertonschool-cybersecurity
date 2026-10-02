#!/usr/bin/env python3
"""Unit tests for the BreachCheck security tool."""

import unittest

from breach_check import check_policy
from utils import hash_password, validate_line


class TestBreachCheck(unittest.TestCase):
    """Test BreachCheck validation, policy, and hashing functions."""

    def test_validate_line_valid(self) -> None:
        """Test a valid email and password format."""
        self.assertTrue(validate_line("user@example.com:Password123"))

    def test_validate_line_invalid_format(self) -> None:
        """Test an invalid credential separator."""
        self.assertFalse(validate_line("user@example.com;Password123"))

    def test_validate_line_missing_parts(self) -> None:
        """Test credentials with missing parts."""
        self.assertFalse(validate_line("user@example.com:"))
        self.assertFalse(validate_line(":Password123"))

    def test_policy_short_password(self) -> None:
        """Test that a short password is weak."""
        self.assertEqual(check_policy("abc123"), "WEAK")

    def test_policy_numeric_password(self) -> None:
        """Test that the common numeric password is weak."""
        self.assertEqual(check_policy("123456"), "WEAK")

    def test_policy_compliant_password(self) -> None:
        """Test a compliant password."""
        self.assertEqual(check_policy("Secure123"), "COMPLIANT")

    def test_hash_password_consistency(self) -> None:
        """Test that identical inputs produce identical hashes."""
        first_hash = hash_password("Secure123", "testsalt")
        second_hash = hash_password("Secure123", "testsalt")

        self.assertEqual(first_hash, second_hash)


if __name__ == "__main__":
    unittest.main()