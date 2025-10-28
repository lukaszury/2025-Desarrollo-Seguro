#!/usr/bin/env python3
"""
Regression Test: SQL Injection Mitigation

This test validates that the SQL injection vulnerability in the invoice listing
functionality has been properly mitigated.

Vulnerability Description:
The vulnerable version (main branch) uses string concatenation in SQL queries:
  q.andWhereRaw(" status " + operator + " '" + status + "'")
This allows SQL injection through malicious status/operator parameters.

Mitigation:
The secure version (practico-2) implements:
1. Operator whitelisting with allowed operators
2. Input validation for status parameter
3. Parameterized queries using knex.js instead of raw string concatenation

Test Strategy:
- Attempt various SQL injection payloads that would work on vulnerable version
- Verify that all malicious payloads are rejected with appropriate error messages
- Confirm that legitimate queries still work correctly
- Ensure no information leakage occurs
"""

import requests
import json
import sys
import urllib.parse
import pytest

# Configuration
BASE_URL = "http://localhost:5000"
USERNAME = "test"
PASSWORD = "password"


class TestSQLInjectionRegression:
    """Test class for SQL injection regression testing"""

    @pytest.fixture(scope="class")
    def auth_token(self):
        """Fixture to get authentication token for tests"""
        url = f"{BASE_URL}/auth/login"
        data = {"username": USERNAME, "password": PASSWORD}

        try:
            response = requests.post(url, json=data)
            assert response.status_code == 200, f"Login failed: {response.status_code}"
            token = response.json()["token"]
            assert token, "No token received"
            return token
        except Exception as e:
            pytest.fail(f"Authentication failed: {e}")

    def test_basic_sql_injection_payloads_rejected(self, auth_token):
        """Test that basic SQL injection payloads are properly rejected"""

        malicious_payloads = [
            ("paid' OR '1'='1", "=", "Bypass authentication"),
            ("paid' UNION SELECT 1,2,3,4,5--", "=", "Basic UNION injection"),
            ("paid'; DROP TABLE invoices; --", "=", "Destructive injection"),
            ("paid' UNION SELECT table_name,column_name,data_type,null,null FROM information_schema.columns--", "=", "Schema extraction"),
            ("paid' AND 1=1", "=", "Logic bypass"),
            ("paid' AND 1=2", "=", "Logic bypass negative"),
            ("paid' OR 1=1--", "=", "Comment injection"),
            ("paid' /*", "=", "Block comment"),
            ("paid' || 'test'", "=", "Concatenation injection"),
            ("paid'; SELECT * FROM users--", "=", "Multi-statement injection"),
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for status, operator, description in malicious_payloads:
            print(f"\nTesting: {description}")
            encoded_status = urllib.parse.quote(status)
            encoded_operator = urllib.parse.quote(operator)

            url = f"{BASE_URL}/invoices?status={encoded_status}&operator={encoded_operator}"

            try:
                response = requests.get(url, headers=headers, timeout=10)

                # Check that injection is blocked
                assert response.status_code != 200, f"SQL injection succeeded for {description}: {response.status_code}"

                # Should get validation error or 500, but not successful execution
                if response.status_code == 400:
                    # Good - validation error
                    error_data = response.json() if response.headers.get('content-type') == 'application/json' else {}
                    print(f"✓ Properly rejected with validation error: {error_data}")
                elif response.status_code == 500:
                    # Acceptable - server error due to invalid SQL
                    error_text = response.text[:200]
                    assert "syntax error" not in error_text.lower(), f"SQL syntax error leaked: {error_text}"
                    print(f"✓ Properly rejected with server error (mitigated)")
                else:
                    pytest.fail(f"Unexpected response for {description}: {response.status_code} - {response.text}")

            except requests.exceptions.RequestException as e:
                # Connection errors are acceptable as long as injection doesn't succeed
                print(f"✓ Request blocked (connection error): {e}")

    def test_operator_validation(self, auth_token):
        """Test that only allowed operators are accepted"""

        invalid_operators = [
            "LIKE",  # Valid but without proper validation
            "NOT LIKE",  # Valid but without proper validation
            "INVALID_OP",  # Invalid operator
            "OR",  # Dangerous operator
            "AND",  # Dangerous operator
            ";",  # Dangerous character
            "--",  # Comment character
            "/*",  # Block comment
            "UNION",  # Dangerous keyword
            "DROP",  # Dangerous keyword
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for operator in invalid_operators:
            print(f"\nTesting invalid operator: {operator}")
            encoded_operator = urllib.parse.quote(operator)
            url = f"{BASE_URL}/invoices?status=paid&operator={encoded_operator}"

            try:
                response = requests.get(url, headers=headers, timeout=10)

                # Should not succeed
                assert response.status_code != 200, f"Invalid operator {operator} was accepted: {response.status_code}"

                if response.status_code == 400:
                    print(f"✓ Operator {operator} properly rejected")
                elif response.status_code == 500:
                    error_text = response.text[:200]
                    # Make sure it's not a successful injection
                    assert "UNION" not in error_text and "SELECT" not in error_text, f"Possible injection with operator {operator}"
                    print(f"✓ Operator {operator} blocked with server error")

            except requests.exceptions.RequestException as e:
                print(f"✓ Operator {operator} blocked (connection error): {e}")

    def test_status_parameter_validation(self, auth_token):
        """Test that malicious characters in status parameter are rejected"""

        malicious_statuses = [
            "paid' OR '1'='1",
            "paid'; DROP TABLE invoices; --",
            "paid' UNION SELECT * FROM users--",
            "paid'/*",
            "paid'--",
            "paid';--",
            "paid' AND 1=1 UNION SELECT password FROM users--",
            "paid<script>alert('xss')</script>",  # XSS attempt
            "paid../../../etc/passwd",  # Path traversal
            "paid' || (SELECT password FROM users LIMIT 1)--",  # Subquery injection
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for status in malicious_statuses:
            print(f"\nTesting malicious status: {status[:50]}...")
            encoded_status = urllib.parse.quote(status)
            url = f"{BASE_URL}/invoices?status={encoded_status}&operator=="

            try:
                response = requests.get(url, headers=headers, timeout=10)

                assert response.status_code != 200, f"Malicious status parameter accepted: {status[:50]}"

                if response.status_code == 400:
                    print(f"✓ Malicious status properly rejected: {status[:30]}...")
                elif response.status_code == 500:
                    error_text = response.text[:200]
                    assert not any(keyword in error_text.upper() for keyword in ["UNION", "SELECT", "DROP"]), f"Possible injection success with status: {status[:30]}"
                    print(f"✓ Malicious status blocked: {status[:30]}...")

            except requests.exceptions.RequestException as e:
                print(f"✓ Malicious status blocked (connection error): {status[:30]}...")

    def test_legitimate_queries_still_work(self, auth_token):
        """Test that legitimate queries continue to work after mitigation"""

        legitimate_queries = [
            ("paid", "=", "Exact status match"),
            ("unpaid", "=", "Exact status match"),
            ("pending", "=", "Exact status match"),
            ("paid", "!=", "Not equal operator"),
            ("paid", ">", "Greater than (invalid for status but tests validation)"),
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for status, operator, description in legitimate_queries:
            print(f"\nTesting legitimate query: {description} ({status} {operator})")
            encoded_status = urllib.parse.quote(status)
            encoded_operator = urllib.parse.quote(operator)

            url = f"{BASE_URL}/invoices?status={encoded_status}&operator={encoded_operator}"

            try:
                response = requests.get(url, headers=headers, timeout=10)

                # For string status with > operator, should be rejected
                if operator == ">":
                    assert response.status_code in [400, 500], f"Invalid operator should be rejected: {operator}"
                    print(f"✓ Invalid operator properly rejected: {operator}")
                else:
                    # Valid queries should work (may return 200 or 404 if no data)
                    assert response.status_code in [200, 404], f"Valid query failed: {response.status_code} - {response.text[:200]}"
                    print(f"✓ Legitimate query works: {status} {operator}")

            except requests.exceptions.RequestException as e:
                # Connection errors for valid queries are unexpected
                if operator != ">":
                    pytest.fail(f"Valid query failed with connection error: {e}")
                else:
                    print(f"✓ Invalid operator properly blocked: {operator}")

    def test_no_information_leakage(self, auth_token):
        """Test that error messages don't leak sensitive information"""

        malicious_payloads = [
            "paid' UNION SELECT table_name FROM information_schema.tables--",
            "paid' UNION SELECT column_name FROM information_schema.columns--",
            "paid'; SHOW TABLES;--",
            "paid'; SELECT database();--",
        ]

        headers = {"Authorization": f"Bearer {auth_token}"}

        for payload in malicious_payloads:
            encoded_payload = urllib.parse.quote(payload)
            url = f"{BASE_URL}/invoices?status={encoded_payload}&operator=="

            try:
                response = requests.get(url, headers=headers, timeout=10)

                if response.status_code == 500:
                    error_text = response.text.lower()
                    # Ensure no database information is leaked
                    assert not any(keyword in error_text for keyword in [
                        "table", "column", "database", "schema", "mysql", "postgresql"
                    ]), f"Information leakage detected in error: {response.text[:300]}"

                    print(f"✓ No information leakage for payload: {payload[:30]}...")

            except requests.exceptions.RequestException:
                print(f"✓ Request blocked for payload: {payload[:30]}...")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
