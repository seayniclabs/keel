"""Unit tests for sounding.validators — no network or Docker needed."""

from __future__ import annotations

import pytest

from sounding.validators import (
    sanitize_domain,
    validate_host,
    validate_port,
    validate_subnet,
    validate_url,
)


# ── validate_host ──────────────────────────────────────────────────────────


class TestValidateHost:
    def test_valid_hostname(self):
        assert validate_host("example.com") == "example.com"

    def test_valid_ip(self):
        assert validate_host("1.2.3.4") == "1.2.3.4"

    def test_valid_ipv6(self):
        assert validate_host("::1") == "::1"

    def test_strips_whitespace(self):
        assert validate_host("  example.com  ") == "example.com"

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_host("")

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("example.com; rm -rf /")

    def test_rejects_pipe(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("example.com | cat /etc/passwd")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("`whoami`.example.com")

    def test_rejects_dollar(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("$(whoami).example.com")

    def test_rejects_ampersand(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("example.com & echo pwned")

    def test_rejects_newline(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            validate_host("example.com\n; echo pwned")

    def test_localhost(self):
        assert validate_host("localhost") == "localhost"

    def test_subdomain(self):
        assert validate_host("sub.domain.example.com") == "sub.domain.example.com"


# ── validate_url ───────────────────────────────────────────────────────────


class TestValidateUrl:
    def test_http(self):
        assert validate_url("http://example.com") == "http://example.com"

    def test_https(self):
        assert validate_url("https://example.com/path") == "https://example.com/path"

    def test_rejects_file(self):
        with pytest.raises(ValueError, match="not allowed"):
            validate_url("file:///etc/passwd")

    def test_rejects_ftp(self):
        with pytest.raises(ValueError, match="not allowed"):
            validate_url("ftp://example.com")

    def test_rejects_no_scheme(self):
        with pytest.raises(ValueError, match="must include a scheme"):
            validate_url("example.com")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_url("")

    def test_rejects_javascript(self):
        with pytest.raises(ValueError):
            validate_url("javascript:alert(1)")

    def test_strips_whitespace(self):
        assert validate_url("  https://example.com  ") == "https://example.com"


# ── validate_subnet ────────────────────────────────────────────────────────


class TestValidateSubnet:
    def test_private_192(self):
        assert validate_subnet("192.168.1.0/24") == "192.168.1.0/24"

    def test_private_10(self):
        assert validate_subnet("10.0.0.0/24") == "10.0.0.0/24"

    def test_private_172(self):
        assert validate_subnet("172.16.0.0/24") == "172.16.0.0/24"

    def test_rejects_public(self):
        with pytest.raises(ValueError, match="not within RFC 1918"):
            validate_subnet("8.8.8.0/24")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            validate_subnet("")

    def test_rejects_garbage(self):
        with pytest.raises(ValueError, match="Invalid subnet"):
            validate_subnet("not-a-subnet")

    def test_rejects_172_32(self):
        """172.32.x.x is outside the 172.16-31 private range."""
        with pytest.raises(ValueError, match="not within RFC 1918"):
            validate_subnet("172.32.0.0/24")


# ── validate_port ──────────────────────────────────────────────────────────


class TestValidatePort:
    def test_valid_port(self):
        assert validate_port(80) is True

    def test_port_1(self):
        assert validate_port(1) is True

    def test_port_65535(self):
        assert validate_port(65535) is True

    def test_port_0(self):
        assert validate_port(0) is False

    def test_port_negative(self):
        assert validate_port(-1) is False

    def test_port_too_high(self):
        assert validate_port(65536) is False

    def test_port_string(self):
        assert validate_port("80") is False  # type: ignore


# ── sanitize_domain ────────────────────────────────────────────────────────


class TestSanitizeDomain:
    def test_basic(self):
        assert sanitize_domain("Example.COM") == "example.com"

    def test_strips_whitespace(self):
        assert sanitize_domain("  example.com  ") == "example.com"

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            sanitize_domain("example.com; rm -rf /")

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="must not be empty"):
            sanitize_domain("")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError, match="forbidden characters"):
            sanitize_domain("`whoami`.com")
