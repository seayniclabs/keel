"""Integration tests for Sounding MCP tools.

These tests call the tool functions directly (not through the MCP transport)
to verify network functionality against the Docker Compose test targets.
"""

from __future__ import annotations

import pytest

from sounding.server import (
    check_ssl_cert,
    dns_lookup,
    get_public_ip,
    health,
    http_check,
    ping,
    port_check,
    port_scan,
    reverse_dns,
    subnet_scan,
    traceroute,
    whois_lookup,
)
from sounding import __version__


# ── health ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health_returns_version():
    result = await health()
    assert result["status"] == "ok"
    assert result["version"] == __version__


# ── ping ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ping_localhost():
    """Ping localhost — TCP connect to port 80 may fail, but the call
    should not raise."""
    result = await ping("localhost", count=2, timeout=2)
    assert result["host"] == "localhost"
    assert "success" in result


@pytest.mark.asyncio
async def test_ping_web_target(web_target):
    """Ping the Docker web target — port 80 is open."""
    host, _port = web_target.split(":")
    result = await ping(host, count=2, timeout=5)
    assert result["host"] == host


# ── dns_lookup ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dns_lookup_google():
    """Lookup google.com A records — should return at least one."""
    result = await dns_lookup("google.com", record_type="A")
    assert result["domain"] == "google.com"
    assert len(result["records"]) >= 1


@pytest.mark.asyncio
async def test_dns_lookup_invalid_type():
    """Invalid record type should raise ValueError."""
    with pytest.raises(ValueError, match="record_type must be one of"):
        await dns_lookup("google.com", record_type="INVALID")


# ── port_check ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_port_check_open(web_target):
    """Port 18080 on web-target should be open."""
    host, port = web_target.split(":")
    result = await port_check(host, int(port), timeout=3)
    assert result["state"] == "open"


@pytest.mark.asyncio
async def test_port_check_closed(web_target):
    """Port 9999 should be closed."""
    host, _port = web_target.split(":")
    result = await port_check(host, 9999, timeout=2)
    assert result["state"] == "closed"


# ── port_scan ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_port_scan_over_100_rejected():
    """Requesting more than 100 ports should raise ValueError."""
    with pytest.raises(ValueError, match="limited to 100"):
        await port_scan("localhost", ports=list(range(1, 102)))


@pytest.mark.asyncio
async def test_port_scan_small(web_target):
    """Scan a few ports on web-target."""
    host, port = web_target.split(":")
    result = await port_scan(host, ports=[int(port), 9999])
    assert result["ports_scanned"] == 2
    open_ports = [r["port"] for r in result["open_ports"]]
    assert int(port) in open_ports


# ── command injection ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_injection_semicolon():
    """Semicolon in host should be rejected."""
    with pytest.raises(ValueError, match="forbidden characters"):
        await ping("localhost; rm -rf /")


@pytest.mark.asyncio
async def test_injection_pipe():
    """Pipe in host should be rejected."""
    with pytest.raises(ValueError, match="forbidden characters"):
        await port_check("localhost | cat /etc/passwd", 80)


@pytest.mark.asyncio
async def test_injection_backtick():
    """Backtick in host should be rejected."""
    with pytest.raises(ValueError, match="forbidden characters"):
        await dns_lookup("`whoami`.example.com")


# ── http_check ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_http_check_web_target(web_target):
    """HTTP check against the Docker web target."""
    host, port = web_target.split(":")
    result = await http_check(f"http://{host}:{port}/")
    assert result["status_code"] == 200
    assert result["total_ms"] > 0


@pytest.mark.asyncio
async def test_http_check_file_url_rejected():
    """file:// URLs must be rejected."""
    with pytest.raises(ValueError, match="not allowed"):
        await http_check("file:///etc/passwd")


@pytest.mark.asyncio
async def test_http_check_ftp_url_rejected():
    """ftp:// URLs must be rejected."""
    with pytest.raises(ValueError, match="not allowed"):
        await http_check("ftp://example.com")


# ── subnet_scan ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_subnet_scan_public_rejected():
    """Public subnets must be rejected."""
    with pytest.raises(ValueError, match="not within RFC 1918"):
        await subnet_scan("8.8.8.0/24")


@pytest.mark.asyncio
async def test_subnet_scan_private_allowed():
    """A small private subnet scan should not raise."""
    result = await subnet_scan("10.255.255.0/30")
    assert result["subnet"] == "10.255.255.0/30"
    assert "hosts_found" in result


# ── check_ssl_cert ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ssl_cert_badssl():
    """Check SSL cert on a known host (may fail in CI without network)."""
    # Use the web target if ssl-target not available; just verify the call shape.
    result = await check_ssl_cert("expired.badssl.com", port=443)
    # The call should return a dict regardless of cert validity.
    assert "host" in result


# ── reverse_dns ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reverse_dns_shape():
    """reverse_dns should return the expected dict shape."""
    result = await reverse_dns("8.8.8.8")
    assert "ip" in result
    assert "hostnames" in result or "error" in result


# ── whois_lookup ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_whois_shape():
    """whois_lookup should return the expected dict shape."""
    result = await whois_lookup("google.com")
    assert result["domain"] == "google.com"
    assert "raw" in result or "error" in result


# ── traceroute ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_traceroute_shape():
    """traceroute should return the expected dict shape."""
    result = await traceroute("localhost", max_hops=3)
    assert "host" in result
    assert "hops" in result or "error" in result
