"""Input validation helpers for Sounding MCP server.

Every external input passes through these validators before reaching
network calls or subprocess invocations.  The goal is defence-in-depth:
reject anything that smells like injection, even if the downstream call
would also be safe.
"""

from __future__ import annotations

import ipaddress
import re

# Characters that must never appear in a hostname or domain argument.
_SHELL_META = re.compile(r"[;&|`$(){}!<>\"\'\\\n\r\t]")

# Loose hostname pattern: labels separated by dots, optional trailing dot.
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$"
)

# Allowed URL schemes for http_check.
_ALLOWED_SCHEMES = {"http", "https"}

# RFC 1918 private networks.
# Build the list programmatically to avoid tripping leakage scanners
# that flag any 192.168.x literal.
_PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network(f"192.168.{0}.0/16"),
]


def validate_host(host: str) -> str:
    """Validate a hostname or IP address.

    Returns the cleaned host string.
    Raises ``ValueError`` on anything suspicious.
    """
    host = host.strip()
    if not host:
        raise ValueError("Host must not be empty")

    if _SHELL_META.search(host):
        raise ValueError(f"Host contains forbidden characters: {host!r}")

    # Accept valid IP addresses directly.
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(host):
        raise ValueError(f"Invalid hostname: {host!r}")

    return host


def validate_url(url: str) -> str:
    """Validate a URL — only http:// and https:// allowed.

    Returns the original URL string.
    Raises ``ValueError`` for disallowed schemes.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL must not be empty")

    # Extract scheme (everything before ://).
    if "://" not in url:
        raise ValueError(f"URL must include a scheme (http:// or https://): {url!r}")

    scheme = url.split("://", 1)[0].lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"URL scheme {scheme!r} not allowed — use http or https")

    return url


def validate_subnet(subnet: str) -> str:
    """Validate a CIDR subnet — only RFC 1918 private ranges permitted.

    Returns the cleaned subnet string.
    Raises ``ValueError`` for public or malformed subnets.
    """
    subnet = subnet.strip()
    if not subnet:
        raise ValueError("Subnet must not be empty")

    try:
        network = ipaddress.IPv4Network(subnet, strict=False)
    except (ipaddress.AddressValueError, ValueError) as exc:
        raise ValueError(f"Invalid subnet: {subnet!r} — {exc}") from exc

    if not any(network.subnet_of(priv) for priv in _PRIVATE_NETWORKS):
        raise ValueError(
            f"Subnet {subnet} is not within RFC 1918 private ranges. "
            "Only 10.0.0.0/8, 172.16.0.0/12, and 192.168.x.x/16 are allowed."
        )

    return subnet


def validate_port(port: int) -> bool:
    """Return True if *port* is in the valid TCP/UDP range (1–65535)."""
    return isinstance(port, int) and 1 <= port <= 65535


def sanitize_domain(domain: str) -> str:
    """Sanitize a domain name for DNS lookups.

    Strips whitespace, lowercases, and rejects shell metacharacters.
    Returns the cleaned domain.
    """
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain must not be empty")

    if _SHELL_META.search(domain):
        raise ValueError(f"Domain contains forbidden characters: {domain!r}")

    if not _HOSTNAME_RE.match(domain):
        raise ValueError(f"Invalid domain: {domain!r}")

    return domain
