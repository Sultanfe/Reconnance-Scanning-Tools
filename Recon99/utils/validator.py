"""
utils/validator.py
Recon99 — Target input validation and normalization
Author: FMShomit
"""

import re
import socket
from urllib.parse import urlparse


def normalize_target(target: str) -> dict:
    """
    Accept a domain, subdomain, URL, or IP and return a structured dict:
      {
        "raw":      original input,
        "url":      https://... base URL,
        "host":     hostname or IP,
        "scheme":   http or https,
        "is_ip":    bool,
      }
    Raises ValueError on invalid input.
    """
    target = target.strip().rstrip("/")

    # Add scheme if missing
    if not target.startswith(("http://", "https://")):
        # Check if HTTPS is reachable; fall back to HTTP
        target = "https://" + target

    parsed = urlparse(target)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"

    if not host:
        raise ValueError(f"Cannot parse host from: {target}")

    is_ip = _is_ip(host)

    # Build clean base URL (no trailing path for recon)
    port = parsed.port
    if port and port not in (80, 443):
        base_url = f"{scheme}://{host}:{port}"
    else:
        base_url = f"{scheme}://{host}"

    return {
        "raw":    target,
        "url":    base_url,
        "host":   host,
        "scheme": scheme,
        "is_ip":  is_ip,
    }


def _is_ip(host: str) -> bool:
    """Return True if the host is an IPv4 or IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        pass
    return False


def is_valid_target(host: str) -> bool:
    """Basic sanity check: resolves or is IP."""
    if _is_ip(host):
        return True
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
