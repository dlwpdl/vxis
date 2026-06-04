"""Target identity helpers for Persistent Target Intelligence."""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit

DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
}


def hash_text(value: str) -> str:
    """Return the SHA-256 hex digest for a UTF-8 string."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_target_url(target_url: str) -> str:
    """Normalize a target URL to the PTI identity tuple: scheme, host, and port."""

    target = target_url.strip()
    if not target:
        raise ValueError("target_url cannot be empty")

    if target.startswith("//"):
        target = f"https:{target}"
    elif "://" not in target:
        target = f"https://{target}"

    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()
    if not scheme:
        raise ValueError("target_url must include a scheme")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("target_url must include a host")

    host = _normalize_hostname(hostname)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("target_url contains an invalid port") from exc

    if port is None:
        port = DEFAULT_PORTS.get(scheme)
    if port is None:
        raise ValueError(f"target_url must include a port for scheme {scheme!r}")

    host_for_url = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{host_for_url}:{port}"


def target_hash_for_url(target_url: str) -> str:
    """Return the PTI target hash for a URL after canonical normalization."""

    return hash_text(normalize_target_url(target_url))


def validate_target_hash(target_hash: str) -> str:
    """Normalize and validate a SHA-256 target hash."""

    normalized = target_hash.strip().lower()
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError("target_hash must be a 64-character lowercase SHA-256 hex digest")
    return normalized


def _normalize_hostname(hostname: str) -> str:
    host = hostname.strip().rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host
