from __future__ import annotations

import ipaddress
from enum import Enum
from fnmatch import fnmatch
from urllib.parse import urlparse

from vxis.p1.models import Scope


class ScopeDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    OUT_OF_SCOPE = "out_of_scope"


def normalize_target(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname or parsed.netloc
        return host.lower().strip("[]")
    return raw.lower().strip("[]")


def matches(target: str, patterns: list[str]) -> bool:
    normalized = normalize_target(target)
    if not normalized:
        return False
    return any(_matches_one(normalized, pattern) for pattern in patterns)


def classify(target: str, scope: Scope) -> ScopeDecision:
    if matches(target, scope.deny):
        return ScopeDecision.DENIED
    if matches(target, scope.allow):
        return ScopeDecision.ALLOWED
    return ScopeDecision.OUT_OF_SCOPE


def _matches_one(target: str, pattern: str) -> bool:
    raw_pattern = normalize_target(pattern)
    if not raw_pattern:
        return False
    try:
        network = ipaddress.ip_network(raw_pattern, strict=False)
    except ValueError:
        network = None
    if network is not None:
        try:
            return ipaddress.ip_address(target) in network
        except ValueError:
            return False
    try:
        return ipaddress.ip_address(target) == ipaddress.ip_address(raw_pattern)
    except ValueError:
        pass
    return fnmatch(target, raw_pattern)
