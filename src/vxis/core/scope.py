"""Scope validation for VXIS security automation platform.

Ensures all scan targets are within the authorized scope and that
excluded targets or ports are rejected before any tool execution.
"""

from __future__ import annotations

import ipaddress
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network


class ScopeViolationError(Exception):
    """Raised when a target is outside the authorized scan scope.

    Attributes:
        target: The target that violated the scope.
        scope_targets: The list of in-scope targets that were defined.
    """

    def __init__(self, target: str, scope_targets: list[str]) -> None:
        self.target = target
        self.scope_targets = scope_targets
        formatted = ", ".join(scope_targets) if scope_targets else "(none)"
        super().__init__(
            f"Target '{target}' is outside the authorized scope. "
            f"Authorized targets: [{formatted}]"
        )


def _parse_target(raw: str) -> IPv4Network | IPv6Network | str:
    """Parse a raw target string into an IP network or a normalized domain.

    IP networks are parsed with strict=False so that host bits are silently
    masked (e.g. '10.0.0.1/24' -> '10.0.0.0/24').  Domain strings have any
    leading '*.' wildcard prefix stripped so that '*.example.com' becomes
    'example.com' for matching purposes.

    Args:
        raw: Raw target string such as '192.168.1.0/24', '10.0.0.5',
             'example.com', or '*.example.com'.

    Returns:
        An IPv4Network / IPv6Network instance for IP-based targets, or a
        lower-cased domain string for domain-based targets.
    """
    stripped = raw.strip()
    try:
        return ipaddress.ip_network(stripped, strict=False)
    except ValueError:
        # Treat as domain; strip wildcard prefix
        domain = stripped.lstrip("*").lstrip(".")
        return domain.lower()


class ScopeValidator:
    """Validates whether targets and ports are within the authorized scope.

    Targets are parsed into either IP networks (for CIDR ranges / single IPs)
    or domain strings.  Exclusions take priority over inclusions: a target
    that matches an exclusion is always out of scope regardless of whether it
    also matches an in-scope entry.

    Args:
        targets: Authorized scan targets (CIDR ranges, IPs, or hostnames).
        exclude_targets: Targets explicitly excluded from scope.
        exclude_ports: Port numbers that must not be scanned.
    """

    def __init__(
        self,
        targets: list[str],
        exclude_targets: list[str],
        exclude_ports: list[int] | None = None,
    ) -> None:
        self._raw_targets = list(targets)
        self._parsed_targets: list[IPv4Network | IPv6Network | str] = [
            _parse_target(t) for t in targets
        ]
        self._parsed_exclusions: list[IPv4Network | IPv6Network | str] = [
            _parse_target(t) for t in exclude_targets
        ]
        self._exclude_ports: set[int] = set(exclude_ports) if exclude_ports else set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _matches_any(
        self,
        target: str,
        parsed_list: list[IPv4Network | IPv6Network | str],
    ) -> bool:
        """Return True if *target* matches any entry in *parsed_list*."""
        # Try to resolve target as an IP address first
        target_ip: IPv4Address | IPv6Address | None = None
        try:
            target_ip = ipaddress.ip_address(target.strip())
        except ValueError:
            pass

        target_domain = target.strip().lower()

        for entry in parsed_list:
            if isinstance(entry, (IPv4Network, IPv6Network)):
                if target_ip is not None and target_ip in entry:
                    return True
            else:
                # Domain matching: exact or subdomain
                # 'example.com'  matches 'example.com'
                # 'sub.example.com' matches 'example.com' (suffix '.example.com')
                if target_domain == entry or target_domain.endswith("." + entry):
                    return True

        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_in_scope(self, target: str) -> bool:
        """Return True if *target* is within the authorized scope.

        Exclusions are evaluated before inclusions.  A target that matches
        an exclusion entry is always considered out of scope.

        Args:
            target: IP address, hostname, or domain to check.

        Returns:
            True when in scope, False otherwise.
        """
        # Exclusions take absolute priority
        if self._matches_any(target, self._parsed_exclusions):
            return False

        return self._matches_any(target, self._parsed_targets)

    def validate(self, target: str) -> None:
        """Assert that *target* is within the authorized scope.

        Args:
            target: IP address, hostname, or domain to validate.

        Raises:
            ScopeViolationError: When the target is outside the scope.
        """
        if not self.is_in_scope(target):
            raise ScopeViolationError(target, self._raw_targets)

    def is_port_allowed(self, port: int) -> bool:
        """Return True when *port* is not in the exclusion list.

        Args:
            port: TCP/UDP port number to check.

        Returns:
            True when the port may be scanned, False when excluded.
        """
        return port not in self._exclude_ports
