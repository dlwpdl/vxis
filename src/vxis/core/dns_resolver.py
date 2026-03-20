"""
DNS Pinning Resolver for VXIS security automation platform.

Resolves hostnames to IP addresses and caches ("pins") results to ensure
consistent targeting throughout a scan session. Supports custom nameservers.
"""

import ipaddress

import dns.resolver


class DNSPinningResolver:
    """
    Resolves and caches DNS A records for consistent IP targeting.

    Once a hostname is resolved, subsequent lookups return the cached
    result ("pinned" IPs). This prevents DNS rebinding attacks and
    ensures scan targets remain stable across a session.
    """

    def __init__(self, nameservers: list[str] | None = None) -> None:
        """
        Initialize the resolver.

        Args:
            nameservers: Optional list of custom nameserver IP addresses.
                         If None, the system default nameservers are used.
        """
        self._cache: dict[str, list[str]] = {}
        self._resolver = dns.resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers

    async def resolve(self, hostname: str) -> list[str]:
        """
        Resolve a hostname to a list of IPv4 addresses, with caching.

        If the hostname is already an IP address, it is returned as-is.
        If the hostname has been resolved before, the cached result is returned.
        On DNS failure (NXDOMAIN, timeout, no answer, etc.), returns an empty list.

        Args:
            hostname: The hostname or IP address to resolve.

        Returns:
            List of resolved IP address strings, or [] on failure.
        """
        if self._is_ip(hostname):
            return [hostname]

        if hostname in self._cache:
            return self._cache[hostname]

        try:
            answer = self._resolver.resolve(hostname, "A")
            ips = [rdata.address for rdata in answer]
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.exception.DNSException,
        ):
            ips = []

        self._cache[hostname] = ips
        return ips

    async def resolve_many(self, hostnames: list[str]) -> dict[str, list[str]]:
        """
        Resolve multiple hostnames concurrently.

        Args:
            hostnames: List of hostnames or IP addresses to resolve.

        Returns:
            Mapping of hostname -> list of resolved IP strings.
        """
        results: dict[str, list[str]] = {}
        for hostname in hostnames:
            results[hostname] = await self.resolve(hostname)
        return results

    def get_canonical_target(self, target: str) -> str:
        """
        Return the first pinned IP for a resolved hostname, or the target itself.

        If the target has been resolved and at least one IP is cached, returns
        the first IP. Otherwise returns the original target string unchanged
        (covers both unresolved hostnames and direct IP inputs).

        Args:
            target: Hostname or IP address.

        Returns:
            First cached IP string, or `target` if not cached / cache is empty.
        """
        ips = self._cache.get(target)
        if ips:
            return ips[0]
        return target

    def get_pinned_results(self) -> dict[str, list[str]]:
        """
        Return the full DNS pin cache.

        Returns:
            A copy of the internal hostname -> IP list mapping.
        """
        return dict(self._cache)

    @staticmethod
    def _is_ip(value: str) -> bool:
        """
        Check whether a string is a valid IPv4 or IPv6 address.

        Args:
            value: String to check.

        Returns:
            True if value is a valid IP address, False otherwise.
        """
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
