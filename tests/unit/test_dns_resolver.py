"""
Unit tests for DNSPinningResolver.

Tests that require actual DNS resolution (google.com) are marked
to be skipped if network access is unavailable.
"""

import pytest

from vxis.core.dns_resolver import DNSPinningResolver


class TestDNSPinningResolver:
    """Tests for DNSPinningResolver."""

    async def test_resolve_returns_ips_for_google(self) -> None:
        """
        Resolving google.com should return at least one valid IPv4 address.
        """
        resolver = DNSPinningResolver()
        ips = await resolver.resolve("google.com")

        assert len(ips) > 0, "Expected at least one IP for google.com"
        # Each result should be a non-empty string
        for ip in ips:
            assert isinstance(ip, str) and len(ip) > 0

    async def test_pinning_returns_same_result_on_second_call(self) -> None:
        """
        A second resolve() for the same hostname must return the cached
        (pinned) result — identical list from the internal cache.
        """
        resolver = DNSPinningResolver()

        first = await resolver.resolve("google.com")
        second = await resolver.resolve("google.com")

        assert first == second, "Cached result must be identical to first resolution"

    async def test_get_canonical_target_for_cached_domain(self) -> None:
        """
        After resolving a domain, get_canonical_target() returns its first IP.
        """
        resolver = DNSPinningResolver()
        ips = await resolver.resolve("google.com")

        canonical = resolver.get_canonical_target("google.com")

        assert canonical == ips[0], (
            f"Expected canonical target to be first IP {ips[0]!r}, got {canonical!r}"
        )

    async def test_get_canonical_target_for_ip_address(self) -> None:
        """
        get_canonical_target() for a raw IP address that was never
        resolved returns the IP itself (no cache entry exists).
        """
        resolver = DNSPinningResolver()
        ip = "93.184.216.34"

        canonical = resolver.get_canonical_target(ip)

        assert canonical == ip, (
            f"Expected canonical target to be the IP itself, got {canonical!r}"
        )

    async def test_resolve_invalid_domain_returns_empty_list(self) -> None:
        """
        Resolving a non-existent domain must return [] without raising.
        """
        resolver = DNSPinningResolver()
        ips = await resolver.resolve("this-domain-does-not-exist.invalid")

        assert ips == [], f"Expected [] for invalid domain, got {ips!r}"

    def test_is_ip_for_ipv4(self) -> None:
        """_is_ip returns True for a valid IPv4 address."""
        assert DNSPinningResolver._is_ip("192.168.1.1") is True

    def test_is_ip_for_domain(self) -> None:
        """_is_ip returns False for a domain name."""
        assert DNSPinningResolver._is_ip("google.com") is False

    def test_is_ip_for_ipv6(self) -> None:
        """_is_ip returns True for a valid IPv6 address."""
        assert DNSPinningResolver._is_ip("2001:db8::1") is True

    def test_is_ip_for_invalid_string(self) -> None:
        """_is_ip returns False for arbitrary non-IP strings."""
        assert DNSPinningResolver._is_ip("not-an-ip") is False

    async def test_resolve_ip_returns_itself(self) -> None:
        """
        Passing a raw IP to resolve() bypasses DNS and returns [ip].
        """
        resolver = DNSPinningResolver()
        ip = "8.8.8.8"

        result = await resolver.resolve(ip)

        assert result == [ip]

    async def test_resolve_many_returns_mapping(self) -> None:
        """
        resolve_many() returns a dict keyed by each hostname.
        """
        resolver = DNSPinningResolver()
        hostnames = ["google.com", "8.8.8.8"]

        results = await resolver.resolve_many(hostnames)

        assert set(results.keys()) == set(hostnames)
        assert results["8.8.8.8"] == ["8.8.8.8"]
        assert len(results["google.com"]) > 0

    async def test_get_pinned_results_returns_cache(self) -> None:
        """
        get_pinned_results() returns a copy of all cached resolutions.
        """
        resolver = DNSPinningResolver()
        await resolver.resolve("google.com")

        pinned = resolver.get_pinned_results()

        assert "google.com" in pinned
        assert isinstance(pinned["google.com"], list)
