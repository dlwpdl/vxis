"""
Unit tests for TokenBucketRateLimiter and GlobalRateLimiter.
"""

import asyncio
import time

import pytest

from vxis.core.rate_limiter import GlobalRateLimiter, TokenBucketRateLimiter


class TestTokenBucketRateLimiter:
    """Tests for the TokenBucketRateLimiter class."""

    async def test_allows_requests_within_rate(self) -> None:
        """
        High rate (100 t/s) should process 5 requests in well under 1 second.

        With 100 tokens/second and capacity=100 (default), the bucket starts
        full, so 5 requests should be served without any meaningful delay.
        """
        limiter = TokenBucketRateLimiter(rate=100)

        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"Expected < 1s for 5 requests at rate=100, got {elapsed:.3f}s"

    async def test_throttles_over_rate(self) -> None:
        """
        Low rate (10 t/s) with capacity=1 should throttle 3 requests.

        Capacity=1 means no burst. The first token is consumed immediately,
        then each subsequent token requires ~0.1s to accumulate.
        3 requests should require at least 0.15s total.
        """
        limiter = TokenBucketRateLimiter(rate=10, capacity=1)

        start = time.monotonic()
        for _ in range(3):
            await limiter.acquire()
        elapsed = time.monotonic() - start

        assert elapsed >= 0.15, (
            f"Expected >= 0.15s throttle for 3 requests at rate=10, capacity=1, "
            f"got {elapsed:.3f}s"
        )

    async def test_zero_rate_never_blocks(self) -> None:
        """
        rate=0 disables limiting; all acquires return immediately.

        Even requesting many tokens should complete near-instantly.
        """
        limiter = TokenBucketRateLimiter(rate=0)

        start = time.monotonic()
        for _ in range(100):
            await limiter.acquire()
        elapsed = time.monotonic() - start

        assert elapsed < 0.1, (
            f"Expected < 0.1s for rate=0 (no limiting), got {elapsed:.3f}s"
        )

    async def test_negative_rate_never_blocks(self) -> None:
        """
        Negative rate is also treated as 'no limiting' (rate <= 0 check).
        """
        limiter = TokenBucketRateLimiter(rate=-5)

        start = time.monotonic()
        for _ in range(50):
            await limiter.acquire()
        elapsed = time.monotonic() - start

        assert elapsed < 0.1, (
            f"Expected < 0.1s for rate=-5 (no limiting), got {elapsed:.3f}s"
        )


class TestGlobalRateLimiter:
    """Tests for the GlobalRateLimiter class."""

    def test_per_target_isolation_different_targets(self) -> None:
        """
        Different targets must return distinct limiter instances.
        """
        glr = GlobalRateLimiter(default_rate=50)

        limiter_a = glr.get_limiter("192.168.1.1")
        limiter_b = glr.get_limiter("10.0.0.1")

        assert limiter_a is not limiter_b, (
            "Different targets must have separate limiter instances"
        )

    def test_per_target_same_instance_for_same_target(self) -> None:
        """
        Calling get_limiter() twice with the same target must return
        the exact same instance (identity check, not just equality).
        """
        glr = GlobalRateLimiter(default_rate=50)

        limiter_first = glr.get_limiter("example.com")
        limiter_second = glr.get_limiter("example.com")

        assert limiter_first is limiter_second, (
            "Same target must always return the same limiter instance"
        )

    def test_set_rate_updates_existing_limiter(self) -> None:
        """
        set_rate() on an existing target updates the rate on the same instance.
        """
        glr = GlobalRateLimiter(default_rate=50)
        limiter = glr.get_limiter("target.internal")

        glr.set_rate("target.internal", 10)

        assert glr.get_limiter("target.internal") is limiter
        assert limiter.rate == 10

    def test_set_rate_creates_new_limiter_if_missing(self) -> None:
        """
        set_rate() for an unknown target creates a new limiter with that rate.
        """
        glr = GlobalRateLimiter(default_rate=50)
        glr.set_rate("new.target", 5)

        limiter = glr.get_limiter("new.target")
        assert limiter.rate == 5

    def test_default_rate_applied_on_creation(self) -> None:
        """
        New limiters inherit the GlobalRateLimiter's default_rate.
        """
        glr = GlobalRateLimiter(default_rate=25)
        limiter = glr.get_limiter("host.example")

        assert limiter.rate == 25
