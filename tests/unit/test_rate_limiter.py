"""
Unit tests for TokenBucketRateLimiter and GlobalRateLimiter.
"""

import asyncio
import time


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
            f"Expected >= 0.15s throttle for 3 requests at rate=10, capacity=1, got {elapsed:.3f}s"
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

        assert elapsed < 0.1, f"Expected < 0.1s for rate=0 (no limiting), got {elapsed:.3f}s"

    async def test_negative_rate_never_blocks(self) -> None:
        """
        Negative rate is also treated as 'no limiting' (rate <= 0 check).
        """
        limiter = TokenBucketRateLimiter(rate=-5)

        start = time.monotonic()
        for _ in range(50):
            await limiter.acquire()
        elapsed = time.monotonic() - start

        assert elapsed < 0.1, f"Expected < 0.1s for rate=-5 (no limiting), got {elapsed:.3f}s"

    async def test_burst_capacity_allows_initial_burst(self) -> None:
        """
        With rate=5 and capacity=10, the bucket starts with 10 tokens,
        allowing an immediate burst of 10 requests before throttling kicks in.
        """
        limiter = TokenBucketRateLimiter(rate=5, capacity=10)

        start = time.monotonic()
        for _ in range(10):
            await limiter.acquire()
        burst_elapsed = time.monotonic() - start

        # The initial 10 should be near-instant (bucket starts full at capacity=10)
        assert burst_elapsed < 0.1, (
            f"Expected burst of 10 to complete in < 0.1s, got {burst_elapsed:.3f}s"
        )

        # The 11th request should require waiting for token refill (~0.2s at rate=5)
        start = time.monotonic()
        await limiter.acquire()
        wait_elapsed = time.monotonic() - start

        assert wait_elapsed >= 0.15, (
            f"Expected >= 0.15s wait after burst exhaustion, got {wait_elapsed:.3f}s"
        )

    async def test_concurrent_access_does_not_exceed_rate(self) -> None:
        """
        Multiple coroutines acquiring from the same limiter concurrently
        must not produce more tokens than the rate allows.

        With rate=10, capacity=2, firing 6 coroutines simultaneously:
        - 2 return immediately (from initial capacity)
        - remaining 4 must wait, taking at least 0.3s total
        """
        limiter = TokenBucketRateLimiter(rate=10, capacity=2)

        async def _acquire() -> float:
            t = time.monotonic()
            await limiter.acquire()
            return time.monotonic() - t

        start = time.monotonic()
        await asyncio.gather(*[_acquire() for _ in range(6)])
        total_elapsed = time.monotonic() - start

        # 2 immediate + 4 waiting: at rate=10, 4 tokens take 0.4s to refill.
        # Allow some margin; total should be at least 0.3s.
        assert total_elapsed >= 0.3, (
            f"Expected >= 0.3s for 6 concurrent acquires at rate=10, capacity=2, "
            f"got {total_elapsed:.3f}s"
        )

    async def test_concurrent_access_tokens_never_go_negative(self) -> None:
        """
        After concurrent access, internal token count must never be negative.

        This validates the fix where the old implementation could leave
        _tokens < 0 when multiple coroutines raced after sleeping.
        """
        limiter = TokenBucketRateLimiter(rate=100, capacity=5)

        await asyncio.gather(*[limiter.acquire() for _ in range(10)])

        # After all acquires complete, refill and check tokens are non-negative
        async with limiter._lock:
            limiter._refill()
            assert limiter._tokens >= 0, f"Tokens went negative: {limiter._tokens}"

    async def test_acquire_multiple_tokens_at_once(self) -> None:
        """
        Requesting more than 1 token per acquire() should work correctly.
        """
        limiter = TokenBucketRateLimiter(rate=10, capacity=5)

        # First acquire of 5 tokens should succeed immediately (bucket starts full)
        start = time.monotonic()
        await limiter.acquire(tokens=5)
        elapsed = time.monotonic() - start
        assert elapsed < 0.05

        # Next acquire of 3 tokens should wait ~0.3s (3 tokens / 10 rate)
        start = time.monotonic()
        await limiter.acquire(tokens=3)
        elapsed = time.monotonic() - start
        assert elapsed >= 0.25, f"Expected >= 0.25s for 3 tokens at rate=10, got {elapsed:.3f}s"

    async def test_refill_caps_at_capacity(self) -> None:
        """
        Tokens should never exceed capacity, even after a long idle period.
        """
        limiter = TokenBucketRateLimiter(rate=100, capacity=5)

        # Consume all tokens
        for _ in range(5):
            await limiter.acquire()

        # Wait enough for many tokens to accumulate
        await asyncio.sleep(0.2)

        # Refill should cap at capacity=5
        async with limiter._lock:
            limiter._refill()
            assert limiter._tokens <= limiter.capacity, (
                f"Tokens {limiter._tokens} exceeded capacity {limiter.capacity}"
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

        assert limiter_a is not limiter_b, "Different targets must have separate limiter instances"

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

    def test_set_rate_resets_token_bucket(self) -> None:
        """
        set_rate() should reset the token bucket to the new capacity,
        ensuring the limiter immediately reflects the updated rate.
        """
        glr = GlobalRateLimiter(default_rate=50)
        limiter = glr.get_limiter("target.internal")

        # Drain some tokens
        # (synchronous check of internal state, not via acquire)
        limiter._tokens = 0

        glr.set_rate("target.internal", 20)

        assert limiter.rate == 20
        assert limiter.capacity == 20
        assert limiter._tokens == 20  # Reset to full capacity

    async def test_per_target_rate_limiting_independent(self) -> None:
        """
        Two targets with different rates should be throttled independently.

        Target A at rate=10/capacity=1 should throttle, while target B
        at rate=0 (unlimited) should complete instantly.
        """
        glr = GlobalRateLimiter(default_rate=10)

        # Target A: slow, capacity=1 to force throttling
        glr.set_rate("target_a", 10)
        limiter_a = glr.get_limiter("target_a")
        limiter_a.capacity = 1
        limiter_a._tokens = 1

        # Target B: unlimited
        glr.set_rate("target_b", 0)
        limiter_b = glr.get_limiter("target_b")

        # Target B should be instant even while A is slow
        start = time.monotonic()
        for _ in range(100):
            await limiter_b.acquire()
        elapsed_b = time.monotonic() - start

        assert elapsed_b < 0.05, f"Unlimited target took {elapsed_b:.3f}s, expected < 0.05s"

        # Target A with capacity=1 should throttle
        start = time.monotonic()
        for _ in range(3):
            await limiter_a.acquire()
        elapsed_a = time.monotonic() - start

        assert elapsed_a >= 0.15, f"Rate-limited target took {elapsed_a:.3f}s, expected >= 0.15s"
