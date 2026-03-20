"""
Token Bucket Rate Limiter for VXIS security automation platform.

Provides per-target rate limiting using the token bucket algorithm.
Tokens are refilled at a constant rate up to a maximum capacity.
"""

import asyncio
import time


class TokenBucketRateLimiter:
    """
    Asynchronous token bucket rate limiter.

    Tokens are added at `rate` tokens/second up to `capacity`.
    When tokens run out, acquire() sleeps until enough tokens are available.
    If rate <= 0, no limiting is applied and acquire() returns immediately.
    """

    def __init__(self, rate: float, capacity: float | None = None) -> None:
        """
        Initialize the rate limiter.

        Args:
            rate: Tokens added per second. If <= 0, no rate limiting is applied.
            capacity: Maximum token capacity. Defaults to `rate` (1 second burst).
        """
        self.rate = rate
        self.capacity = capacity if capacity is not None else rate
        self._tokens = self.capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        """
        Add tokens based on elapsed time since last refill.
        Caps tokens at capacity.
        """
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._last_refill = now

        if self.rate > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

    async def acquire(self, tokens: float = 1.0) -> None:
        """
        Wait until the requested number of tokens are available, then consume them.

        If rate <= 0, returns immediately without blocking.

        Args:
            tokens: Number of tokens to consume. Defaults to 1.0.
        """
        if self.rate <= 0:
            return

        async with self._lock:
            self._refill()

            if self._tokens >= tokens:
                self._tokens -= tokens
                return

            # Calculate wait time needed for enough tokens to accumulate
            deficit = tokens - self._tokens
            wait_time = deficit / self.rate

        # Sleep outside the lock to allow other coroutines to proceed
        await asyncio.sleep(wait_time)

        async with self._lock:
            self._refill()
            self._tokens -= tokens


class GlobalRateLimiter:
    """
    Global registry of per-target TokenBucketRateLimiters.

    Maintains one limiter per target string. The same target always
    returns the same limiter instance, enabling consistent rate enforcement
    across different call sites.
    """

    def __init__(self, default_rate: float = 50) -> None:
        """
        Initialize the global rate limiter.

        Args:
            default_rate: Default tokens/second for new target limiters.
        """
        self.default_rate = default_rate
        self._limiters: dict[str, TokenBucketRateLimiter] = {}

    def get_limiter(self, target: str) -> TokenBucketRateLimiter:
        """
        Return the TokenBucketRateLimiter for the given target.

        Creates a new limiter with the default rate if none exists yet.

        Args:
            target: Identifier for the target (e.g., hostname, IP address).

        Returns:
            The TokenBucketRateLimiter associated with this target.
        """
        if target not in self._limiters:
            self._limiters[target] = TokenBucketRateLimiter(rate=self.default_rate)
        return self._limiters[target]

    def set_rate(self, target: str, rate: float) -> None:
        """
        Update the rate for an existing or new target limiter.

        If the target already has a limiter, its rate and capacity are updated
        and the token bucket is reset to the new capacity.

        Args:
            target: Identifier for the target.
            rate: New tokens/second rate.
        """
        if target in self._limiters:
            limiter = self._limiters[target]
            limiter.rate = rate
            limiter.capacity = rate
            limiter._tokens = rate
        else:
            self._limiters[target] = TokenBucketRateLimiter(rate=rate)
