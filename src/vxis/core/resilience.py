"""Resilience primitives: result classification, retry logic, and custom errors."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Result level
# ---------------------------------------------------------------------------


class ToolResultLevel(Enum):
    """Severity classification of a tool's execution result."""

    SUCCESS = "success"
    PARTIAL = "partial"
    DEGRADED = "degraded"
    FAILED = "failed"

    @property
    def should_continue(self) -> bool:
        """Return True when the pipeline should continue after this result."""
        return self in (
            ToolResultLevel.SUCCESS,
            ToolResultLevel.PARTIAL,
            ToolResultLevel.DEGRADED,
        )


# ---------------------------------------------------------------------------
# Retry configuration
# ---------------------------------------------------------------------------


@dataclass
class RetryConfig:
    """Configuration that governs retry behaviour for tool executions."""

    max_retries: int = 2
    backoff_base: float = 5.0
    backoff_multiplier: float = 2.0
    retryable_exit_codes: tuple[int, ...] = field(default_factory=lambda: (137, 143))

    def is_retryable(self, exit_code: int) -> bool:
        """Return True if *exit_code* warrants a retry attempt."""
        return exit_code in self.retryable_exit_codes


# ---------------------------------------------------------------------------
# Result classification
# ---------------------------------------------------------------------------


def classify_result(return_code: int, stdout: str) -> ToolResultLevel:
    """Map a tool's exit code and stdout to a ToolResultLevel.

    Rules:
    - exit 0                        → SUCCESS
    - exit != 0 with stdout content → PARTIAL
    - exit != 0 without stdout      → FAILED
    """
    if return_code == 0:
        return ToolResultLevel.SUCCESS
    if stdout.strip():
        return ToolResultLevel.PARTIAL
    return ToolResultLevel.FAILED


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class ToolExecutionError(Exception):
    """Raised when a tool exits with a non-zero code after all retries."""

    def __init__(self, message: str, exit_code: int, stderr: str) -> None:
        super().__init__(message)
        self.exit_code = exit_code
        self.stderr = stderr


class ToolTimeoutError(Exception):
    """Raised when a tool exceeds its allotted execution time."""

    def __init__(self, tool_name: str, timeout: float) -> None:
        super().__init__(f"Tool '{tool_name}' timed out after {timeout} second(s).")
        self.tool_name = tool_name
        self.timeout = timeout


# ---------------------------------------------------------------------------
# Resilient runner
# ---------------------------------------------------------------------------


class ResilientRunner:
    """Executes an async callable with configurable retry and back-off logic."""

    def __init__(self, config: RetryConfig | None = None) -> None:
        self._config = config or RetryConfig()

    async def run_with_retry(
        self,
        func: Callable[[], Awaitable[T]],
        max_retries: int | None = None,
    ) -> T:
        """Call *func* and retry on failure up to *max_retries* times.

        Args:
            func: Zero-argument async callable to execute.
            max_retries: Override for ``RetryConfig.max_retries``.

        Returns:
            The return value of *func* on success.

        Raises:
            ToolExecutionError: After all retry attempts are exhausted.
            Any other exception raised by *func* is propagated immediately.
        """
        attempts = (max_retries if max_retries is not None else self._config.max_retries) + 1
        last_error: Exception | None = None

        for attempt in range(attempts):
            try:
                return await func()
            except ToolExecutionError as exc:
                last_error = exc
                remaining = attempts - attempt - 1
                if remaining == 0:
                    break
                delay = self._config.backoff_base * (
                    self._config.backoff_multiplier ** attempt
                )
                logger.warning(
                    "Attempt %d/%d failed (exit_code=%d). Retrying in %.1f s…",
                    attempt + 1,
                    attempts,
                    exc.exit_code,
                    delay,
                )
                await asyncio.sleep(delay)

        assert last_error is not None  # mypy / type narrowing
        raise last_error
