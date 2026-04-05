"""Unit tests for vxis.core.resilience."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from vxis.core.resilience import (
    RetryConfig,
    ResilientRunner,
    ToolExecutionError,
    ToolResultLevel,
    ToolTimeoutError,
    classify_result,
)


# ---------------------------------------------------------------------------
# ToolResultLevel
# ---------------------------------------------------------------------------


class TestToolResultLevel:
    def test_success_should_continue(self) -> None:
        assert ToolResultLevel.SUCCESS.should_continue is True

    def test_partial_should_continue(self) -> None:
        assert ToolResultLevel.PARTIAL.should_continue is True

    def test_degraded_should_continue(self) -> None:
        assert ToolResultLevel.DEGRADED.should_continue is True

    def test_failed_should_not_continue(self) -> None:
        assert ToolResultLevel.FAILED.should_continue is False


# ---------------------------------------------------------------------------
# RetryConfig
# ---------------------------------------------------------------------------


class TestRetryConfig:
    def test_default_values(self) -> None:
        config = RetryConfig()

        assert config.max_retries == 2
        assert config.backoff_base == 5.0
        assert config.backoff_multiplier == 2.0
        assert 137 in config.retryable_exit_codes
        assert 143 in config.retryable_exit_codes

    def test_is_retryable_returns_true_for_137(self) -> None:
        config = RetryConfig()
        assert config.is_retryable(137) is True

    def test_is_retryable_returns_false_for_zero(self) -> None:
        config = RetryConfig()
        assert config.is_retryable(0) is False

    def test_is_retryable_returns_false_for_unknown_code(self) -> None:
        config = RetryConfig()
        assert config.is_retryable(42) is False


# ---------------------------------------------------------------------------
# classify_result
# ---------------------------------------------------------------------------


class TestClassifyResult:
    def test_exit_0_is_success(self) -> None:
        assert classify_result(0, "") == ToolResultLevel.SUCCESS

    def test_exit_0_with_stdout_is_still_success(self) -> None:
        assert classify_result(0, "some output") == ToolResultLevel.SUCCESS

    def test_nonzero_with_stdout_is_partial(self) -> None:
        assert classify_result(1, "partial output") == ToolResultLevel.PARTIAL

    def test_nonzero_without_stdout_is_failed(self) -> None:
        assert classify_result(1, "") == ToolResultLevel.FAILED

    def test_nonzero_whitespace_only_stdout_is_failed(self) -> None:
        # Whitespace-only output should be treated as "no output".
        assert classify_result(2, "   \n  ") == ToolResultLevel.FAILED


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class TestToolExecutionError:
    def test_attributes(self) -> None:
        err = ToolExecutionError("tool crashed", exit_code=1, stderr="oops")

        assert err.exit_code == 1
        assert err.stderr == "oops"
        assert "tool crashed" in str(err)


class TestToolTimeoutError:
    def test_attributes(self) -> None:
        err = ToolTimeoutError(tool_name="nmap", timeout=30.0)

        assert err.tool_name == "nmap"
        assert err.timeout == 30.0
        assert "nmap" in str(err)


# ---------------------------------------------------------------------------
# ResilientRunner
# ---------------------------------------------------------------------------


class TestResilientRunner:
    async def test_success_on_first_try(self) -> None:
        """When func succeeds immediately, result is returned without retries."""
        func = AsyncMock(return_value="ok")
        runner = ResilientRunner(RetryConfig(max_retries=2))

        result = await runner.run_with_retry(func)

        assert result == "ok"
        func.assert_awaited_once()

    async def test_retries_on_failure_then_succeeds(self) -> None:
        """Runner should retry after a ToolExecutionError and return on success."""
        error = ToolExecutionError("fail", exit_code=1, stderr="")
        func = AsyncMock(side_effect=[error, "recovered"])

        # Patch asyncio.sleep to avoid real delays during tests.
        runner = ResilientRunner(RetryConfig(max_retries=2, backoff_base=0.0))

        result = await runner.run_with_retry(func)

        assert result == "recovered"
        assert func.await_count == 2

    async def test_raises_after_max_retries(self) -> None:
        """After exhausting all retries, ToolExecutionError must propagate."""
        error = ToolExecutionError("persistent failure", exit_code=1, stderr="err")
        func = AsyncMock(side_effect=error)

        runner = ResilientRunner(RetryConfig(max_retries=2, backoff_base=0.0))

        with pytest.raises(ToolExecutionError) as exc_info:
            await runner.run_with_retry(func)

        assert exc_info.value.exit_code == 1
        # Called once + 2 retries = 3 total
        assert func.await_count == 3

    async def test_max_retries_override(self) -> None:
        """run_with_retry should respect the per-call max_retries override."""
        error = ToolExecutionError("fail", exit_code=1, stderr="")
        func = AsyncMock(side_effect=error)

        # Config says 2 retries, but we override with 1.
        runner = ResilientRunner(RetryConfig(max_retries=2, backoff_base=0.0))

        with pytest.raises(ToolExecutionError):
            await runner.run_with_retry(func, max_retries=1)

        # Called once + 1 retry = 2 total
        assert func.await_count == 2

    async def test_non_execution_error_propagates_immediately(self) -> None:
        """Errors that are not ToolExecutionError must not be swallowed."""
        func = AsyncMock(side_effect=ValueError("unexpected"))
        runner = ResilientRunner(RetryConfig(max_retries=2, backoff_base=0.0))

        with pytest.raises(ValueError, match="unexpected"):
            await runner.run_with_retry(func)

        # Should not retry on unknown exceptions.
        func.assert_awaited_once()
