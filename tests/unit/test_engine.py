"""Unit tests for the DAG executor engine."""

from __future__ import annotations

import asyncio
import time

import pytest

from vxis.core.context import PluginOutput
from vxis.core.engine import DAGExecutor, TaskNode, TaskState, validate_dag


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_node(
    name: str,
    depends_on: list[str] | None = None,
    optional_depends: list[str] | None = None,
    timeout_seconds: int = 600,
) -> TaskNode:
    return TaskNode(
        plugin_name=name,
        depends_on=depends_on or [],
        optional_depends=optional_depends or [],
        timeout_seconds=timeout_seconds,
    )


def make_output(name: str) -> PluginOutput:
    return PluginOutput(plugin_name=name, raw_output=f"{name} output")


async def _success_runner(name: str) -> PluginOutput:
    """Always succeeds immediately."""
    return make_output(name)


async def _failing_runner(name: str) -> PluginOutput:
    """Always raises an exception."""
    raise RuntimeError(f"Plugin '{name}' intentionally failed.")


def _selective_runner(*failing_names: str):
    """Returns a run_func that fails for specified plugin names."""

    async def _run(name: str) -> PluginOutput:
        if name in failing_names:
            raise RuntimeError(f"Plugin '{name}' intentionally failed.")
        return make_output(name)

    return _run


# ---------------------------------------------------------------------------
# Test: DAG respects dependency ordering (subfinder → httpx → nuclei)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dag_respects_dependency_ordering() -> None:
    """Nodes complete in topological order; downstream nodes see upstream results."""
    execution_order: list[str] = []

    async def ordered_runner(name: str) -> PluginOutput:
        # Tiny sleep so ordering differences become visible.
        await asyncio.sleep(0.01)
        execution_order.append(name)
        return make_output(name)

    nodes = {
        "subfinder": make_node("subfinder"),
        "httpx": make_node("httpx", depends_on=["subfinder"]),
        "nuclei": make_node("nuclei", depends_on=["httpx"]),
    }

    executor = DAGExecutor(nodes, max_concurrency=8)
    result = await executor.execute(ordered_runner)

    assert result["subfinder"].state == TaskState.COMPLETED
    assert result["httpx"].state == TaskState.COMPLETED
    assert result["nuclei"].state == TaskState.COMPLETED

    # Verify ordering invariant: subfinder < httpx < nuclei
    assert execution_order.index("subfinder") < execution_order.index("httpx")
    assert execution_order.index("httpx") < execution_order.index("nuclei")


# ---------------------------------------------------------------------------
# Test: DAG skips node when required dependency FAILED
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dag_skips_on_required_dependency_failure() -> None:
    """A node whose required dependency failed must be SKIPPED, not run."""
    nodes = {
        "subfinder": make_node("subfinder"),
        "httpx": make_node("httpx", depends_on=["subfinder"]),
        "nuclei": make_node("nuclei", depends_on=["httpx"]),
    }

    executor = DAGExecutor(nodes, max_concurrency=8)
    result = await executor.execute(_selective_runner("subfinder"))

    assert result["subfinder"].state == TaskState.FAILED
    assert result["httpx"].state == TaskState.SKIPPED
    assert result["nuclei"].state == TaskState.SKIPPED

    # Error message must mention the blocking dependency.
    assert "subfinder" in (result["httpx"].error or "")
    assert "httpx" in (result["nuclei"].error or "")


# ---------------------------------------------------------------------------
# Test: DAG continues on optional dependency failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dag_continues_on_optional_dependency_failure() -> None:
    """A node with only *optional* deps that failed must still execute."""
    nodes = {
        "whois": make_node("whois"),
        "httpx": make_node("httpx", optional_depends=["whois"]),
    }

    executor = DAGExecutor(nodes, max_concurrency=8)
    result = await executor.execute(_selective_runner("whois"))

    assert result["whois"].state == TaskState.FAILED
    # httpx must NOT be skipped; optional failure is tolerated.
    assert result["httpx"].state == TaskState.COMPLETED


# ---------------------------------------------------------------------------
# Test: Cycle detection raises ValueError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cycle_detection_raises_value_error() -> None:
    """A cyclic DAG must raise ValueError before any execution starts."""
    nodes = {
        "a": make_node("a", depends_on=["c"]),
        "b": make_node("b", depends_on=["a"]),
        "c": make_node("c", depends_on=["b"]),
    }

    executor = DAGExecutor(nodes, max_concurrency=8)

    with pytest.raises(ValueError, match="Cycle detected"):
        await executor.execute(_success_runner)


# ---------------------------------------------------------------------------
# Test: Independent nodes still complete even if one sibling fails
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_independent_nodes_complete_even_if_sibling_fails() -> None:
    """Failure of one node must not propagate to unrelated sibling nodes."""
    nodes = {
        "tool_a": make_node("tool_a"),
        "tool_b": make_node("tool_b"),  # independent of tool_a
        "tool_c": make_node("tool_c"),  # independent of tool_a
    }

    executor = DAGExecutor(nodes, max_concurrency=8)
    result = await executor.execute(_selective_runner("tool_a"))

    assert result["tool_a"].state == TaskState.FAILED
    assert result["tool_b"].state == TaskState.COMPLETED
    assert result["tool_c"].state == TaskState.COMPLETED


# ---------------------------------------------------------------------------
# Test: validate_dag catches missing dependency
# ---------------------------------------------------------------------------


def test_validate_dag_catches_missing_dependency() -> None:
    """validate_dag must report an error when a dep name is not in the dict."""
    nodes = {
        "httpx": make_node("httpx", depends_on=["subfinder"]),
        # 'subfinder' is intentionally absent
    }

    errors = validate_dag(nodes)

    assert len(errors) > 0
    assert any("subfinder" in e for e in errors)


def test_validate_dag_catches_missing_optional_dependency() -> None:
    """validate_dag also reports missing optional dependencies."""
    nodes = {
        "nuclei": make_node("nuclei", optional_depends=["nonexistent"]),
    }

    errors = validate_dag(nodes)

    assert any("nonexistent" in e for e in errors)


def test_validate_dag_reports_cycle() -> None:
    """validate_dag must include a cycle error in its results."""
    nodes = {
        "x": make_node("x", depends_on=["y"]),
        "y": make_node("y", depends_on=["x"]),
    }

    errors = validate_dag(nodes)

    assert any("Cycle" in e for e in errors)


def test_validate_dag_returns_empty_for_valid_dag() -> None:
    """A well-formed DAG produces zero errors."""
    nodes = {
        "subfinder": make_node("subfinder"),
        "httpx": make_node("httpx", depends_on=["subfinder"]),
        "nuclei": make_node("nuclei", depends_on=["httpx"]),
    }

    errors = validate_dag(nodes)

    assert errors == []


# ---------------------------------------------------------------------------
# Test: Concurrent execution — independent nodes run in parallel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_execution_for_independent_nodes() -> None:
    """Two independent nodes must complete in roughly parallel wall time."""
    DELAY = 0.1

    async def slow_runner(name: str) -> PluginOutput:
        await asyncio.sleep(DELAY)
        return make_output(name)

    nodes = {
        "tool_a": make_node("tool_a"),
        "tool_b": make_node("tool_b"),
    }

    start = time.monotonic()
    executor = DAGExecutor(nodes, max_concurrency=2)
    result = await executor.execute(slow_runner)
    elapsed = time.monotonic() - start

    assert result["tool_a"].state == TaskState.COMPLETED
    assert result["tool_b"].state == TaskState.COMPLETED

    # If they ran sequentially this would be >= 2 * DELAY; parallel should be
    # close to 1 * DELAY.  Use 1.8 * DELAY as a generous upper bound.
    assert elapsed < DELAY * 1.8, f"Nodes appear to have run sequentially: elapsed={elapsed:.3f}s"


# ---------------------------------------------------------------------------
# Test: started_at / finished_at are recorded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_node_timestamps_are_recorded() -> None:
    """Every completed node must have non-None started_at and finished_at."""
    nodes = {"only_node": make_node("only_node")}

    executor = DAGExecutor(nodes, max_concurrency=1)
    result = await executor.execute(_success_runner)

    node = result["only_node"]
    assert node.started_at is not None
    assert node.finished_at is not None
    assert node.finished_at >= node.started_at


# ---------------------------------------------------------------------------
# Test: TIMED_OUT state on exceeding timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timed_out_state_on_timeout() -> None:
    """A node that exceeds its timeout must transition to TIMED_OUT."""

    async def slow_runner(name: str) -> PluginOutput:
        await asyncio.sleep(10)  # much longer than the node's timeout
        return make_output(name)

    nodes = {
        "slow_tool": make_node("slow_tool", timeout_seconds=1),
    }

    executor = DAGExecutor(nodes, max_concurrency=1)
    result = await executor.execute(slow_runner)

    assert result["slow_tool"].state == TaskState.TIMED_OUT
    assert result["slow_tool"].error is not None


# ---------------------------------------------------------------------------
# Test: TIMED_OUT required dep also causes skip in dependents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_timed_out_dep_causes_skip() -> None:
    """A node with a TIMED_OUT required dep must be SKIPPED."""

    async def slow_runner(name: str) -> PluginOutput:
        if name == "slow_tool":
            await asyncio.sleep(10)
        return make_output(name)

    nodes = {
        "slow_tool": make_node("slow_tool", timeout_seconds=1),
        "dependent": make_node("dependent", depends_on=["slow_tool"]),
    }

    executor = DAGExecutor(nodes, max_concurrency=2)
    result = await executor.execute(slow_runner)

    assert result["slow_tool"].state == TaskState.TIMED_OUT
    assert result["dependent"].state == TaskState.SKIPPED
