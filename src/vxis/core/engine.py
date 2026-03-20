"""DAG executor engine for VXIS plugin pipeline.

Manages dependency resolution, concurrent execution, cycle detection,
and node lifecycle for the plugin DAG.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vxis.core.context import PluginOutput

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Task state
# ---------------------------------------------------------------------------


class TaskState(Enum):
    """Lifecycle state of a single DAG node."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"


# ---------------------------------------------------------------------------
# Task node
# ---------------------------------------------------------------------------


@dataclass
class TaskNode:
    """Represents a single plugin as a node in the execution DAG."""

    plugin_name: str
    depends_on: list[str] = field(default_factory=list)
    optional_depends: list[str] = field(default_factory=list)
    timeout_seconds: int = 600
    state: TaskState = field(default=TaskState.PENDING)
    result: PluginOutput | None = None
    error: str | None = None
    started_at: float | None = None
    finished_at: float | None = None

    @property
    def duration_seconds(self) -> float | None:
        """Wall-clock duration of this node's execution."""
        if self.started_at is None or self.finished_at is None:
            return None
        return self.finished_at - self.started_at

    @property
    def is_terminal(self) -> bool:
        """True when the node has reached a final state."""
        return self.state in (
            TaskState.COMPLETED,
            TaskState.FAILED,
            TaskState.SKIPPED,
            TaskState.TIMED_OUT,
        )


# ---------------------------------------------------------------------------
# DAG executor
# ---------------------------------------------------------------------------

# Type alias for the coroutine that actually runs a single plugin.
# Receives the plugin name, must return a PluginOutput.
RunFunc = Callable[[str], Awaitable[PluginOutput]]

# States that represent a non-successful terminal outcome for a required dep.
# SKIPPED is included because if dep A is skipped, anything that depends on A
# should also be skipped — the transitive failure propagates down the chain.
_TERMINAL_FAILURE_STATES = {TaskState.FAILED, TaskState.TIMED_OUT, TaskState.SKIPPED}


class DAGExecutor:
    """Executes a plugin DAG respecting dependency ordering and concurrency limits.

    Dependency semantics
    --------------------
    - ``depends_on``:        hard dependencies — if any required dep is in a
                             failure state the dependent node is SKIPPED.
    - ``optional_depends``:  soft dependencies — failures are tolerated; the
                             node still executes without that input.

    Concurrency
    -----------
    An ``asyncio.Semaphore`` caps the number of nodes running at the same
    time.  Each node is wrapped in an ``asyncio.Event`` so that dependents
    can await completion without busy-polling.
    """

    def __init__(
        self,
        nodes: dict[str, TaskNode],
        max_concurrency: int = 8,
    ) -> None:
        self._nodes = nodes
        self._semaphore = asyncio.Semaphore(max_concurrency)
        # One asyncio.Event per node; set when the node reaches a terminal state.
        self._done_events: dict[str, asyncio.Event] = {
            name: asyncio.Event() for name in nodes
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def execute(self, run_func: RunFunc) -> dict[str, TaskNode]:
        """Execute all nodes respecting the dependency graph.

        Args:
            run_func: Async callable that accepts a plugin name and returns
                      a ``PluginOutput``.  The caller is responsible for
                      building the command, calling the tool, and parsing
                      the output.

        Returns:
            The ``nodes`` dict with updated state for every node.

        Raises:
            ValueError: If the DAG contains cycles.
        """
        self._validate_no_cycles()

        tasks = [
            asyncio.create_task(self._run_node(name, run_func), name=name)
            for name in self._nodes
        ]

        await asyncio.gather(*tasks, return_exceptions=True)
        return self._nodes

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_node(self, name: str, run_func: RunFunc) -> None:
        """Drive a single node through its lifecycle."""
        node = self._nodes[name]

        # 1. Wait for all hard dependencies to reach a terminal state.
        for dep_name in node.depends_on:
            dep_event = self._done_events.get(dep_name)
            if dep_event is not None:
                await dep_event.wait()

        # 2. Wait for optional dependencies (we still want their data if
        #    available, but we don't bail if they failed).
        for dep_name in node.optional_depends:
            dep_event = self._done_events.get(dep_name)
            if dep_event is not None:
                await dep_event.wait()

        # 3. Check whether any required dependency failed — if so, skip.
        for dep_name in node.depends_on:
            dep_node = self._nodes.get(dep_name)
            if dep_node is not None and dep_node.state in _TERMINAL_FAILURE_STATES:
                logger.warning(
                    "Skipping '%s': required dependency '%s' is in state '%s'.",
                    name,
                    dep_name,
                    dep_node.state.value,
                )
                node.state = TaskState.SKIPPED
                node.error = (
                    f"Required dependency '{dep_name}' is in state "
                    f"'{dep_node.state.value}'."
                )
                self._done_events[name].set()
                return

        # 4. Acquire the concurrency semaphore and execute.
        async with self._semaphore:
            node.state = TaskState.RUNNING
            node.started_at = time.monotonic()
            logger.debug("Starting plugin '%s'.", name)

            try:
                result = await asyncio.wait_for(
                    run_func(name),
                    timeout=node.timeout_seconds,
                )
                node.result = result
                node.state = TaskState.COMPLETED
                logger.debug("Plugin '%s' completed successfully.", name)

            except TimeoutError:
                node.state = TaskState.TIMED_OUT
                node.error = (
                    f"Plugin '{name}' timed out after {node.timeout_seconds}s."
                )
                logger.error(
                    "Plugin '%s' timed out after %ds.",
                    name,
                    node.timeout_seconds,
                )

            except Exception as exc:  # noqa: BLE001
                node.state = TaskState.FAILED
                node.error = str(exc)
                logger.exception("Plugin '%s' raised an unexpected error.", name)

            finally:
                node.finished_at = time.monotonic()
                self._done_events[name].set()

    def _validate_no_cycles(self) -> None:
        """Depth-first search cycle detection.

        Raises:
            ValueError: Describing the first cycle found.
        """
        # DFS colouring: 0 = unvisited, 1 = in-stack, 2 = fully explored
        color: dict[str, int] = {name: 0 for name in self._nodes}
        parent: dict[str, str | None] = {name: None for name in self._nodes}

        def _dfs(node_name: str) -> None:
            color[node_name] = 1  # mark as in-stack
            all_deps = (
                self._nodes[node_name].depends_on
                + self._nodes[node_name].optional_depends
            )
            for dep in all_deps:
                if dep not in color:
                    # unknown node — cycle detection only cares about known ones
                    continue
                if color[dep] == 1:
                    # Back-edge found → cycle
                    raise ValueError(
                        f"Cycle detected in DAG: '{node_name}' -> '{dep}'."
                    )
                if color[dep] == 0:
                    parent[dep] = node_name
                    _dfs(dep)
            color[node_name] = 2  # fully explored

        for name in self._nodes:
            if color[name] == 0:
                _dfs(name)


# ---------------------------------------------------------------------------
# Standalone validation helper
# ---------------------------------------------------------------------------


def validate_dag(nodes: dict[str, TaskNode]) -> list[str]:
    """Validate the DAG and return a list of human-readable error strings.

    Checks performed:
    - Missing hard dependencies (referenced name not present in ``nodes``).
    - Missing optional dependencies (referenced name not present in ``nodes``).
    - Cycles (via DFS).

    Returns:
        A (possibly empty) list of error descriptions.  An empty list means
        the DAG is valid.
    """
    errors: list[str] = []

    # Check for missing dependency references.
    for name, node in nodes.items():
        for dep in node.depends_on:
            if dep not in nodes:
                errors.append(
                    f"Node '{name}': required dependency '{dep}' is not defined."
                )
        for dep in node.optional_depends:
            if dep not in nodes:
                errors.append(
                    f"Node '{name}': optional dependency '{dep}' is not defined."
                )

    # Cycle detection — reuse DAGExecutor's DFS implementation.
    try:
        # Build a throw-away executor just for cycle detection.
        executor = DAGExecutor(nodes, max_concurrency=1)
        executor._validate_no_cycles()
    except ValueError as exc:
        errors.append(str(exc))

    return errors
