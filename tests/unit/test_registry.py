"""Unit tests for the plugin registry."""

from __future__ import annotations

from typing import Any

import pytest

from vxis.core.context import DAGContext, PluginOutput
from vxis.core.engine import TaskNode, TaskState
from vxis.plugins.base import BasePlugin, PluginMeta
from vxis.plugins.registry import build_dag_from_plugins, discover_plugins


# ---------------------------------------------------------------------------
# Inline test plugins
# ---------------------------------------------------------------------------


class _ReconPlugin(BasePlugin):
    """Minimal concrete plugin used in tests — no real binary needed."""

    @property
    def meta(self) -> PluginMeta:
        return PluginMeta(
            name="test-recon",
            version="1.0.0",
            tool_binary="subfinder",
            category="recon",
            depends_on=(),
            optional_depends=(),
            timeout_seconds=120,
        )

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        return f"subfinder -d {target}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
        )


class _ScanPlugin(BasePlugin):
    """Second test plugin that depends on the recon plugin."""

    @property
    def meta(self) -> PluginMeta:
        return PluginMeta(
            name="test-scan",
            version="2.0.0",
            tool_binary="httpx",
            category="scan",
            depends_on=("test-recon",),
            optional_depends=("test-whois",),
            timeout_seconds=300,
        )

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        return "httpx -l targets.txt"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
        )


class _OptionalDepPlugin(BasePlugin):
    """Plugin with an optional dependency only."""

    @property
    def meta(self) -> PluginMeta:
        return PluginMeta(
            name="test-whois",
            version="1.0.0",
            tool_binary="whois",
            category="recon",
            depends_on=(),
            optional_depends=(),
            timeout_seconds=60,
        )

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        return f"whois {target}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
        )


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def inline_registry() -> dict[str, BasePlugin]:
    """Registry built from the inline test plugins above."""
    recon = _ReconPlugin()
    scan = _ScanPlugin()
    whois = _OptionalDepPlugin()
    return {
        recon.meta.name: recon,
        scan.meta.name: scan,
        whois.meta.name: whois,
    }


# ---------------------------------------------------------------------------
# Test: discover_plugins
# ---------------------------------------------------------------------------


def test_discover_plugins_returns_dict() -> None:
    """discover_plugins must always return a dict (even if empty)."""
    result = discover_plugins()
    assert isinstance(result, dict)


def test_discover_plugins_finds_at_least_zero_plugins() -> None:
    """Discovering plugins from the real package is acceptable with 0 results."""
    result = discover_plugins("vxis.plugins")
    # Each value must be a BasePlugin instance.
    for name, plugin in result.items():
        assert isinstance(plugin, BasePlugin), (
            f"Expected BasePlugin but got {type(plugin)} for '{name}'"
        )


def test_discover_plugins_with_nonexistent_package() -> None:
    """Providing an unknown package path returns an empty dict without raising."""
    result = discover_plugins("vxis.plugins.does_not_exist_xyz")
    assert result == {}


# ---------------------------------------------------------------------------
# Test: build_dag_from_plugins creates correct TaskNodes
# ---------------------------------------------------------------------------


def test_build_dag_creates_task_node_for_each_plugin(
    inline_registry: dict[str, BasePlugin],
) -> None:
    """Every plugin in the registry must map to a TaskNode in the DAG."""
    dag = build_dag_from_plugins(inline_registry)

    assert set(dag.keys()) == set(inline_registry.keys())
    for name, node in dag.items():
        assert isinstance(node, TaskNode)
        assert node.plugin_name == name


def test_build_dag_sets_correct_depends_on(
    inline_registry: dict[str, BasePlugin],
) -> None:
    """depends_on on TaskNode must match PluginMeta.depends_on."""
    dag = build_dag_from_plugins(inline_registry)

    scan_node = dag["test-scan"]
    assert "test-recon" in scan_node.depends_on


def test_build_dag_sets_correct_optional_depends(
    inline_registry: dict[str, BasePlugin],
) -> None:
    """optional_depends on TaskNode must match PluginMeta.optional_depends."""
    dag = build_dag_from_plugins(inline_registry)

    scan_node = dag["test-scan"]
    assert "test-whois" in scan_node.optional_depends


def test_build_dag_sets_correct_timeout(
    inline_registry: dict[str, BasePlugin],
) -> None:
    """timeout_seconds on TaskNode must match PluginMeta.timeout_seconds."""
    dag = build_dag_from_plugins(inline_registry)

    assert dag["test-recon"].timeout_seconds == 120
    assert dag["test-scan"].timeout_seconds == 300
    assert dag["test-whois"].timeout_seconds == 60


def test_build_dag_initial_state_is_pending(
    inline_registry: dict[str, BasePlugin],
) -> None:
    """All freshly built TaskNodes must start in PENDING state."""
    dag = build_dag_from_plugins(inline_registry)

    for name, node in dag.items():
        assert node.state == TaskState.PENDING, (
            f"Node '{name}' should start PENDING but is {node.state}"
        )


def test_build_dag_from_empty_registry() -> None:
    """An empty registry must produce an empty DAG dict."""
    dag = build_dag_from_plugins({})
    assert dag == {}


def test_build_dag_node_with_no_deps() -> None:
    """A plugin with no dependencies must produce a node with empty dep lists."""
    registry = {"test-recon": _ReconPlugin()}
    dag = build_dag_from_plugins(registry)

    node = dag["test-recon"]
    assert node.depends_on == []
    assert node.optional_depends == []


# ---------------------------------------------------------------------------
# Test: plugin metadata integrity
# ---------------------------------------------------------------------------


def test_plugin_meta_name_matches_registry_key(
    inline_registry: dict[str, BasePlugin],
) -> None:
    """meta.name must equal the key used in the registry."""
    for name, plugin in inline_registry.items():
        assert plugin.meta.name == name, (
            f"Plugin registered as '{name}' but meta.name is '{plugin.meta.name}'"
        )


def test_plugin_meta_fields_are_correct() -> None:
    """Spot-check meta fields on the inline scan plugin."""
    plugin = _ScanPlugin()
    meta = plugin.meta

    assert meta.name == "test-scan"
    assert meta.version == "2.0.0"
    assert meta.tool_binary == "httpx"
    assert meta.category == "scan"
    assert "test-recon" in meta.depends_on
    assert "test-whois" in meta.optional_depends
    assert meta.timeout_seconds == 300
