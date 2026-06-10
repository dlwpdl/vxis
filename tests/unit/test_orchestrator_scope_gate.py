"""Unit tests for the ambient scope gate on the orchestrator plugin scan path.

The plugin scan path in ScanOrchestrator._make_run_func does NOT route through
ToolRegistry.dispatch, so it previously bypassed the ambient scope gate. These
tests verify the gate now blocks out-of-scope plugin runs fail-closed, while
leaving non-scoped runs unaffected (gate returns None when no scope is active).
"""

import pytest

from vxis.config.schema import VXISConfig
from vxis.core.context import DAGContext
from vxis.core.orchestrator import ScanOrchestrator
from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.runtime_gate import clear_active_scope, set_active_scope
from vxis.scope.schemas import ScopeConfig


@pytest.fixture(autouse=True)
def _reset_scope():
    """Ensure no ambient scope leaks between tests."""
    clear_active_scope()
    yield
    clear_active_scope()


class _ReachedBuildCommand(Exception):
    """Raised by the fake plugin to prove the gate let execution proceed."""


class FakePlugin:
    """Records whether build_command is reached.

    On the blocked path the gate returns before build_command, so ``built``
    stays False. On the allowed path we raise a sentinel from build_command so
    the test can assert the gate passed without driving the full run_tool
    execution machinery (which needs a real plugin with parse_output, etc.).
    """

    def __init__(self) -> None:
        self.built = False

    def build_command(self, **kwargs):
        self.built = True
        raise _ReachedBuildCommand

    def get_timeout(self, profile):
        return 1


def _make_enforcer(in_scope: list[str]) -> ScopeEnforcer:
    return ScopeEnforcer(
        ScopeConfig(
            scan_id="scan-test",
            target=in_scope[0] if in_scope else "",
            in_scope_domains=in_scope,
            out_of_scope=[],
            path_rules={},
            http_methods={},
            data_sensitivity={},
            account_rules={},
            destructive_actions={},
            time_window={},
            rate_limits={},
            audit={},
        )
    )


@pytest.mark.asyncio
async def test_scope_gate_blocks_out_of_scope_plugin(tmp_path):
    """An active scope of app.acme.com must block a plugin run on evil.com,
    before build_command is ever called."""
    set_active_scope(_make_enforcer(["app.acme.com"]))

    plugin = FakePlugin()
    orchestrator = ScanOrchestrator(VXISConfig(data_dir=tmp_path))
    context = DAGContext(target="http://evil.com", scan_profile="standard")
    run = orchestrator._make_run_func(
        registry={"nmap": plugin},
        dag_context=context,
        target="http://evil.com",
        profile="standard",
        scan_id="scan-test",
    )

    output = await run("nmap")

    assert plugin.built is False
    assert output.parsed_data.get("blocked") is True
    assert output.errors  # reason recorded
    # The blocked output is also stored in the DAG context for downstream nodes.
    assert context.get("nmap").parsed_data.get("blocked") is True


@pytest.mark.asyncio
async def test_scope_gate_allows_in_scope_plugin(tmp_path):
    """A plugin run on an in-scope host is not blocked by the scope gate."""
    set_active_scope(_make_enforcer(["app.acme.com"]))

    plugin = FakePlugin()
    orchestrator = ScanOrchestrator(VXISConfig(data_dir=tmp_path))
    context = DAGContext(target="http://app.acme.com", scan_profile="standard")
    run = orchestrator._make_run_func(
        registry={"nmap": plugin},
        dag_context=context,
        target="http://app.acme.com",
        profile="standard",
        scan_id="scan-test",
    )

    with pytest.raises(_ReachedBuildCommand):
        await run("nmap")

    # Not blocked by scope: execution proceeded past the gate into build_command.
    assert plugin.built is True


@pytest.mark.asyncio
async def test_no_active_scope_leaves_run_unaffected(tmp_path):
    """With no ambient scope active, the gate returns None and the plugin runs
    even against an arbitrary target (non-scoped runs unaffected)."""
    # Note: _reset_scope autouse fixture guarantees no active scope here.
    plugin = FakePlugin()
    orchestrator = ScanOrchestrator(VXISConfig(data_dir=tmp_path))
    context = DAGContext(target="http://evil.com", scan_profile="standard")
    run = orchestrator._make_run_func(
        registry={"nmap": plugin},
        dag_context=context,
        target="http://evil.com",
        profile="standard",
        scan_id="scan-test",
    )

    with pytest.raises(_ReachedBuildCommand):
        await run("nmap")

    assert plugin.built is True
