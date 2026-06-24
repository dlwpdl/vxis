import importlib.util

import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools.agent_graph_tools import AgentGraphTool


def test_sdk_runtime_not_importable_from_production_src() -> None:
    assert importlib.util.find_spec("vxis.agent.sdk_runtime") is None


def test_sdk_runtime_flag_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VXIS_USE_SDK_AGENT_RUNTIME", "1")
    registry = ToolRegistry()
    registry.register(AgentGraphTool())

    with pytest.raises(RuntimeError, match="incubator-only"):
        ScanAgentLoop(target="http://example.test", registry=registry)
