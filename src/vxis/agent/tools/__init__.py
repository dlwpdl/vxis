"""Tools package — BrainTool implementations and the default registry builder.

Future tasks will expand build_default_registry() with high-level Phase wrappers
(Tasks 7-11) and Finding CRUD (Task 12).
"""
from __future__ import annotations

from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools.control_tools import FinishScanTool, ThinkTool, WaitTool
from vxis.agent.tools.hands_tools import (
    HttpRequestTool,
    BrowserRenderTool,
    InterceptProxyTool,
)
from vxis.agent.tools.shell_tools import ShellExecTool
from vxis.agent.tools.python_tools import PythonExecTool
from vxis.agent.tools.finding_tools import (
    ReportFindingTool,
    QueryFindingsTool,
    LinkChainTool,
)
from vxis.agent.tools.playbook_tools import (
    ListPlaybooksTool,
    LoadPlaybookTool,
)
from vxis.agent.tools.fingerprint_tools import FingerprintTargetTool
from vxis.agent.tools.memory_tools import QueryScanMemoryTool
from vxis.agent.tools.verifier_tools import VerifyFindingTool

__all__ = [
    "FinishScanTool",
    "ThinkTool",
    "WaitTool",
    "HttpRequestTool",
    "BrowserRenderTool",
    "InterceptProxyTool",
    "ShellExecTool",
    "PythonExecTool",
    "ReportFindingTool",
    "QueryFindingsTool",
    "LinkChainTool",
    "ListPlaybooksTool",
    "LoadPlaybookTool",
    "FingerprintTargetTool",
    "QueryScanMemoryTool",
    "VerifyFindingTool",
    "build_default_registry",
]


def build_default_registry(brain: object | None = None) -> ToolRegistry:
    """Build a ToolRegistry with the default tool set registered.

    Phase B: playbook + fingerprint + memory tools let Brain auto-detect
    stack and pull stack-specific techniques.

    Phase C: verify_finding tool added — adversarial verifier that uses
    a stronger model to refute claimed findings. If `brain` is passed,
    it's injected into VerifyFindingTool so the verifier can reuse the
    brain's provider fallback chain.
    """
    reg = ToolRegistry()
    reg.register(FinishScanTool())
    reg.register(ThinkTool())
    reg.register(WaitTool())
    reg.register(HttpRequestTool())
    reg.register(BrowserRenderTool())
    reg.register(InterceptProxyTool())
    reg.register(ShellExecTool())
    reg.register(PythonExecTool())
    reg.register(ReportFindingTool())
    reg.register(QueryFindingsTool())
    reg.register(LinkChainTool())
    reg.register(ListPlaybooksTool())
    reg.register(LoadPlaybookTool())
    reg.register(FingerprintTargetTool())
    reg.register(QueryScanMemoryTool())
    verifier = VerifyFindingTool(brain=brain)
    reg.register(verifier)
    return reg
