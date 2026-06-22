"""Tools package — BrainTool implementations and the default registry builder.

Future tasks will expand build_default_registry() with high-level Phase wrappers
(Tasks 7-11) and Finding CRUD (Task 12).
"""

from __future__ import annotations

import logging
import os

from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools.control_tools import FinishScanTool, ThinkTool, WaitTool
from vxis.agent.tools.hands_tools import (
    HttpRequestTool,
    BrowserRenderTool,
    InterceptProxyTool,
)
from vxis.agent.tools.shell_tools import ShellExecTool
from vxis.agent.tools.nmap_tools import NmapScanTool
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
from vxis.agent.tools.skill_runner import RunSkillTool
from vxis.agent.tools.agent_graph_tools import AgentGraphTool
from vxis.agent.tools.browser_tools import (
    BrowserNavigateTool,
    BrowserAnalyzeDomTool,
    BrowserClickTool,
    BrowserFillFormTool,
    BrowserScreenshotTool,
    BrowserEvalJsTool,
    BrowserGetCookiesTool,
)
from vxis.agent.scan_loop_v3 import v3_enabled

__all__ = [
    "FinishScanTool",
    "ThinkTool",
    "WaitTool",
    "HttpRequestTool",
    "BrowserRenderTool",
    "InterceptProxyTool",
    "ShellExecTool",
    "NmapScanTool",
    "PythonExecTool",
    "ReportFindingTool",
    "QueryFindingsTool",
    "LinkChainTool",
    "ListPlaybooksTool",
    "LoadPlaybookTool",
    "FingerprintTargetTool",
    "QueryScanMemoryTool",
    "VerifyFindingTool",
    "AgentGraphTool",
    "build_default_registry",
]

logger = logging.getLogger(__name__)


def build_default_registry(
    brain: object | None = None,
    sandbox_key: str | None = None,
    *,
    box_mode: str = "black",
) -> ToolRegistry:
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
    reg.register(ShellExecTool(sandbox_key=sandbox_key))
    # nmap is OFF by default: it is not installed in the sandbox image, and
    # active port/service scanning carries scope/noise/legality risk. Opt in
    # explicitly with VXIS_ENABLE_NMAP=1 (and install nmap in the sandbox).
    if os.environ.get("VXIS_ENABLE_NMAP", "").strip().lower() in {"1", "true", "yes", "on"}:
        reg.register(NmapScanTool(sandbox_key=sandbox_key))
    reg.register(PythonExecTool(sandbox_key=sandbox_key))
    reg.register(ReportFindingTool())
    reg.register(QueryFindingsTool())
    reg.register(LinkChainTool())
    reg.register(ListPlaybooksTool())
    reg.register(LoadPlaybookTool())
    reg.register(FingerprintTargetTool())
    reg.register(QueryScanMemoryTool())
    verifier = VerifyFindingTool(brain=brain)
    reg.register(verifier)
    # Phase C Eyes integration: browser tools for rendered-page visibility.
    # Graceful: if Playwright not installed, tools will return error on use.
    reg.register(BrowserNavigateTool())
    reg.register(BrowserAnalyzeDomTool())
    reg.register(BrowserClickTool())
    reg.register(BrowserFillFormTool())
    reg.register(BrowserScreenshotTool())
    reg.register(BrowserEvalJsTool())
    reg.register(BrowserGetCookiesTool())
    reg.register(RunSkillTool())
    reg.register(AgentGraphTool())
    if v3_enabled():
        _register_optional_v3_tools(reg)
    # Production scans are black-box today. Source-aware CODE tools must be
    # completed and promoted deliberately before they are registered here.
    _enforce_box_mode(reg, box_mode)
    return reg


def _enforce_box_mode(reg: ToolRegistry, box_mode: str) -> None:
    """NOW-2/2b (F5): in black-box, no registered tool may grant source access.

    Keyed on explicit ``source_access`` metadata (ToolRegistry.tool_is_source_aware),
    so a future source-aware tool under ANY module path cannot silently leak — a
    hard build-time guarantee for "black-box must be fully black-box". White/grey
    may carry source-aware tools.
    """
    if box_mode == "black":
        leaked = [t.name for t in reg._tools.values() if ToolRegistry.tool_is_source_aware(t)]
        if leaked:
            raise RuntimeError(f"black-box registry leaked source-aware tools: {leaked}")


def _register_optional_v3_tools(reg: ToolRegistry) -> None:
    """Register v3 tools if their modules are present.

    v3 components land behind feature flags and can be developed in slices.
    Missing modules are ignored so Phase A-E scans keep their existing behavior.
    """
    try:
        from vxis.agent.tools.hypothesis_tools import build_hypothesis_tools

        for tool in build_hypothesis_tools():
            if not reg.has_tool(tool.name):
                reg.register(tool)
    except Exception as exc:
        logger.debug("optional v3 hypothesis tools unavailable: %s", exc)

    optional_tools = [
        ("vxis.agent.tools.ask_human", "AskHumanTool"),
        ("vxis.agent.tools.self_critique", "SelfCritiqueTool"),
    ]
    for module_name, class_name in optional_tools:
        try:
            module = __import__(module_name, fromlist=[class_name])
            tool_cls = getattr(module, class_name)
            tool = tool_cls()
            if not reg.has_tool(tool.name):
                reg.register(tool)
        except Exception as exc:
            logger.debug("optional v3 tool %s.%s unavailable: %s", module_name, class_name, exc)
            continue
