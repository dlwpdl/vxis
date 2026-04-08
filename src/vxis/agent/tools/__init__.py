"""Tools package — BrainTool implementations and the default registry builder.

Future tasks will expand build_default_registry() with Hands/Eyes/X-Ray primitives
(Task 6), high-level Phase wrappers (Tasks 7-11), and Finding CRUD (Task 12).
"""
from __future__ import annotations

from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools.control_tools import FinishScanTool, ThinkTool, WaitTool

__all__ = ["FinishScanTool", "ThinkTool", "WaitTool", "build_default_registry"]


def build_default_registry() -> ToolRegistry:
    """Build a ToolRegistry with the default set of control tools registered.

    As Tasks 6-12 land, this helper will also register Hands/Eyes/X-Ray primitives,
    high-level Phase wrappers, and Finding CRUD tools.
    """
    reg = ToolRegistry()
    reg.register(FinishScanTool())
    reg.register(ThinkTool())
    reg.register(WaitTool())
    return reg
