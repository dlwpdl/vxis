"""Control tools for ScanAgentLoop — minimal primitives the Brain uses to manage loop flow.

These are BrainTool implementations of:
- finish_scan: signal end of scan
- think: scratchpad reasoning (logged, no side effects)
- wait: brief pause (max 5s, clamped)

Every ScanAgentLoop registers these by default via tools.build_default_registry().
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

_MAX_WAIT_SECONDS = 5.0


class FinishScanTool:
    name = "finish_scan"
    description = "End the scan. Emit this when reconnaissance and analysis are complete, or when no further productive actions are possible."
    input_schema: dict[str, Any] = {"type": "object", "properties": {}}

    async def run(self, **kwargs: Any) -> ToolResult:
        return ToolResult(ok=True, data={"final": True}, summary="scan finished")


class ThinkTool:
    name = "think"
    description = "Record a reasoning step (scratchpad). No side effects. Use for intermediate planning thoughts that should be visible in the scan log but don't require an action."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"thought": {"type": "string"}},
        "required": ["thought"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        thought = str(kwargs.get("thought", ""))
        logger.info("[Brain.think] %s", thought[:500])
        return ToolResult(ok=True, summary=f"noted: {thought[:100]}")


class WaitTool:
    name = "wait"
    description = "Pause for a brief moment (max 5 seconds, clamped). Use when waiting for rate limits, async state settling, or deliberately pacing requests."
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {"seconds": {"type": "number", "minimum": 0, "maximum": _MAX_WAIT_SECONDS}},
        "required": ["seconds"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        raw = kwargs.get("seconds", 0)
        try:
            seconds = float(raw)
        except (TypeError, ValueError):
            seconds = 0.0
        clamped = max(0.0, min(_MAX_WAIT_SECONDS, seconds))
        await asyncio.sleep(clamped)
        return ToolResult(ok=True, summary=f"waited {clamped}s")
