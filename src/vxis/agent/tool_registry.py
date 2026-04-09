from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

@dataclass
class ToolResult:
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    error: str | None = None

@runtime_checkable
class BrainTool(Protocol):
    name: str
    description: str
    input_schema: dict[str, Any]
    async def run(self, **kwargs: Any) -> ToolResult: ...

class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, BrainTool] = {}

    def register(self, tool: BrainTool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool {tool.name} already registered")
        self._tools[tool.name] = tool

    def list_tools(self) -> list[str]:
        return sorted(self._tools.keys())

    def describe_all(self) -> list[dict[str, Any]]:
        return [
            {"name": t.name, "description": t.description, "input_schema": t.input_schema}
            for t in self._tools.values()
        ]

    async def dispatch(self, name: str, args: dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(ok=False, summary=f"unknown tool: {name}", error="unknown_tool")
        try:
            return await tool.run(**args)
        except Exception as e:
            return ToolResult(ok=False, summary=f"tool {name} raised {type(e).__name__}: {e}", error=str(e))
