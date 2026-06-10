from __future__ import annotations
import inspect
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

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def get_tool(self, name: str) -> BrainTool | None:
        return self._tools.get(name)

    def describe_all(self) -> list[dict[str, Any]]:
        from vxis.agent.egress_contract import describe_tool_target_egress

        return [
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "target_egress": describe_tool_target_egress(t.name),
            }
            for t in self._tools.values()
        ]

    def validate_args(self, name: str, args: Any) -> list[str]:
        """Return human-readable validation errors for a tool invocation.

        This is intentionally a small JSON-Schema subset. Individual tools
        still do semantic validation; the registry catches only malformed LLM
        calls that would otherwise become noisy Python exceptions.
        """
        tool = self._tools.get(name)
        if tool is None:
            return [f"unknown tool: {name}"]
        if not isinstance(args, dict):
            return [f"args for {name} must be an object"]

        schema = getattr(tool, "input_schema", {}) or {}
        if not isinstance(schema, dict):
            return []

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}

        errors: list[str] = []
        for field_name in schema.get("required", []) or []:
            prop_schema = properties.get(field_name, {})
            if isinstance(prop_schema, dict) and "default" in prop_schema:
                continue
            value = args.get(field_name)
            if value is None or (isinstance(value, str) and not value.strip()):
                errors.append(f"missing required arg: {field_name}")

        for field_name, value in args.items():
            prop_schema = properties.get(field_name)
            if not isinstance(prop_schema, dict):
                continue
            expected_type = prop_schema.get("type")
            if expected_type and not _matches_json_type(value, expected_type):
                errors.append(f"arg {field_name} must be {expected_type}")
                continue
            enum_values = prop_schema.get("enum")
            if (
                isinstance(enum_values, list)
                and value not in enum_values
                and not _matches_string_enum_case_insensitive(value, enum_values)
            ):
                errors.append(f"arg {field_name} must be one of {enum_values}")

        return errors

    async def dispatch(self, name: str, args: dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(ok=False, summary=f"unknown tool: {name}", error="unknown_tool")
        validation_errors = self.validate_args(name, args)
        if validation_errors:
            return ToolResult(
                ok=False,
                summary=f"invalid args for {name}: " + "; ".join(validation_errors),
                error="invalid_args",
            )
        try:
            from vxis.p1.runtime_gate import enforce_tool_invocation

            p1_decision = enforce_tool_invocation(name, args)
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"P1 runtime gate failed before {name}: {type(e).__name__}: {e}",
                error="p1_gate_failed",
            )
        if p1_decision is not None and not p1_decision.allowed:
            return ToolResult(
                ok=False,
                data={
                    "blocked": True,
                    "policy": "p1_engagement_scope",
                    "audit": p1_decision.audit_entry or {},
                },
                summary=f"{name} BLOCKED by P1 engagement gate: {p1_decision.reason}",
                error="p1_scope_blocked",
            )
        # Standard-path scope gate (active for any scan that set an ambient scope).
        try:
            from vxis.scope.runtime_gate import enforce_scope_invocation

            scope_decision = enforce_scope_invocation(name, args)
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"scope gate failed before {name}: {type(e).__name__}: {e}",
                error="scope_gate_failed",
            )
        if scope_decision is not None and not scope_decision.allowed:
            return ToolResult(
                ok=False,
                data={
                    "blocked": True,
                    "policy": scope_decision.policy or "scope",
                    "requires_approval": scope_decision.requires_approval,
                },
                summary=f"{name} BLOCKED by scope gate: {scope_decision.reason}",
                error="scope_blocked",
            )
        try:
            return await tool.run(**args)
        except Exception as e:
            return ToolResult(ok=False, summary=f"tool {name} raised {type(e).__name__}: {e}", error=str(e))

    async def cleanup(self) -> None:
        """Best-effort cleanup hook for tools that own per-scan resources."""
        seen: set[int] = set()
        for tool in self._tools.values():
            marker = id(tool)
            if marker in seen:
                continue
            seen.add(marker)
            cleanup = getattr(tool, "cleanup", None)
            if cleanup is None:
                continue
            result = cleanup()
            if inspect.isawaitable(result):
                await result


def _matches_json_type(value: Any, expected_type: Any) -> bool:
    """Permissive top-level JSON type check for LLM-produced args."""
    if isinstance(expected_type, list):
        return any(_matches_json_type(value, item) for item in expected_type)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return (
            isinstance(value, int) and not isinstance(value, bool)
        ) or (isinstance(value, str) and value.strip().lstrip("-").isdigit())
    if expected_type == "number":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if isinstance(value, str):
            try:
                float(value.strip())
                return True
            except ValueError:
                return False
        return False
    if expected_type == "boolean":
        return isinstance(value, bool) or (
            isinstance(value, str) and value.strip().lower() in {"true", "false"}
        )
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "null":
        return value is None
    return True


def _matches_string_enum_case_insensitive(value: Any, enum_values: list[Any]) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    return any(isinstance(item, str) and lowered == item.lower() for item in enum_values)
