from __future__ import annotations

import json
from typing import Any, Iterable

from agents import Agent, FunctionTool
from agents.model_settings import ModelSettings

from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.llm.model_registry import is_reasoning_model


def _model_id_for_capability_lookup(model: str | None) -> str:
    value = str(model or "").strip()
    if "/" not in value:
        return value
    provider, model_id = value.split("/", 1)
    if provider.lower() in {"openai", "anthropic", "gemini", "together", "deepseek"}:
        return model_id
    return value


def _looks_like_reasoning_model(model: str | None) -> bool:
    model_id = _model_id_for_capability_lookup(model)
    lower = model_id.lower()
    if is_reasoning_model(model_id):
        return True
    return lower.startswith(("o1", "o3", "o4")) or "deepseek-r1" in lower or "/r1" in lower


def make_vxis_model_settings(*, require_tool: bool = True, model: str | None = None) -> ModelSettings:
    """Return the SDK settings VXIS needs for single-step security agents."""
    reasoning_model = _looks_like_reasoning_model(model)
    return ModelSettings(
        tool_choice="required" if require_tool and not reasoning_model else None,
        parallel_tool_calls=False,
        include_usage=True,
    )


def build_vxis_sdk_agent(
    *,
    name: str,
    instructions: str,
    tools: Iterable[FunctionTool],
    model: str | None = None,
    require_tool: bool = True,
) -> Agent:
    """Build an SDK Agent with VXIS' lifecycle defaults."""
    return Agent(
        name=name,
        instructions=instructions,
        model=model,
        tools=list(tools),
        model_settings=make_vxis_model_settings(require_tool=require_tool, model=model),
        reset_tool_choice=False,
    )


def sdk_tools_from_registry(
    registry: ToolRegistry,
    *,
    tool_names: Iterable[str] | None = None,
) -> list[FunctionTool]:
    names = list(tool_names) if tool_names is not None else registry.list_tools()
    return [sdk_tool_from_registry(registry, name) for name in names]


def sdk_tool_from_registry(registry: ToolRegistry, name: str) -> FunctionTool:
    tool = registry.get_tool(name)
    if tool is None:
        raise KeyError(f"unknown VXIS tool: {name}")

    async def _invoke(_ctx: Any, raw_input: str) -> str:
        args = _parse_sdk_tool_args(raw_input)
        if not isinstance(args, dict):
            return _dump_tool_result(
                ToolResult(
                    ok=False,
                    summary=f"invalid args for {name}: expected JSON object",
                    error="invalid_json_args",
                )
            )
        result = await registry.dispatch(name, args)
        return _dump_tool_result(result)

    return FunctionTool(
        name=tool.name,
        description=tool.description,
        params_json_schema=tool.input_schema,
        on_invoke_tool=_invoke,
        strict_json_schema=False,
    )


def _parse_sdk_tool_args(raw_input: str) -> Any:
    if not raw_input:
        return {}
    try:
        return json.loads(raw_input)
    except json.JSONDecodeError:
        return None


def _dump_tool_result(result: ToolResult) -> str:
    return json.dumps(
        {
            "ok": bool(result.ok),
            "summary": str(result.summary or ""),
            "data": result.data if isinstance(result.data, dict) else {},
            "error": result.error,
        },
        ensure_ascii=False,
        default=str,
    )
