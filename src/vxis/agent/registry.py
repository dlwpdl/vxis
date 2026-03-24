from __future__ import annotations
from .base import BaseAgent

_REGISTRY: dict[str, type[BaseAgent]] = {}


def register(agent_class: type[BaseAgent]) -> type[BaseAgent]:
    """에이전트 클래스 등록 데코레이터."""
    _REGISTRY[agent_class.agent_id] = agent_class
    return agent_class


def get_agent(agent_id: str) -> type[BaseAgent] | None:
    return _REGISTRY.get(agent_id)


def list_agents() -> list[str]:
    return list(_REGISTRY.keys())


def spawn(agent_id: str) -> BaseAgent | None:
    cls = get_agent(agent_id)
    return cls() if cls else None
