from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from .context import AgentContext
from ..graph.hypothesis import Hypothesis
from ..evidence.schema import Evidence


@dataclass
class AgentResult:
    agent_id: str
    findings: list[Evidence]
    hypotheses: list[Hypothesis]
    status: str  # "completed" | "error" | "partial"
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status == "completed"


class BaseAgent(ABC):
    agent_id: str = ""
    description: str = ""

    @abstractmethod
    async def run(self, context: AgentContext) -> AgentResult:
        """에이전트 실행. 발견물 + 새 가설 반환."""
        ...
