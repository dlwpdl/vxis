"""Brain Protocol — Brain 인터페이스 정의 (structural typing)."""

from __future__ import annotations

from typing import Any, Protocol

from vxis.agent.brain import AgentAction, AgentObservation


class BrainProtocol(Protocol):
    """AgentExecutor가 사용하는 Brain 인터페이스.

    세 가지 구현:
        1. AgentBrain     — 외부 LLM API 호출 (자율 모드)
        2. InteractiveBrain — stdin/stdout JSON (Claude Code 모드)
        3. FileBasedBrain   — 파일 프로토콜 (Claude Code 모드)
    """

    is_done: bool
    max_steps: int
    _step_count: int

    def think(self, observation: AgentObservation) -> list[AgentAction]: ...

    def record_result(self, action: AgentAction, result: dict[str, Any]) -> None: ...

    def get_execution_log(self) -> str: ...
