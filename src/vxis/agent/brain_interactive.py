"""VXIS InteractiveBrain — Claude Code가 Brain이 되는 모드.

stdin/stdout NDJSON 프로토콜로 외부 프로세스(Claude Code)와 통신.

Protocol:
    VXIS → stdout: {"type": "observation", ...}   — Brain에게 현재 상태 전달
    stdin → VXIS:  {"type": "decision", "actions": [...]}  — Brain의 판단
    VXIS → stdout: {"type": "result", ...}         — 실행 결과 알림
    VXIS → stdout: {"type": "complete", ...}       — 스캔 완료

Usage:
    vxis scan https://target.com --interactive
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, TextIO

from vxis.ghost.trigger import detect_ghost_keyword
from vxis.ghost.layer import ghost_layer
from vxis.agent.brain import (
    AgentAction,
    AgentObservation,
    AgentStep,
    TOOL_DESCRIPTIONS,
    _increment_brain_decision_count,
)

logger = logging.getLogger(__name__)


class InteractiveBrain:
    """Claude Code (또는 다른 외부 프로세스)가 Brain 역할을 하는 인터랙티브 모드.

    think()가 호출되면:
        1. 현재 observation을 JSON으로 stdout에 출력
        2. stdin에서 action 결정을 읽어옴 (blocking)
        3. AgentAction 리스트로 반환
    """

    def __init__(
        self,
        max_steps: int = 15,
        input_stream: TextIO | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        self.is_done = False
        self.max_steps = max_steps
        self._step_count = 0
        self._steps: list[AgentStep] = []
        self._input = input_stream or sys.stdin
        self._output = output_stream or sys.stdout

    def _emit(self, msg: dict[str, Any]) -> None:
        """stdout에 JSON 한 줄 출력."""
        self._output.write(json.dumps(msg, ensure_ascii=False, default=str) + "\n")
        self._output.flush()

    def _read_decision(self) -> dict[str, Any]:
        """stdin에서 JSON 한 줄 읽기 (blocking)."""
        try:
            line = self._input.readline()
            if not line or not line.strip():
                logger.warning("stdin closed or empty — 스캔 종료")
                self.is_done = True
                return {"actions": [{"tool": "DONE", "reasoning": "stdin closed"}]}

            # ghost 키워드 감지 (JSON 파싱 전 raw text 검사)
            if detect_ghost_keyword(line) and not ghost_layer.is_active():
                ghost_layer.activate()
                self._emit(
                    {
                        "type": "ghost_activated",
                        "message": "[GHOST MODE ACTIVATED] 익명화 모드 활성화됨",
                    }
                )
                logger.info("[Ghost] Brain 자연어 트리거 감지 → 활성화")

            return json.loads(line.strip())
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON from stdin: %s", e)
            return {"actions": [{"tool": "DONE", "reasoning": f"JSON parse error: {e}"}]}

    def think(self, observation: AgentObservation) -> list[AgentAction]:
        """Brain 판단 요청 — observation 출력 후 decision 대기."""
        if self.is_done or self._step_count >= self.max_steps:
            self.is_done = True
            return []

        self._step_count += 1
        _increment_brain_decision_count()

        # Observation을 JSON으로 출력 (Claude Code가 읽음)
        obs_msg: dict[str, Any] = {
            "type": "observation",
            "step": self._step_count,
            "max_steps": self.max_steps,
            "target": observation.target,
            "tech_stack": observation.tech_stack,
            "open_ports": observation.open_ports[:30],
            "findings": observation.findings[:50],
            "executed_tools": observation.executed_tools,
            "subdomains": observation.subdomains[:20],
            "live_urls": observation.live_urls[:20],
            "available_tools": TOOL_DESCRIPTIONS,
        }
        self._emit(obs_msg)

        # Claude Code의 판단 대기
        decision = self._read_decision()

        # 파싱
        actions: list[AgentAction] = []
        for a in decision.get("actions", []):
            actions.append(
                AgentAction(
                    tool=a.get("tool", "DONE"),
                    args=a.get("args", {}),
                    reasoning=a.get("reasoning", ""),
                    priority=a.get("priority", "medium"),
                )
            )

        if not actions:
            actions = [AgentAction(tool="DONE", reasoning="no actions provided")]

        # DONE 체크
        if any(a.tool == "DONE" for a in actions):
            self.is_done = True

        # 스텝 기록
        self._steps.append(
            AgentStep(
                step_number=self._step_count,
                observation_summary=f"Step {self._step_count}: {len(observation.findings)} findings, {len(observation.executed_tools)} tools run",
                actions=actions,
            )
        )

        logger.info(
            "Step %d: %d action(s) — %s",
            self._step_count,
            len(actions),
            ", ".join(a.tool for a in actions),
        )

        return actions

    def record_result(self, action: AgentAction, result: dict[str, Any]) -> None:
        """실행 결과를 stdout으로 알림 (Claude Code가 다음 판단에 참고)."""
        self._emit(
            {
                "type": "result",
                "action": {"tool": action.tool, "args": action.args, "reasoning": action.reasoning},
                "result": result,
            }
        )

        if self._steps:
            self._steps[-1].results.append(
                {
                    "tool": action.tool,
                    "result_summary": str(result.get("summary", ""))[:500],
                    "findings_count": result.get("findings_count", 0),
                    "success": result.get("success", True),
                }
            )

    def get_execution_log(self) -> str:
        """실행 로그 반환."""
        lines = ["## AI Agent Execution Log (Interactive Mode)\n"]
        for step in self._steps:
            lines.append(f"### Step {step.step_number}")
            lines.append(f"- {step.observation_summary}")
            for action in step.actions:
                lines.append(f"- Action: {action.tool} — {action.reasoning}")
            for result in step.results:
                lines.append(
                    f"- Result: {result['tool']} — "
                    f"{'OK' if result.get('success') else 'FAIL'} "
                    f"({result.get('findings_count', 0)} findings)"
                )
            lines.append("")
        return "\n".join(lines)
