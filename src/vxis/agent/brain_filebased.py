"""VXIS FileBasedBrain — Claude Code가 파일 프로토콜로 Brain 역할을 수행.

Protocol:
    파이프라인 → observation.json 작성 + status.json="waiting_for_brain"
    Claude Code → observation.json 읽고 → decision.json 작성
    파이프라인 → decision.json 읽고 실행 → result.json 작성
    반복...
    파이프라인 → status.json="done"

Usage:
    # 파이프라인 쪽 (백그라운드 프로세스)
    brain = FileBasedBrain(brain_dir="tools/benchmark/.brain")
    pipeline = ScanPipeline(brain=brain)
    await pipeline.run(target="http://localhost:8081")

    # Claude Code 쪽 (메인 프로세스)
    # Read(status.json) → Write(decision.json) 루프
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vxis.agent.brain import (
    AgentAction,
    AgentObservation,
    AgentStep,
    _increment_brain_decision_count,
)

logger = logging.getLogger(__name__)


# ── 상태 상수 ────────────────────────────────────────────────────

STATE_INITIALIZING = "initializing"
STATE_WAITING_FOR_BRAIN = "waiting_for_brain"
STATE_EXECUTING = "executing"
STATE_DONE = "done"
STATE_ERROR = "error"


# ── 원자적 파일 쓰기 ─────────────────────────────────────────────


def atomic_write(path: str, data: dict[str, Any]) -> None:
    """원자적 JSON 파일 쓰기. 읽는 쪽이 깨진 파일을 볼 일 없음.

    임시 파일에 먼저 쓴 뒤 os.replace()로 원자적 교체.
    실패 시 임시 파일을 정리하여 깨진 파일이 남지 않도록 보장.
    """
    dir_path = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp_path, path)  # atomic on POSIX
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ── FileBasedBrain ──────────────────────────────────────────────


class FileBasedBrain:
    """파일 기반 Brain — Claude Code가 외부에서 판단을 주입."""

    def __init__(
        self,
        brain_dir: str = "tools/benchmark/.brain",
        timeout_per_vector: int = 120,
        poll_interval: float = 1.0,
        scan_id: str = "",
    ) -> None:
        # scan_id가 있으면 scan별 서브디렉토리 사용 — 동시 파이프라인 충돌 방지
        base = Path(brain_dir)
        self.brain_dir = (base / scan_id) if scan_id else base
        self.brain_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_per_vector = timeout_per_vector
        self.poll_interval = poll_interval
        self.is_done = False
        self.max_steps = 9999
        self._step_count = 0
        self._steps: list[AgentStep] = []
        # File paths
        self._status_path = str(self.brain_dir / "status.json")
        self._observation_path = str(self.brain_dir / "observation.json")
        self._decision_path = str(self.brain_dir / "decision.json")
        self._result_path = str(self.brain_dir / "result.json")
        self._context_path = str(self.brain_dir / "scan_context.json")
        self._lock_path = str(self.brain_dir / ".write.lock")   # 동시 쓰기 방지 락
        # Cumulative context
        self._cumulative_findings: list[dict[str, Any]] = []
        self._previous_decisions: list[dict[str, Any]] = []
        self._endpoints_discovered: list[dict[str, Any]] = []
        # Init status
        self._write_status(STATE_INITIALIZING, {})
        # Clean up stale decision and lock
        decision_p = Path(self._decision_path)
        if decision_p.exists():
            decision_p.unlink()
        lock_p = Path(self._lock_path)
        if lock_p.exists() and (time.time() - lock_p.stat().st_mtime) > 60:
            lock_p.unlink()  # 60초 이상 된 stale lock 제거

    def think(self, observation: AgentObservation) -> list[AgentAction]:
        """Observation을 파일에 쓰고 외부 decision을 기다린다."""
        if self.is_done:
            return []
        self._step_count += 1
        _increment_brain_decision_count()
        obs_data = self._serialize_observation(observation)
        # 락 획득 — 동시 파이프라인 인스턴스가 같은 파일을 덮어쓰지 않도록
        self._acquire_lock()
        try:
            atomic_write(self._observation_path, obs_data)
            self._write_status(STATE_WAITING_FOR_BRAIN, {
                "vector_index": self._step_count,
                "findings_so_far": len(self._cumulative_findings),
            })
        finally:
            self._release_lock()
        decision = self._wait_for_decision()
        self._write_status(STATE_EXECUTING, {"vector_index": self._step_count})
        actions = self._parse_decision(decision)
        self._previous_decisions.append({
            "vector_id": decision.get("vector_id", ""),
            "attempted": decision.get("attempt", False),
            "found": False,
        })
        self._steps.append(AgentStep(
            step_number=self._step_count,
            observation_summary=f"Step {self._step_count}: vector={decision.get('vector_id', '?')}",
            actions=actions,
        ))
        return actions

    def record_result(self, action: AgentAction, result: dict[str, Any]) -> None:
        """실행 결과를 파일에 기록하고 누적 컨텍스트를 갱신."""
        atomic_write(self._result_path, result)
        findings = result.get("findings", [])
        self._cumulative_findings.extend(findings)
        if self._previous_decisions and findings:
            self._previous_decisions[-1]["found"] = True
        if self._steps:
            self._steps[-1].results.append({
                "tool": action.tool,
                "result_summary": str(result.get("summary", ""))[:500],
                "findings_count": len(findings),
                "success": result.get("success", True),
            })

    def mark_done(self) -> None:
        """스캔 완료 표시."""
        self.is_done = True
        self._write_status(STATE_DONE, {
            "total_vectors": self._step_count,
            "total_findings": len(self._cumulative_findings),
        })

    def get_execution_log(self) -> str:
        """마크다운 형식의 실행 로그 반환."""
        lines = ["## AI Agent Execution Log (FileBasedBrain)\n"]
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

    # ── Private ──────────────────────────────────────────────────

    def _write_status(self, state: str, extra: dict[str, Any]) -> None:
        data: dict[str, Any] = {
            "state": state,
            "step": self._step_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        data.update(extra)
        atomic_write(self._status_path, data)

    def _acquire_lock(self, timeout: float = 30.0) -> None:
        """파일 락 획득 — 동시 파이프라인 인스턴스 간 observation 충돌 방지."""
        lock_p = Path(self._lock_path)
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            try:
                # O_CREAT|O_EXCL — 원자적 생성, 이미 존재하면 FileExistsError
                fd = os.open(str(lock_p), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, str(os.getpid()).encode())
                os.close(fd)
                return
            except FileExistsError:
                # stale lock 확인 (30초 초과)
                try:
                    if time.time() - lock_p.stat().st_mtime > 30:
                        lock_p.unlink(missing_ok=True)
                except OSError:
                    pass
                time.sleep(0.2)
        # 타임아웃 — 락 없이 진행 (데이터 경합보다 deadlock이 더 나쁨)
        logger.warning("  [BRAIN] Lock acquisition timeout — proceeding without lock")

    def _release_lock(self) -> None:
        """파일 락 해제."""
        try:
            Path(self._lock_path).unlink(missing_ok=True)
        except OSError:
            pass

    def _serialize_observation(self, obs: AgentObservation) -> dict[str, Any]:
        # 전체 이력에서 compact summary 생성 — 30개 절삭 보완
        all_attempted = [p["vector_id"] for p in self._previous_decisions if p.get("attempted") and p.get("vector_id")]
        all_found     = [p["vector_id"] for p in self._previous_decisions if p.get("found")     and p.get("vector_id")]
        all_skipped   = [p["vector_id"] for p in self._previous_decisions if not p.get("attempted") and p.get("vector_id")]
        data: dict[str, Any] = {
            "target": obs.target,
            "tech_stack": obs.tech_stack,
            "open_ports": obs.open_ports[:30],
            "live_urls": obs.live_urls[:20],
            "subdomains": obs.subdomains[:20],
            "endpoints_discovered": self._endpoints_discovered[:100],
            "cumulative_findings": self._cumulative_findings[-50:],
            "previous_decisions": self._previous_decisions[-50:],   # 30→50
            "all_vectors_summary": {                                 # 전체 이력 compact
                "attempted": list(dict.fromkeys(all_attempted)),    # 중복 제거
                "found":     list(dict.fromkeys(all_found)),
                "skipped":   list(dict.fromkeys(all_skipped)),
                "total_steps": self._step_count,
            },
            "executed_tools": obs.executed_tools,
            "step": self._step_count,
        }
        if hasattr(self, "_current_vector_id"):
            data["vector_id"] = self._current_vector_id
            data["vector_name"] = getattr(self, "_current_vector_name", "")
            data["phase"] = getattr(self, "_current_phase", "")
        return data

    def _wait_for_decision(self) -> dict[str, Any]:
        start = time.monotonic()
        decision_p = Path(self._decision_path)
        while time.monotonic() - start < self.timeout_per_vector:
            if decision_p.exists():
                try:
                    data = json.loads(decision_p.read_text(encoding="utf-8"))
                    decision_p.unlink()
                    logger.info(
                        "  [BRAIN] Decision received: attempt=%s vector=%s",
                        data.get("attempt"),
                        data.get("vector_id", "?"),
                    )
                    return data
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("  [BRAIN] Bad decision file: %s — retrying", exc)
                    time.sleep(self.poll_interval)
                    continue
            time.sleep(self.poll_interval)
        logger.warning("  [BRAIN] Timeout after %ds — auto-skipping", self.timeout_per_vector)
        return {"attempt": False, "reasoning": "brain timeout — auto-skipped"}

    def _parse_decision(self, decision: dict[str, Any]) -> list[AgentAction]:
        if not decision.get("attempt", False):
            return [AgentAction(
                tool="SKIP",
                reasoning=decision.get("reasoning", "brain decided to skip"),
            )]
        actions: list[AgentAction] = []
        targets = decision.get("targets", [])
        reasoning = decision.get("reasoning", "")
        chain_hint = decision.get("chain_hint", "")
        if targets:
            for target in targets:
                actions.append(AgentAction(
                    tool="PROBE",
                    args={
                        "endpoint": target.get("endpoint", ""),
                        "method": target.get("method", "GET"),
                        "param": target.get("param", ""),
                        "payloads": target.get("payloads", []),
                        "note": target.get("note", ""),
                    },
                    reasoning=f"{reasoning} | chain: {chain_hint}" if chain_hint else reasoning,
                ))
        else:
            actions.append(AgentAction(tool="PROBE", args={}, reasoning=reasoning))
        return actions
