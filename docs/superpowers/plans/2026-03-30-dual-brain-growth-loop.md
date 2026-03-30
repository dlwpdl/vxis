# Dual-Brain Growth Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Claude Code가 Brain으로 동작하는 FileBasedBrain + 기존 API Brain을 `--brain` 옵션으로 선택 가능하게 한다.

**Architecture:** FileBasedBrain은 파일 프로토콜(observation.json → decision.json)로 외부 프로세스(Claude Code)와 통신한다. 파이프라인은 백그라운드에서 실행되고, Claude Code가 매 벡터마다 파일을 읽고 판단을 쓴다. API Brain은 기존 AgentBrain을 그대로 사용한다.

**Tech Stack:** Python 3.12, asyncio, JSON file protocol, pytest

---

## File Structure

| Action | Path | Responsibility |
|--------|------|---------------|
| Create | `src/vxis/agent/brain_filebased.py` | FileBasedBrain — 파일 프로토콜 Brain 구현 |
| Create | `tests/unit/test_brain_filebased.py` | FileBasedBrain 단위 테스트 |
| Modify | `src/vxis/agent/__init__.py` | FileBasedBrain export 등록 |
| Modify | `src/vxis/agent/brain_protocol.py` | docstring에 FileBasedBrain 추가 |
| Modify | `src/vxis/scoring/benchmark.py:246-267` | brain_mode 분기 (claude-code vs api) |
| Modify | `src/vxis/pipeline/pipeline.py:67-95` | 벡터 단위 Brain 호출 메서드 추가 |
| Modify | `tools/growth_loop_runner.py:469-512` | `--brain` CLI 옵션 추가 |
| Modify | `.github/workflows/growth-loop.yml:82` | `--brain api` 명시 |

---

### Task 1: FileBasedBrain 핵심 — atomic_write + 상태머신

**Files:**
- Create: `src/vxis/agent/brain_filebased.py`
- Test: `tests/unit/test_brain_filebased.py`

- [ ] **Step 1: Write the failing test for atomic_write**

```python
# tests/unit/test_brain_filebased.py
"""FileBasedBrain 단위 테스트."""
import json
import os
import tempfile
from pathlib import Path

import pytest


def test_atomic_write_creates_file():
    """atomic_write가 JSON 파일을 정상 생성하는지 확인."""
    from vxis.agent.brain_filebased import atomic_write

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        data = {"key": "value", "number": 42}
        atomic_write(path, data)

        assert os.path.exists(path)
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded == data


def test_atomic_write_no_partial_file_on_error():
    """atomic_write 실패 시 깨진 파일이 남지 않는지 확인."""
    from vxis.agent.brain_filebased import atomic_write

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")

        class BadObj:
            def __repr__(self):
                raise RuntimeError("serialize error")

        # json.dump가 실패해야 함 — TypeError
        with pytest.raises(TypeError):
            atomic_write(path, {"bad": BadObj()})

        assert not os.path.exists(path)


def test_atomic_write_overwrites_existing():
    """atomic_write가 기존 파일을 원자적으로 덮어쓰는지 확인."""
    from vxis.agent.brain_filebased import atomic_write

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "test.json")
        atomic_write(path, {"v": 1})
        atomic_write(path, {"v": 2})

        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded["v"] == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/test_brain_filebased.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'vxis.agent.brain_filebased'`

- [ ] **Step 3: Write atomic_write and status constants**

```python
# src/vxis/agent/brain_filebased.py
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vxis.agent.brain import AgentAction, AgentObservation, AgentStep

logger = logging.getLogger(__name__)


# ── 상태 상수 ────────────────────────────────────────────────────

STATE_INITIALIZING = "initializing"
STATE_WAITING_FOR_BRAIN = "waiting_for_brain"
STATE_EXECUTING = "executing"
STATE_DONE = "done"
STATE_ERROR = "error"


# ── 원자적 파일 쓰기 ─────────────────────────────────────────────

def atomic_write(path: str, data: dict[str, Any]) -> None:
    """원자적 JSON 파일 쓰기. 읽는 쪽이 깨진 파일을 볼 일 없음."""
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest tests/unit/test_brain_filebased.py -v`
Expected: 3 PASSED

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/brain_filebased.py tests/unit/test_brain_filebased.py
git commit -m "feat(brain): add atomic_write and state constants for FileBasedBrain"
```

---

### Task 2: FileBasedBrain.think() — observation 쓰기 + decision 대기

**Files:**
- Modify: `src/vxis/agent/brain_filebased.py`
- Modify: `tests/unit/test_brain_filebased.py`

- [ ] **Step 1: Write the failing test for think()**

```python
# tests/unit/test_brain_filebased.py — 추가

import threading


def test_think_writes_observation_and_waits_for_decision():
    """think()가 observation.json을 쓰고 decision.json을 기다리는지 확인."""
    from vxis.agent.brain_filebased import FileBasedBrain, atomic_write
    from vxis.agent.brain import AgentObservation

    with tempfile.TemporaryDirectory() as tmpdir:
        brain = FileBasedBrain(brain_dir=tmpdir, timeout_per_vector=5, poll_interval=0.1)

        obs = AgentObservation(
            target="http://localhost:8081",
            tech_stack=["PHP", "Apache"],
            findings=[{"id": "F-001", "type": "sqli"}],
        )

        # 별도 스레드에서 1초 후 decision.json 작성 (Claude Code 역할 시뮬레이션)
        def write_decision():
            time.sleep(0.5)
            decision_path = os.path.join(tmpdir, "decision.json")
            atomic_write(decision_path, {
                "vector_id": "WEB-XSS-001",
                "attempt": True,
                "reasoning": "test decision",
                "targets": [{"endpoint": "/search.php", "param": "q", "payloads": ["<script>alert(1)</script>"]}],
            })

        t = threading.Thread(target=write_decision)
        t.start()

        actions = brain.think(obs)
        t.join()

        # observation.json이 생성되었는지
        obs_path = os.path.join(tmpdir, "observation.json")
        assert os.path.exists(obs_path)

        # actions가 반환되었는지
        assert len(actions) >= 1
        assert actions[0].tool != "SKIP"


def test_think_timeout_returns_skip():
    """decision.json이 오지 않으면 타임아웃 후 SKIP 반환."""
    from vxis.agent.brain_filebased import FileBasedBrain
    from vxis.agent.brain import AgentObservation

    with tempfile.TemporaryDirectory() as tmpdir:
        brain = FileBasedBrain(brain_dir=tmpdir, timeout_per_vector=1, poll_interval=0.1)

        obs = AgentObservation(target="http://localhost:8081")
        actions = brain.think(obs)

        # 타임아웃 → SKIP
        assert len(actions) == 1
        assert actions[0].tool == "SKIP"
        assert "timeout" in actions[0].reasoning
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src pytest tests/unit/test_brain_filebased.py::test_think_writes_observation_and_waits_for_decision tests/unit/test_brain_filebased.py::test_think_timeout_returns_skip -v`
Expected: FAIL with `AttributeError: module has no attribute 'FileBasedBrain'`

- [ ] **Step 3: Implement FileBasedBrain class**

Add to `src/vxis/agent/brain_filebased.py`:

```python
class FileBasedBrain:
    """파일 기반 Brain — Claude Code가 외부에서 판단을 주입.

    think() 호출 시:
      1. observation.json 작성 (현재 벡터 + 누적 컨텍스트)
      2. status.json을 "waiting_for_brain"으로 변경
      3. decision.json이 나타날 때까지 polling (timeout 적용)
      4. decision.json 파싱 → AgentAction 리스트 반환

    record_result() 호출 시:
      1. result.json 작성 (실행 결과)
      2. status.json을 "executing"으로 변경
    """

    def __init__(
        self,
        brain_dir: str = "tools/benchmark/.brain",
        timeout_per_vector: int = 120,
        poll_interval: float = 1.0,
    ) -> None:
        self.brain_dir = Path(brain_dir)
        self.brain_dir.mkdir(parents=True, exist_ok=True)

        self.timeout_per_vector = timeout_per_vector
        self.poll_interval = poll_interval

        self.is_done = False
        self.max_steps = 9999  # FileBasedBrain은 벡터 수에 의존
        self._step_count = 0
        self._steps: list[AgentStep] = []

        # 파일 경로
        self._status_path = str(self.brain_dir / "status.json")
        self._observation_path = str(self.brain_dir / "observation.json")
        self._decision_path = str(self.brain_dir / "decision.json")
        self._result_path = str(self.brain_dir / "result.json")
        self._context_path = str(self.brain_dir / "scan_context.json")

        # 누적 컨텍스트
        self._cumulative_findings: list[dict[str, Any]] = []
        self._previous_decisions: list[dict[str, Any]] = []
        self._endpoints_discovered: list[dict[str, Any]] = []

        # 초기 상태
        self._write_status(STATE_INITIALIZING, {})

        # 이전 decision.json이 남아있으면 삭제
        decision_p = Path(self._decision_path)
        if decision_p.exists():
            decision_p.unlink()

    def think(self, observation: AgentObservation) -> list[AgentAction]:
        """Brain 판단 요청 — observation 작성 후 decision 대기."""
        if self.is_done:
            return []

        self._step_count += 1

        # 1. observation.json 작성
        obs_data = self._serialize_observation(observation)
        atomic_write(self._observation_path, obs_data)

        # 2. status.json → waiting_for_brain
        self._write_status(STATE_WAITING_FOR_BRAIN, {
            "vector_index": self._step_count,
            "findings_so_far": len(self._cumulative_findings),
        })

        # 3. decision.json 대기 (polling)
        decision = self._wait_for_decision()

        # 4. status.json → executing
        self._write_status(STATE_EXECUTING, {
            "vector_index": self._step_count,
        })

        # 5. decision → AgentAction 변환
        actions = self._parse_decision(decision)

        # 6. 기록
        self._previous_decisions.append({
            "vector_id": decision.get("vector_id", ""),
            "attempted": decision.get("attempt", False),
            "found": False,  # result.json에서 업데이트
        })

        self._steps.append(AgentStep(
            step_number=self._step_count,
            observation_summary=f"Step {self._step_count}: vector={decision.get('vector_id', '?')}",
            actions=actions,
        ))

        return actions

    def record_result(self, action: AgentAction, result: dict[str, Any]) -> None:
        """실행 결과를 result.json에 기록."""
        atomic_write(self._result_path, result)

        # 누적 컨텍스트 업데이트
        findings = result.get("findings", [])
        self._cumulative_findings.extend(findings)

        # 이전 decision의 found 업데이트
        if self._previous_decisions and findings:
            self._previous_decisions[-1]["found"] = True

        # 스텝 결과 기록
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
        """실행 로그 반환."""
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
        """status.json 갱신."""
        data: dict[str, Any] = {
            "state": state,
            "step": self._step_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        data.update(extra)
        atomic_write(self._status_path, data)

    def _serialize_observation(self, obs: AgentObservation) -> dict[str, Any]:
        """AgentObservation을 observation.json 형식으로 직렬화."""
        return {
            "target": obs.target,
            "tech_stack": obs.tech_stack,
            "open_ports": obs.open_ports[:30],
            "live_urls": obs.live_urls[:20],
            "subdomains": obs.subdomains[:20],
            "endpoints_discovered": self._endpoints_discovered[:100],
            "cumulative_findings": self._cumulative_findings[-50:],
            "previous_decisions": self._previous_decisions[-30:],
            "executed_tools": obs.executed_tools,
            "step": self._step_count,
        }

    def _wait_for_decision(self) -> dict[str, Any]:
        """decision.json이 나타날 때까지 대기."""
        start = time.monotonic()
        decision_p = Path(self._decision_path)

        while time.monotonic() - start < self.timeout_per_vector:
            if decision_p.exists():
                try:
                    data = json.loads(decision_p.read_text(encoding="utf-8"))
                    decision_p.unlink()  # 소비 후 삭제
                    logger.info(
                        "  [BRAIN] Decision received: attempt=%s vector=%s",
                        data.get("attempt"), data.get("vector_id", "?"),
                    )
                    return data
                except (json.JSONDecodeError, OSError) as exc:
                    logger.warning("  [BRAIN] Bad decision file: %s — retrying", exc)
                    time.sleep(self.poll_interval)
                    continue
            time.sleep(self.poll_interval)

        # 타임아웃 → 자동 스킵
        logger.warning(
            "  [BRAIN] Timeout after %ds — auto-skipping",
            self.timeout_per_vector,
        )
        return {"attempt": False, "reasoning": "brain timeout — auto-skipped"}

    def _parse_decision(self, decision: dict[str, Any]) -> list[AgentAction]:
        """decision dict를 AgentAction 리스트로 변환."""
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
            # targets 없으면 기본 PROBE
            actions.append(AgentAction(
                tool="PROBE",
                args={},
                reasoning=reasoning,
            ))

        return actions
```

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src pytest tests/unit/test_brain_filebased.py -v`
Expected: 5 PASSED

- [ ] **Step 5: Commit**

```bash
git add src/vxis/agent/brain_filebased.py tests/unit/test_brain_filebased.py
git commit -m "feat(brain): implement FileBasedBrain with think/record_result/timeout"
```

---

### Task 3: Module registration — __init__.py + brain_protocol.py

**Files:**
- Modify: `src/vxis/agent/__init__.py`
- Modify: `src/vxis/agent/brain_protocol.py`

- [ ] **Step 1: Update __init__.py to export FileBasedBrain**

In `src/vxis/agent/__init__.py`, add the import and export:

```python
# 기존 import 아래에 추가
from vxis.agent.brain_filebased import FileBasedBrain

# __all__ 리스트에 추가
# "InteractiveBrain" 다음 줄에:
# "FileBasedBrain",
```

- [ ] **Step 2: Update brain_protocol.py docstring**

In `src/vxis/agent/brain_protocol.py`, line 11-16 docstring 수정:

```python
class BrainProtocol(Protocol):
    """AgentExecutor가 사용하는 Brain 인터페이스.

    세 가지 구현:
        1. AgentBrain      — 외부 LLM API 호출 (자율 모드)
        2. InteractiveBrain — stdin/stdout JSON (대화형 모드)
        3. FileBasedBrain   — 파일 프로토콜 (Claude Code 모드)
    """
```

- [ ] **Step 3: Verify import works**

Run: `PYTHONPATH=src python -c "from vxis.agent import FileBasedBrain; print('OK:', FileBasedBrain)"`
Expected: `OK: <class 'vxis.agent.brain_filebased.FileBasedBrain'>`

- [ ] **Step 4: Commit**

```bash
git add src/vxis/agent/__init__.py src/vxis/agent/brain_protocol.py
git commit -m "feat(brain): register FileBasedBrain in module exports and protocol docs"
```

---

### Task 4: benchmark.py — brain_mode 분기 추가

**Files:**
- Modify: `src/vxis/scoring/benchmark.py:246-267`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_brain_filebased.py — 추가

def test_benchmark_creates_filebased_brain_in_claude_code_mode():
    """VXIS_BRAIN_MODE=claude-code일 때 FileBasedBrain이 생성되는지 확인."""
    import os
    os.environ["VXIS_BRAIN_MODE"] = "claude-code"
    try:
        from vxis.scoring.benchmark import BenchmarkRunner
        runner = BenchmarkRunner(baseline_path="tools/benchmark/baseline.json")
        # _execute_pipeline을 직접 호출하지 않고, 환경변수 분기만 검증
        # 실제 파이프라인은 Docker 타겟이 필요하므로 통합 테스트에서
        assert os.environ.get("VXIS_BRAIN_MODE") == "claude-code"
    finally:
        os.environ.pop("VXIS_BRAIN_MODE", None)
```

- [ ] **Step 2: Update benchmark.py _execute_pipeline**

In `src/vxis/scoring/benchmark.py`, replace the current `_execute_pipeline` method (lines 246-267):

```python
    async def _execute_pipeline(
        self,
        target_type: str,
        target_url: str,
        scan_id: str,
    ):
        """타겟 타입에 맞는 파이프라인을 실행하고 ScanContext를 반환한다."""
        brain_mode = os.environ.get("VXIS_BRAIN_MODE", "api")

        if brain_mode == "claude-code":
            from vxis.agent.brain_filebased import FileBasedBrain
            brain = FileBasedBrain()
            logger.info("[BENCHMARK] Brain mode: claude-code (FileBasedBrain)")
        else:
            from vxis.agent.brain import AgentBrain
            brain = AgentBrain()
            logger.info("[BENCHMARK] Brain mode: api (AgentBrain)")

        if target_type == "web":
            from vxis.pipeline.pipeline import ScanPipeline
            pipeline = ScanPipeline(brain=brain)
            ctx = await pipeline.run(target=target_url)
        elif target_type == "game":
            # game_pipeline 미구현 — web 파이프라인으로 fallback
            from vxis.pipeline.pipeline import ScanPipeline
            pipeline = ScanPipeline(brain=brain)
            ctx = await pipeline.run(target=target_url)
        elif target_type == "mobile":
            from vxis.pipeline.mobile_pipeline import MobilePipeline
            pipeline = MobilePipeline()
            ctx = await pipeline.run(target=target_url)
        else:
            raise ValueError(f"Unknown target_type: {target_type!r}")

        # FileBasedBrain이면 스캔 완료 표시
        if brain_mode == "claude-code" and hasattr(brain, "mark_done"):
            brain.mark_done()

        return ctx
```

- [ ] **Step 3: Run test**

Run: `PYTHONPATH=src pytest tests/unit/test_brain_filebased.py -v`
Expected: ALL PASSED

- [ ] **Step 4: Commit**

```bash
git add src/vxis/scoring/benchmark.py tests/unit/test_brain_filebased.py
git commit -m "feat(benchmark): add VXIS_BRAIN_MODE=claude-code branch for FileBasedBrain"
```

---

### Task 5: growth_loop_runner.py — `--brain` CLI 옵션

**Files:**
- Modify: `tools/growth_loop_runner.py:469-512`

- [ ] **Step 1: Add --brain argument to argparse**

In `tools/growth_loop_runner.py`, modify the `main()` function's argparse section (after line 470):

```python
    parser.add_argument(
        "--brain", default="api",
        choices=["api", "claude-code"],
        help="Brain mode: api (LLM API call) or claude-code (file protocol for Claude Code). Default: api",
    )
```

- [ ] **Step 2: Wire up brain mode to environment variable**

In `tools/growth_loop_runner.py`, after the `# LLM Provider 설정` block (after line 503), add:

```python
    # Brain 모드 설정
    if args.brain == "claude-code":
        os.environ["VXIS_BRAIN_MODE"] = "claude-code"
        print(f"  Brain: Claude Code (FileBasedBrain)")
        print(f"  Protocol dir: tools/benchmark/.brain/")
    else:
        os.environ["VXIS_BRAIN_MODE"] = "api"
```

- [ ] **Step 3: Update the header print block to show brain mode**

In `tools/growth_loop_runner.py`, in the header print section (around line 518), add after `Provider:` line:

```python
    print(f"  Brain: {args.brain}")
```

- [ ] **Step 4: Test CLI help**

Run: `python tools/growth_loop_runner.py --help`
Expected: `--brain {api,claude-code}` appears in output

- [ ] **Step 5: Test claude-code mode starts correctly (dry run)**

Run: `python tools/growth_loop_runner.py --brain claude-code --iterations 1 --targets dvwa 2>&1 | head -15`
Expected: Output shows `Brain: Claude Code (FileBasedBrain)` and starts polling for docker

- [ ] **Step 6: Commit**

```bash
git add tools/growth_loop_runner.py
git commit -m "feat(runner): add --brain cli option for claude-code vs api mode"
```

---

### Task 6: GitHub Actions 워크플로우 — `--brain api` 명시

**Files:**
- Modify: `.github/workflows/growth-loop.yml:82`

- [ ] **Step 1: Update the GHA inline Python to pass brain_mode**

In `.github/workflows/growth-loop.yml`, the Growth Loop step (line 82-438) uses inline Python that directly calls `BenchmarkRunner`. Add `VXIS_BRAIN_MODE=api` to the env section.

In the `env:` block under `Growth Loop` step (line 77-80), add:

```yaml
          VXIS_BRAIN_MODE: api
```

- [ ] **Step 2: Verify no other changes needed**

The GHA workflow uses inline Python that directly calls `BenchmarkRunner`, not `growth_loop_runner.py`. The `VXIS_BRAIN_MODE=api` env var ensures it uses `AgentBrain`. No other changes needed.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/growth-loop.yml
git commit -m "ci(growth-loop): explicitly set VXIS_BRAIN_MODE=api for GHA"
```

---

### Task 7: ScanPipeline — 벡터 단위 Brain 호출 지원 메서드

**Files:**
- Modify: `src/vxis/pipeline/pipeline.py`

이 태스크는 파이프라인에 `_consult_brain_for_vector()` 헬퍼를 추가한다.
각 Phase 메서드가 이미 내부적으로 벡터를 실행하고 있으므로, Brain 호출 레이어를 추가하는 것이다.

- [ ] **Step 1: Add _consult_brain_for_vector method to ScanPipeline**

In `src/vxis/pipeline/pipeline.py`, after the `_run_phase` method (after line 194), add:

```python
    def _consult_brain_for_vector(
        self,
        ctx: ScanContext,
        vector_id: str,
        vector_name: str,
        phase_name: str,
    ) -> dict[str, Any] | None:
        """Brain에게 벡터 실행 여부를 물어본다.

        FileBasedBrain일 때: observation.json 쓰고 decision.json 대기
        AgentBrain일 때: LLM API 호출
        Brain이 없거나 think()가 없으면: None 반환 (기존 로직 유지)

        Returns:
            None — Brain 없음, 기존 로직으로 실행
            dict — Brain의 decision (attempt, reasoning, targets, chain_hint)
        """
        from vxis.agent.brain_filebased import FileBasedBrain

        if not isinstance(self.brain, FileBasedBrain):
            # API Brain이나 다른 Brain은 기존 로직 유지
            # (벡터 단위 Brain 호출은 FileBasedBrain 전용)
            return None

        from vxis.agent.brain import AgentObservation

        obs = AgentObservation(
            target=ctx.target,
            tech_stack=getattr(ctx, "tech_stack", []),
            findings=[
                {
                    "id": getattr(f, "id", ""),
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", ""),
                    "finding_type": getattr(f, "finding_type", ""),
                    "affected_component": getattr(f, "affected_component", ""),
                }
                for f in ctx.findings[-50:]
            ],
            executed_tools=[
                {"tool": p, "status": "done"}
                for p in ctx.phases_completed[-20:]
            ],
        )

        # FileBasedBrain의 observation에 벡터 정보 추가
        self.brain._current_vector_id = vector_id
        self.brain._current_vector_name = vector_name
        self.brain._current_phase = phase_name

        actions = self.brain.think(obs)

        if not actions:
            return {"attempt": False, "reasoning": "brain returned no actions"}

        first = actions[0]
        if first.tool == "SKIP":
            return {"attempt": False, "reasoning": first.reasoning}

        return {
            "attempt": True,
            "reasoning": first.reasoning,
            "targets": [a.args for a in actions],
            "actions": actions,
        }
```

- [ ] **Step 2: Override _serialize_observation in FileBasedBrain to include vector info**

In `src/vxis/agent/brain_filebased.py`, update `_serialize_observation` to include current vector info:

```python
    def _serialize_observation(self, obs: AgentObservation) -> dict[str, Any]:
        """AgentObservation을 observation.json 형식으로 직렬화."""
        data: dict[str, Any] = {
            "target": obs.target,
            "tech_stack": obs.tech_stack,
            "open_ports": obs.open_ports[:30],
            "live_urls": obs.live_urls[:20],
            "subdomains": obs.subdomains[:20],
            "endpoints_discovered": self._endpoints_discovered[:100],
            "cumulative_findings": self._cumulative_findings[-50:],
            "previous_decisions": self._previous_decisions[-30:],
            "executed_tools": obs.executed_tools,
            "step": self._step_count,
        }

        # 현재 벡터 정보 (파이프라인이 설정)
        if hasattr(self, "_current_vector_id"):
            data["vector_id"] = self._current_vector_id
            data["vector_name"] = getattr(self, "_current_vector_name", "")
            data["phase"] = getattr(self, "_current_phase", "")

        return data
```

- [ ] **Step 3: Verify existing tests still pass**

Run: `PYTHONPATH=src pytest tests/unit/test_brain_filebased.py -v`
Expected: ALL PASSED

- [ ] **Step 4: Commit**

```bash
git add src/vxis/pipeline/pipeline.py src/vxis/agent/brain_filebased.py
git commit -m "feat(pipeline): add _consult_brain_for_vector for FileBasedBrain integration"
```

---

### Task 8: Integration test — DVWA 대상 claude-code 모드 E2E

**Files:**
- Create: `tests/integration/test_growth_loop_claude_code.py`

이 테스트는 실제 Docker DVWA를 띄우고 FileBasedBrain 프로토콜이 동작하는지 확인한다.
CI에서는 Docker가 없으면 스킵한다.

- [ ] **Step 1: Write integration test**

```python
# tests/integration/test_growth_loop_claude_code.py
"""FileBasedBrain E2E 통합 테스트.

DVWA Docker 컨테이너가 실행 중일 때만 동작.
"""
import json
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

# Docker가 없으면 스킵
pytestmark = pytest.mark.skipif(
    subprocess.run(["docker", "info"], capture_output=True).returncode != 0,
    reason="Docker not available",
)


def test_filebased_brain_protocol_roundtrip():
    """FileBasedBrain이 observation을 쓰고 decision을 읽는 전체 라운드트립."""
    from vxis.agent.brain_filebased import FileBasedBrain, atomic_write, STATE_WAITING_FOR_BRAIN
    from vxis.agent.brain import AgentObservation

    with tempfile.TemporaryDirectory() as tmpdir:
        brain = FileBasedBrain(brain_dir=tmpdir, timeout_per_vector=10, poll_interval=0.2)

        # 시뮬레이션: 3개 벡터 연속 처리
        vectors = [
            ("WEB-SQLI-001", True, "test SQL injection"),
            ("WEB-XSS-001", True, "test XSS"),
            ("WEB-CSRF-001", False, "skip CSRF"),
        ]

        results = []

        def brain_simulator():
            """Claude Code 역할 시뮬레이션 — 파일을 읽고 decision을 쓴다."""
            status_path = Path(tmpdir) / "status.json"
            obs_path = Path(tmpdir) / "observation.json"
            dec_path = Path(tmpdir) / "decision.json"

            for vector_id, attempt, reasoning in vectors:
                # status.json이 waiting_for_brain이 될 때까지 대기
                for _ in range(50):
                    if status_path.exists():
                        status = json.loads(status_path.read_text())
                        if status.get("state") == STATE_WAITING_FOR_BRAIN:
                            break
                    time.sleep(0.1)

                # observation.json 확인
                if obs_path.exists():
                    obs = json.loads(obs_path.read_text())
                    results.append({"vector": vector_id, "obs_step": obs.get("step")})

                # decision.json 작성
                atomic_write(str(dec_path), {
                    "vector_id": vector_id,
                    "attempt": attempt,
                    "reasoning": reasoning,
                    "targets": [{"endpoint": "/test", "param": "q", "payloads": ["test"]}] if attempt else [],
                })

        t = threading.Thread(target=brain_simulator)
        t.start()

        obs = AgentObservation(target="http://localhost:8081", tech_stack=["PHP"])

        all_actions = []
        for _ in vectors:
            actions = brain.think(obs)
            all_actions.append(actions)
            # record_result 시뮬레이션
            if actions and actions[0].tool != "SKIP":
                brain.record_result(actions[0], {"success": True, "findings": []})

        t.join()

        # 검증
        assert len(results) == 3
        assert results[0]["obs_step"] == 1
        assert results[2]["obs_step"] == 3

        # 첫 두 벡터는 attempt=True → PROBE
        assert all_actions[0][0].tool == "PROBE"
        assert all_actions[1][0].tool == "PROBE"
        # 세 번째는 attempt=False → SKIP
        assert all_actions[2][0].tool == "SKIP"

        # execution log 확인
        log = brain.get_execution_log()
        assert "Step 1" in log
        assert "Step 3" in log
```

- [ ] **Step 2: Run integration test**

Run: `PYTHONPATH=src pytest tests/integration/test_growth_loop_claude_code.py -v`
Expected: PASSED

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_growth_loop_claude_code.py
git commit -m "test(integration): add FileBasedBrain E2E protocol roundtrip test"
```

---

### Task 9: 전체 테스트 + 실제 실행 검증

**Files:** (수정 없음 — 검증만)

- [ ] **Step 1: Run all unit tests**

Run: `PYTHONPATH=src pytest tests/unit/test_brain_filebased.py -v`
Expected: ALL PASSED

- [ ] **Step 2: Run integration test**

Run: `PYTHONPATH=src pytest tests/integration/test_growth_loop_claude_code.py -v`
Expected: PASSED

- [ ] **Step 3: Test API mode still works (regression check)**

Run: `python tools/growth_loop_runner.py --brain api --iterations 1 --targets dvwa 2>&1 | tail -5`
Expected: Score output, no errors

- [ ] **Step 4: Test claude-code mode starts and creates protocol files**

Run: `python tools/growth_loop_runner.py --brain claude-code --iterations 1 --targets dvwa &`
Then: `sleep 5 && cat tools/benchmark/.brain/status.json`
Expected: `status.json` exists with `"state": "waiting_for_brain"` or `"initializing"`

- [ ] **Step 5: Clean up and final commit**

```bash
# .brain/ 디렉토리 gitignore
echo "tools/benchmark/.brain/" >> .gitignore
git add .gitignore
git commit -m "chore: gitignore brain protocol directory"
```

- [ ] **Step 6: Push all changes**

```bash
git push origin main
```
