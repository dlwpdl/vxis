# Dual-Brain Growth Loop Design

**Date**: 2026-03-30
**Status**: Approved
**Author**: Eliot + Claude Code

## Problem

현재 growth loop에는 두 가지 문제가 있다:

1. `benchmark.py._execute_pipeline`이 파이프라인 생성자 시그니처를 잘못 호출 (이미 수정됨)
2. Claude Code를 Brain으로 사용하는 경로가 구현되지 않음 — 구독 중인 Claude Code를 활용하면 추가 API 비용 없이 Brain 역할 가능

## Design Goals

- **로컬 (Claude Code Brain)**: 구독료만으로 Brain 역할 수행, 추가 비용 0원
- **로컬 (API Brain)**: 모델 선택 가능 (Together/Anthropic/Gemini 등)
- **GitHub Actions (API Brain)**: 자동 성장루프, LLM API 호출
- **벡터 단위 판단**: Brain이 모든 개별 벡터에 대해 시도 여부/페이로드/체이닝 결정
- **Phase 순서 고정**: 점수 비교 일관성을 위해 Phase 순서는 ScanPipeline이 관리

## Architecture

### Brain 구현체 3종

```
BrainProtocol (인터페이스)
  ├── AgentBrain        — LLM API 호출 (GHA/로컬 API 모드)
  ├── InteractiveBrain  — stdin/stdout (기존, 유지)
  └── FileBasedBrain    — 파일 프로토콜 (신규, Claude Code 모드)
```

### 실행 모드

| CLI 플래그 | Brain | 용도 |
|-----------|-------|------|
| `--brain claude-code` | FileBasedBrain | 로컬에서 Claude Code가 판단 |
| `--brain api --provider together` | AgentBrain | 로컬/GHA에서 Together AI |
| `--brain api --provider anthropic` | AgentBrain | 로컬/GHA에서 Claude API |
| `--brain api` (기본) | AgentBrain | provider 자동 감지 |

### 실행 흐름: Claude Code Brain

```
Claude Code 세션:
  1. Bash(run_in_background=True):
     "python tools/growth_loop_runner.py --brain claude-code --targets dvwa"
     → 파이프라인이 FileBasedBrain으로 시작, 백그라운드 실행

  2. Claude Code가 Brain 루프 진입:
     loop:
       Read(status.json)
       if state == "waiting_for_brain":
         Read(observation.json)     ← 현재 벡터 + 누적 컨텍스트
         [시니어 펜테스터로서 판단]
         Write(decision.json)       ← 시도 여부, 페이로드, 체이닝
       elif state == "done":
         Read(results.json)         ← 최종 점수
         break
       sleep(2)

  3. 결과 분석 → 약점 파악 → 전략 조정 → 다음 iteration
```

### 실행 흐름: API Brain (기존 + 개선)

```
로컬 또는 GitHub Actions:
  python tools/growth_loop_runner.py --brain api --provider together --iterations 5

  → AgentBrain이 매 벡터마다 LLM API 호출
  → 결과 측정 → 약점 분석 → 전략 조정 → 반복
```

## File-Based Protocol

### 디렉토리 구조

```
tools/benchmark/.brain/
  ├── status.json        ← 상태머신 신호
  ├── observation.json   ← 파이프라인 → Brain
  ├── decision.json      ← Brain → 파이프라인
  ├── result.json        ← 실행 결과
  └── scan_context.json  ← 누적 컨텍스트 (전체 findings)
```

### 상태머신 (status.json)

```
initializing → waiting_for_brain → executing → waiting_for_brain → ... → done
                                                                    └→ error
```

```json
{
  "state": "waiting_for_brain",
  "phase": "Phase 4: Client-Side Injection",
  "vector_id": "WEB-XSS-001",
  "vector_index": 12,
  "total_vectors": 87,
  "elapsed_seconds": 145,
  "findings_so_far": 3
}
```

### observation.json

파이프라인이 매 벡터마다 작성. Brain이 판단에 필요한 모든 정보를 포함.

```json
{
  "phase": "Phase 4: Client-Side Injection",
  "phase_index": 4,
  "total_phases": 14,
  "vector_id": "WEB-XSS-001",
  "vector_name": "Reflected XSS|||반사형 XSS",
  "vector_description": "URL 파라미터가 응답에 반사되는 엔드포인트 탐지 및 XSS 페이로드 삽입",
  "target": "http://localhost:8081",
  "tech_stack": ["PHP 7.4", "Apache 2.4", "MySQL 5.7"],
  "endpoints_discovered": [
    {"path": "/login.php", "method": "POST", "params": ["username", "password"]},
    {"path": "/search.php", "method": "GET", "params": ["q"]},
    {"path": "/guestbook.php", "method": "POST", "params": ["name", "comment"]}
  ],
  "cumulative_findings": [
    {
      "id": "F-001",
      "vector_id": "WEB-SQLI-001",
      "type": "sql_injection",
      "endpoint": "/login.php",
      "param": "username",
      "severity": "critical",
      "evidence": "' OR 1=1 -- triggered 302 redirect to /admin/"
    }
  ],
  "previous_decisions": [
    {"vector_id": "WEB-SQLI-001", "attempted": true, "found": true},
    {"vector_id": "WEB-SQLI-002", "attempted": true, "found": false}
  ]
}
```

### decision.json

Brain(Claude Code)이 작성. 벡터 실행 방법을 지시.

```json
{
  "vector_id": "WEB-XSS-001",
  "attempt": true,
  "reasoning": "search.php의 q 파라미터가 GET으로 반사될 가능성 높음. guestbook.php의 comment는 저장형 XSS 후보이므로 WEB-XSS-002에서 다룰 것. login.php는 이미 SQLi 발견됐으므로 XSS 체이닝 시도.",
  "targets": [
    {
      "endpoint": "/search.php",
      "method": "GET",
      "param": "q",
      "payloads": [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "javascript:alert(1)//",
        "<details open ontoggle=alert(1)>"
      ]
    },
    {
      "endpoint": "/login.php",
      "method": "POST",
      "param": "username",
      "payloads": [
        "admin<script>alert(1)</script>",
        "' onmouseover=alert(1) x='"
      ],
      "note": "SQLi 취약점이 있으니 에러 페이지에서 반사 확인"
    }
  ],
  "chain_hint": "F-001(SQLi)과 체이닝: XSS로 세션 탈취 → SQLi로 권한 상승 시나리오"
}
```

벡터를 건너뛸 때:

```json
{
  "vector_id": "WEB-CSRF-001",
  "attempt": false,
  "reasoning": "이 앱은 CSRF 토큰이 없고 세션 기반 인증도 미약함. 하지만 현재 발견된 SQLi와 XSS가 더 높은 우선순위이므로 나중에 체이닝 시도."
}
```

### result.json

파이프라인이 벡터 실행 후 작성. Brain이 다음 판단에 참고.

```json
{
  "vector_id": "WEB-XSS-001",
  "success": true,
  "findings": [
    {
      "id": "F-003",
      "endpoint": "/search.php",
      "param": "q",
      "payload": "<img src=x onerror=alert(1)>",
      "evidence": "Response contains unescaped payload in HTML body",
      "severity": "high"
    }
  ],
  "attempted_payloads": 5,
  "successful_payloads": 2,
  "response_snippets": [
    {"endpoint": "/search.php", "status": 200, "body_preview": "...Results for: <img src=x onerror=alert(1)>..."}
  ]
}
```

### 파일 원자성

모든 파일 쓰기는 `.tmp` → `rename` 패턴:

```python
import json, os, tempfile

def atomic_write(path: str, data: dict) -> None:
    """원자적 JSON 파일 쓰기. 읽는 쪽이 깨진 파일을 볼 일 없음."""
    dir_path = os.path.dirname(path)
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)  # atomic on POSIX
    except Exception:
        os.unlink(tmp_path)
        raise
```

### 타임아웃

벡터당 기본 120초 타임아웃. Brain이 응답하지 않으면:

```python
# FileBasedBrain 내부
if elapsed > timeout_seconds:
    auto_decision = {
        "vector_id": current_vector_id,
        "attempt": false,
        "reasoning": "brain timeout — auto-skipped"
    }
    atomic_write(decision_path, auto_decision)
```

### 세션 재개

대화가 끊겨도 파일이 남아있으므로 새 Claude Code 세션에서:

```
1. Read(status.json) → "waiting_for_brain", vector_id: "WEB-XSS-003"
2. Read(scan_context.json) → 지금까지의 모든 findings
3. 이어서 Brain 루프 진입
```

## FileBasedBrain 클래스 설계

### 위치

`src/vxis/agent/brain_filebased.py`

### 인터페이스

BrainProtocol과 동일한 `think()` / `record_result()` 메서드 구현.
내부적으로 파일 I/O + polling.

```python
class FileBasedBrain:
    """파일 기반 Brain — Claude Code가 외부에서 판단을 주입.

    think() 호출 시:
      1. observation.json + scan_context.json 작성
      2. status.json을 "waiting_for_brain"으로 변경
      3. decision.json이 나타날 때까지 polling (timeout 적용)
      4. decision.json 파싱 → AgentAction 리스트 반환
    """

    def __init__(
        self,
        brain_dir: str = "tools/benchmark/.brain",
        timeout_per_vector: int = 120,
        poll_interval: float = 1.0,
    ) -> None: ...

    def think(self, observation: AgentObservation) -> list[AgentAction]: ...
    def record_result(self, action: AgentAction, result: dict) -> None: ...
    def get_execution_log(self) -> str: ...
```

### Polling 로직

```python
def _wait_for_decision(self) -> dict:
    """decision.json이 나타날 때까지 대기."""
    start = time.monotonic()
    while time.monotonic() - start < self.timeout_per_vector:
        if self.decision_path.exists():
            data = json.loads(self.decision_path.read_text())
            self.decision_path.unlink()  # 소비 후 삭제
            return data
        time.sleep(self.poll_interval)

    # 타임아웃 → 자동 스킵
    return {"attempt": False, "reasoning": "brain timeout"}
```

## benchmark.py 수정

### _execute_pipeline 변경

```python
async def _execute_pipeline(self, target_type, target_url, scan_id):
    brain_mode = os.environ.get("VXIS_BRAIN_MODE", "api")

    if brain_mode == "claude-code":
        from vxis.agent.brain_filebased import FileBasedBrain
        brain = FileBasedBrain()
    else:
        from vxis.agent.brain import AgentBrain
        brain = AgentBrain()

    if target_type == "web":
        from vxis.pipeline.pipeline import ScanPipeline
        pipeline = ScanPipeline(brain=brain)
        ctx = await pipeline.run(target=target_url)
    elif target_type == "mobile":
        from vxis.pipeline.mobile_pipeline import MobilePipeline
        pipeline = MobilePipeline()
        ctx = await pipeline.run(target=target_url)
    else:
        raise ValueError(f"Unknown target_type: {target_type!r}")

    return ctx
```

## growth_loop_runner.py 수정

### CLI 인터페이스 변경

```
# Claude Code가 Brain
python tools/growth_loop_runner.py --brain claude-code --targets dvwa

# API가 Brain (기존 호환)
python tools/growth_loop_runner.py --brain api --provider together --targets dvwa

# 기본값 = api
python tools/growth_loop_runner.py --targets dvwa
```

### --brain claude-code 동작

```python
if args.brain == "claude-code":
    os.environ["VXIS_BRAIN_MODE"] = "claude-code"
    # 파이프라인이 FileBasedBrain으로 시작됨
    # Claude Code가 외부에서 .brain/ 디렉토리를 통해 판단 주입
```

## ScanPipeline 수정 — 벡터 단위 Brain 호출

### 현재 구조

각 Phase 메서드가 벡터를 내부적으로 실행. Brain 호출 없음.

### 변경

각 벡터 실행 전에 `brain.think(observation)` 호출:

```python
async def _execute_vector(self, ctx, vector_id, vector_name, phase_name):
    """벡터 실행 전 Brain에게 판단 요청."""
    observation = self._build_observation(ctx, vector_id, vector_name, phase_name)
    actions = self.brain.think(observation)

    if not actions or actions[0].tool == "SKIP":
        ctx.score_tracker.record_vector_skip(vector_id, actions[0].reasoning if actions else "brain skip")
        return

    # Brain이 결정한 대로 실행
    for action in actions:
        result = await self._execute_action(ctx, action)
        self.brain.record_result(action, result)
```

이 메서드를 각 Phase에서 벡터별로 호출하도록 리팩터링.

## GitHub Actions 워크플로우

기존 `growth-loop.yml` 변경 최소화:

```yaml
# 변경 전
- run: python tools/growth_loop_runner.py --provider together

# 변경 후
- run: python tools/growth_loop_runner.py --brain api --provider together
```

`--provider` 만 쓰면 `--brain api`가 기본값이므로 기존 호환성 유지.

## 성장루프 흐름 (Claude Code Brain)

```
Iteration 1:
  Claude Code: "python ... --brain claude-code" (background)
  Claude Code: Brain 루프 → 87 벡터 판단 → 점수 580
  분석: 체인 지능 0%, 공격 깊이 30%

Iteration 2:
  Claude Code: 이전 결과 참고하여 체이닝 전략 강화
  Claude Code: Brain 루프 → SQLi→XSS→세션탈취 체이닝 성공 → 점수 720
  분석: 체인 지능 40%로 상승

Iteration 3:
  Claude Code: 공격 깊이 집중, 권한 상승 시도
  ...
```

Claude Code는 대화 컨텍스트를 유지하므로 iteration 간 학습이 자연스럽게 일어남.
API Brain은 매 iteration이 독립적이라 이 이점이 없음 — Claude Code Brain의 고유 강점.

## Implementation Plan (요약)

1. `src/vxis/agent/brain_filebased.py` — FileBasedBrain 구현
2. `src/vxis/agent/brain_protocol.py` — Protocol에 FileBasedBrain 등록
3. `src/vxis/scoring/benchmark.py` — brain_mode 분기 추가
4. `src/vxis/pipeline/pipeline.py` — 벡터 단위 Brain 호출 리팩터링
5. `tools/growth_loop_runner.py` — `--brain` 옵션 추가, claude-code 모드
6. `.github/workflows/growth-loop.yml` — `--brain api` 명시
7. 테스트: DVWA 대상 claude-code 모드 실행
