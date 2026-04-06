# Pipeline Phase Sync + MCP Progress + Bug Fixes

> **Date:** 2026-04-06
> **Session:** Claude Code general-session-ZouUQ
> **Branch:** `claude/general-session-ZouUQ`

**Goal:** 파이프라인 Phase 구조를 실제 코드와 완전 동기화하고, claude.ai/Claude Code 양쪽에서 실시간 스캔 피드백을 제공하며, 발견된 critical 버그 3건을 수정한다.

---

## Completed Tasks

### 1. Phase 구조 동기화 (GH Actions 분리)

- [x] GH Actions 워크플로우 9개 전수 조사
- [x] Phase 9 (CVE Watch) 파이프라인에서 제거 → `cve-watch.yml` 매시간 담당
- [x] Phase 14 (Forecast) 파이프라인에서 제거 → `domain-intel.yml` 매일 담당
- [x] Phase 10, 16, 17, 19 dead method 구현 삭제
- [x] 최종 14 active phases 확정:
  ```
  Stage 1 — Foundation:     P0 Config → P1 Director
  Stage 2 — Recon:          P4 CPR → P15 Digital Twin → P13 Biometrics
  Stage 3 — Intelligence:   P2 Agents → P3 Hypothesis
  Stage 4 — Exploitation:   P5 Special → P7 Hardware
  Stage 5 — Chain Analysis: P8 Synthesis → P11 Mutation
  Stage 6 — Deferred Actions (승인 후 실행)
  Stage 7 — Report:         P6 NCC Style
  Stage 8 — Learning:       P12 Evolution → P18 Collective KB
  ```

### 2. 하드코딩 "19/20 Phase" 전수 제거

- [x] `pipeline.py` — docstring, log, methodology 문구 5곳
- [x] `pipeline/__init__.py` — docstring
- [x] `mobile_pipeline.py` — docstring, log, methodology 6곳
- [x] `game_pipeline.py` — docstring, log 4곳
- [x] `CLAUDE.md` — Phase 구조 + GH Actions 역할 명시
- [x] `docs/SCORING.md` — "19-Phase" 참조
- [x] `docs/superpowers/specs/2026-03-30-dual-brain-growth-loop-design.md` — phase count

### 3. MCP Progress Notification 구현

- [x] `_emit_progress()` — MCP `notifications/progress` JSON-RPC notification 전송
- [x] `MCPProgressEmitter` 클래스 — ScanEventBus 이벤트 → MCP progress 변환
  - Phase 시작/완료 추적
  - Finding 실시간 발견 알림 (severity별)
  - Plugin 상태 (started/completed/failed)
  - 전체 진행률 (N/total)
- [x] `vxis_scan` 핸들러에 progress emitter 연결
- [x] `vxis_agent_scan` 핸들러에 progress emitter 연결
- [x] MCP initialize 응답에 `notifications.progress` capability 추가

### 4. Critical 버그 수정 3건

- [x] **Phase 2**: `get_agent_registry()` 존재하지 않는 함수 import
  - 수정: `from vxis.agent.registry import _REGISTRY, list_agents`
- [x] **Phase 18**: `KnowledgeStore.record_finding()` 메서드 없음 → 학습 완전 무효
  - 수정: Finding → ExecutionRecord 변환 메서드 추가 (severity → effectiveness 매핑)
- [x] **Phase 12**: gap 분석 결과를 버림 → 자가 진화 무효
  - 수정: `ctx.coverage_gaps`에 저장 + Knowledge Store에 gap 기록

### 5. 자동 동기화 CI 체크

- [x] `scripts/check_phase_sync.py` 생성
  - pipeline.py의 `_run_phase()` 호출 자동 추출
  - CLAUDE.md Phase 목록과 교차 검증
  - docstring phase count 숫자 검증
  - 불일치 시 exit code 1
- [x] `.github/workflows/lint.yml`에 step 추가 → PR마다 자동 검증

---

## 전체 파이프라인 감사 결과 (2026-04-06)

### Phase별 상태

| Phase | 이름 | 상태 | Brain 사용 | 비고 |
|-------|------|------|-----------|------|
| P0 | Foundation | Stub | 래퍼 경유 | 초기화만 |
| P1 | Director | Stub | 래퍼 경유 | ChainReasoner init |
| P4 | CPR | **핵심** | 래퍼 경유 | 실제 스캔의 90% — Hands/Eyes/X-Ray |
| P15 | Digital Twin | Real | 래퍼 경유 | 사전 시뮬레이션 |
| P13 | Biometrics | Real | 래퍼 경유 | OSINT 분석 |
| P2 | Agents | Real | 래퍼 경유 | ~~import 깨짐~~ → 수정 완료 |
| P3 | Hypothesis | Real | 래퍼 경유 | KnowledgeStore 패턴 매칭 |
| P5 | Special | Stub | 래퍼 경유 | Web에선 N/A (IoT/VoIP/Web3) |
| P7 | Hardware | Stub | 래퍼 경유 | Web에선 N/A (DMA/SS7) |
| P8 | Synthesis | Real | 래퍼 경유 | CrossProtocol 체이닝 |
| P11 | Mutation | Real | 래퍼 경유 | 대체 공격 경로 |
| P6 | Report | **Brain** | **직접 호출** | 유일한 직접 Brain 사용 (enrichment) |
| P12 | Evolution | Real | 래퍼 경유 | ~~결과 버림~~ → KB 저장으로 수정 |
| P18 | Collective | Real | 래퍼 경유 | ~~method 없음~~ → 추가 완료 |

### Brain-First 아키텍처 준수

`_run_phase` 래퍼가 **모든 14개 Phase 전에** 자동으로:
1. `_consult_brain_for_phase_vectors()` → Brain이 벡터별 전략/payload 결정
2. Phase 메서드 실행
3. `_execute_brain_decisions()` → Brain 결정에 따라 Hands로 공격 실행
4. `_build_chains_and_mark_tp()` → 체인 구축 + TP 마킹

### GH Actions 역할 분리

| 워크플로우 | 스케줄 | 역할 | 대체된 Phase |
|-----------|--------|------|-------------|
| `cve-watch.yml` | 매시간 | CVE 모니터링 | Phase 9 |
| `domain-intel.yml` | 매일/주/월 | Forecast + Industry Intel | Phase 14, 16 |
| `upstream-watch.yml` | 매주 | 공급망 모니터링 | — |
| `growth-loop.yml` | 매주 + push | 자율 코드 개선 벤치마크 | — (Phase 12와 별도 맥락) |
| `action-bridge.yml` | 매일 | Intel → GitHub Issues 변환 | — |

### Growth Loop: 코드 내 vs GH Actions (별도 맥락)

| | Phase 12 (코드 내) | growth-loop.yml (GH Actions) |
|---|---|---|
| **언제** | 매 스캔 직후 | 매주 일요일 + push 시 |
| **무엇을** | 이번 스캔의 커버리지 갭 분석 | 전체 코드의 약점 자동 패치 |
| **결과물** | Knowledge Store에 갭 기록 | 코드 커밋 (실제 소스 수정) |
| **LLM** | 사용 안 함 (패턴 분석) | LLM이 패치 생성 (Llama-3.3-70B) |
| **목적** | "이번 타겟에서 뭘 놓쳤나" | "코드 자체를 어떻게 개선하나" |

---

## Remaining / Future Work

- [ ] Phase 5/7: Game/Mobile 타겟 시 실제 동작하도록 IoT/Hardware 에이전트 구현
- [ ] Phase 내부에서 직접 Brain 호출 확대 (현재 Phase 6만 직접 사용)
- [ ] MCP Progress: ScanPipeline(brain-driven)에도 event bus 연결 (현재 ScanOrchestrator만)
- [ ] Phase 10 (Red vs Blue): 방어 규칙 자동 생성 구현
- [ ] Phase 17 (Outreach): 리포트 자동 전달 구현
- [ ] Phase 19 (Bug Bounty): 자동 제출 구현
- [ ] GH Actions growth-loop: CVE vectors를 실제 LLM prompt에 반영
- [ ] KnowledgeStore: Finding 패턴 컴파일 (현재 tool execution만 컴파일)
