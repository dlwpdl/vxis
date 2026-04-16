---
name: AI Context Hygiene — 4 Principles
type: concept
status: active
when_to_read: context window 관리 원칙 / tool 결과 dump 금지 / wiki 가 RAG 구현인 이유 / 5-Loop 매핑
updated: 2026-04-16
sources:
  - ../../../.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_ai_context_hygiene.md
related:
  - ./brain_first.md
  - ./chain_intelligence.md
  - ./plan_review_workflow.md
  - ../CLAUDE.md
---
# AI Context Hygiene — 4 Principles

## 핵심 사실
| # | 원칙 | 요약 |
|---|---|---|
| 1 | State-not-result | Raw log/output dump 금지, 핵심 state 만 추출 |
| 2 | 5-Loop | 관찰 → 가설 → 설계 → 실행 → 리셋 (VXIS Phase 와 동일) |
| 3 | Gold memory | 중요 단서(creds/hash/token/path)를 Markdown 표로 박제 |
| 4 | RAG | KB(CVE·wiki)에서 필요 시만 fetch, 전체 먹이기 금지 |
| VXIS 매핑 ④ | `wiki/` 자체가 RAG 사내 KB | 매 세션 새로 조사 X, wiki 에서 read |
| 위반 시 영향 | Context 꼬임 → attack chain 전체 어긋남 (multi-step 치명적) |

## TL;DR
AI 컨텍스트는 한정 — 쓰레기 데이터 누적 시 정확도 급락, 특히 multi-step chained reasoning에서 치명적. 4 원칙: ① state-not-result, ② 5-Loop 끊어 진행, ③ 중요 단서 표로 박제, ④ RAG(wiki)에서 꺼내 쓰기. VXIS `wiki/` 자체가 원칙 ④ 구현체.

## What
AI Context Hygiene은 Eliot이 pentest·dev 세션에서 LLM 컨텍스트를 관리하는 4개 룰이다. 각 원칙은 VXIS 코드·wiki 구조에 직접 매핑돼 있다 — 이론이 아니라 운영 표준이다.

## Why
Context window가 오염되면 Brain이 헛소리·표류를 시작하고, 이전 발견과 무관한 페이로드를 생성한다. Pentest처럼 한 단계의 출력이 다음 단계의 입력이 되는 작업에선 한 번의 context 꼬임이 chain 전체를 무너뜨린다. 4 원칙은 이 실패 모드를 각도별로 차단한다.

## How
- **① State-not-result**: Tool 결과가 길면 skill_runner가 요약 state만 Brain에 전달. 예: "Nmap 80/443 open, Apache 2.4.41" O / "로그 500줄 dump" X. `skill_runner.py`가 이 패턴 구현.
- **② 5-Loop**: scan_loop의 Phase 구조(분석 → 결정 → 실행 → 해석 → 다음 행동)가 이 루프다. Multi-step 작업은 한 메시지당 한 루프로 끊는다. `wiki/CLAUDE.md §1`이 5-Loop ↔ wiki 구역 매핑.
- **③ Gold memory**: 스캔 중 발견되는 creds/token/backdoor path는 `state.findings` + `wiki/sources/benchmarks/`에 표로 박제. Brain이 표류하면 이 표를 다시 프롬프트에 주입해 alignment.
- **④ RAG**: `wiki/` 자체가 사내 KB. 새 세션이 매번 코드를 전부 다시 read하지 않고 `wiki/index.md`의 `when_to_read` hint로 필요한 페이지만 fetch. 새 발견은 즉시 wiki에 ingest해 다음 세션의 비용을 0으로.

## Related
- [brain_first](./brain_first.md) — Brain의 입력 품질이 출력 품질을 결정
- [chain_intelligence](./chain_intelligence.md) — 5-Loop의 "다음 행동"이 chain 생성 단계
- [plan_review_workflow](./plan_review_workflow.md) — 8 subagent가 context 분할의 한 형태
