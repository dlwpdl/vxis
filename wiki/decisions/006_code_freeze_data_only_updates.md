---
name: ADR-006 — Code Freeze + Data-Only Updates
type: decision
status: active
when_to_read: 코드 수정 검토 / 데이터 vs 로직 분리 / 회귀 방지 / AI 할루시네이션 방지 / PAYLOADS 외부 파일화
updated: 2026-04-16
sources:
  - /Users/eliot/.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_code_freeze.md
related:
  - ../concepts/brain_first.md
  - ../concepts/payload_rotation.md
  - ./005_dynamic_not_static.md
---
# ADR-006 — Code Freeze + Data-Only Updates

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-04-16 |
| Freeze 대상 | `scan_loop.py` 루프 / `skill_runner.py` cache-aliasing / skills `execute()` 시그니처 / `pipeline/` phase 순서 / `reports/report_generator.py` / `brain.py` LLM 호출 정책 |
| Fresh 대상 | `PAYLOADS_*` 리스트 / CVE 데이터 / threat intel 트렌드 / severity oracle 임계값 · 패턴 / signature regex / `wiki/sources/research` · `benchmarks` |
| 현재 메커니즘 | 페이로드가 `.py` 안 모듈 상수 (in-file) |
| 미래 메커니즘 | YAML / JSON 외부 파일 분리 → 데이터 commit ≠ 코드 commit |

## TL;DR
코드를 계속 업데이트하면 (a) 같은 자리 다시 만지다 다른 곳 회귀 (b) AI 가 옛 버전 기억 + 새 버전 섞어 할루시네이션. 일정 시점 에 코드 freeze, 외부 데이터 (CVE / payloads / threat intel) 만 fresh feed. 코드 표면 stable, 데이터 layer 만 흐르면 회귀·할루시네이션 동시 차단.

## Context
2026-04 현재 `scan_loop.py` / `skill_runner.py` / skills 가 안정화 (7 disconnection 수정 포함). 이 상태서 기능 추가하면 회귀 + AI 가 옛 시그니처와 현재 혼동. 공격 표면은 계속 진화 — CVE·페이로드·bypass 가 매일 등장. 코드 vs 데이터 두 주기 분리 필요.

## Options
1. **혼재 유지** — 모든 변경이 코드 commit, 회귀·할루시네이션 지속.
2. **코드 freeze + 데이터만 fresh** — 표면 stable, 데이터 layer 만 변동.
3. **전체 freeze** — 새 CVE·페이로드 반영 불가, 제품 stale.

## Decision
옵션 2 채택. Freeze 대상·Fresh 대상 명확히 구분 (핵심 사실 표). Freeze 파일 건드리는 commit 은 body 에 정당화 사유 필수. 페이로드는 현재 in-file 상수지만 미래 YAML/JSON 외부 파일 리팩터 (별도 plan). CVE 는 `cve-watch.yml` GH Actions 자동 fetch → `wiki/sources/research/` ingest. 코드 commit 빈도 ↓, 데이터 PR / auto-fetch ↑.

## Consequences
- **Pro**: 회귀 테스트 안정 — 표면 코드 변화 ↓.
- **Pro**: AI 할루시네이션 감소 — 시그니처·인자 메모리가 현재 코드와 일치.
- **Pro**: 외부 위협 인텔 자동 flow — 공격 능력 신선.
- **Con**: 새 기능 욕구 억제 — "데이터인가 로직인가" 자문 습관.
- **Con**: PAYLOADS 외부화 리팩터 별도 투자 필요.
- **Enforcement**: Freeze diff 시 reviewer "외부화 가능?" 질문.
