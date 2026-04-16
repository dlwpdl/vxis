---
name: Plan-Review and Code-Review Workflow
type: concept
status: active
when_to_read: 비자명 작업 시작 절차 / 8 subagent 역할 / phased commit 규칙 / CLAUDE.md 길이 제한 근거
updated: 2026-04-16
sources:
  - ../../CLAUDE.md
related:
  - ./brain_first.md
  - ./ai_context_hygiene.md
  - ../decisions/claude_md_thin.md
---
# Plan-Review and Code-Review Workflow

## 핵심 사실
| 단계 | 도구 | 출력 |
|---|---|---|
| 1. Plan mode | Claude Plan Mode (스코프·성공 기준 명시 프롬프트) | 초안 plan |
| 2. `/plan-review` | 8 subagent (architecture, coding-standards, UX, performance, security, testing, ops, docs) | plan 수정 피드백 |
| 3. Phased commit | 각 phase = 1 commit, `phase-N: <what>` 메시지 | 커밋 체인 |
| 4. `/code-review` | 동일 8 subagent 재사용 | 커밋별 리뷰 |
| 5. 수동 steer | Eliot이 피드백 검토 후 방향 조정 | 다음 phase 입력 |
| CLAUDE.md 한도 | ~100 lines — 워크플로우·원칙·커맨드만 | 상세는 code comment |

## TL;DR
비자명 작업은 Plan Mode 먼저 → `/plan-review` 8 subagent가 plan을 타이트하게 → phased commit → 커밋마다 `/code-review`. Eliot은 driver's seat 유지하며 reviewer 관점을 8배 확장. CLAUDE.md는 얇게, 상세는 코드 주석.

## What
Plan-Review 워크플로우는 VXIS 개발 표준 프로세스다. 모든 비자명 task는 (1) Plan Mode에서 스코프·성공 기준 명시, (2) `/plan-review` skill로 8개 전문 subagent 병렬 리뷰, (3) 각 phase를 독립 commit으로 분리, (4) 커밋마다 `/code-review`로 동일 8 subagent 재실행한다.

## Why
장시간 리뷰 없는 대규모 코드 dump를 방지하기 위함이다. Phased commit은 체크포인트를 강제하고, 8 subagent는 단일 관점이 놓치는 cross-cutting concern(perf × security × a11y)을 각자의 전용 레퍼런스 문서(`postgres_performance.md`, `python_threading.md`, `software_architecture.md` 등)로 잡는다. CLAUDE.md를 100 lines 이하로 유지하는 이유도 같다 — 50 lines 넘어가면 아무도 안 읽는다.

## How
- **Plan Mode 진입 조건**: 코드 3파일 이상 수정, 또는 새 pipeline/skill/decision 도입.
- **/plan-review 호출**: ExitPlanMode 전에 실행. 8 subagent 각각 전용 reference doc 참조(architecture는 SOLID/DRY/KISS/YAGNI 기준).
- **Phased commit**: 계획의 한 phase = 한 commit. 메시지는 `phase-N: <what>` 또는 `feat(scope): <what>`, 본문에 why. `--no-verify`/`--no-gpg-sign` 금지.
- **/code-review**: 각 commit 직후. 피드백은 Eliot이 검토 후 다음 phase 입력에 반영 — 자동 적용 X.
- **CLAUDE.md 편집 규칙**: 워크플로우·절대 원칙·주요 커맨드만. 상세 규칙은 해당 코드 파일 상단 주석에.

## Related
- [brain_first](./brain_first.md) — 개발 표준의 첫 번째 원칙
- [ai_context_hygiene](./ai_context_hygiene.md) — 8 subagent는 context 분할의 한 형태
