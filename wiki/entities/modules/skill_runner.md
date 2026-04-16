---
name: skill_runner
type: module
status: active
when_to_read: run_skill 호출 캐시 / escalation 정책 / 중복 호출 방지 / _skill_override aliasing / SKILL_REGISTRY 접근점
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/tools/skill_runner.py
related:
  - ./scan_loop.md
  - ../../concepts/brain_first.md
code_anchors:
  - src/vxis/agent/tools/skill_runner.py:RunSkillTool
  - src/vxis/agent/tools/skill_runner.py:_skill_cache
  - src/vxis/agent/tools/skill_runner.py:_skills_ever_called
---
# skill_runner

## 핵심 사실
| 항목 | 값 |
|---|---|
| Tool name | `run_skill` |
| Role | Brain 의 skill 호출 어댑터 — 1 call = 수십 payload |
| Cache key | `(skill, json.dumps(args))` — args identity 기반 |
| Escalation | hit#1 soft nudge → #2 strong+untried list → #3+ `ok=False` BLOCK |
| Diversity tracking | `_skills_ever_called: set[str]` — args 무관, skill 이름만 |
| Aliasing | `_skill_override` 로 alias → canonical skill 매핑 |
| Registry | `vxis.agent.skills.SKILL_REGISTRY` (15 skills) |

## TL;DR
Brain 이 동일 `(skill, args)` 를 반복 호출하면 점진적으로 강하게 차단 — 1회차 soft 경고, 2회차 untried skill 리스트, 3회차부터 완전 차단. Brain-First 원칙: "ignore nudges → ESCALATE".

## Key Surfaces
- `RunSkillTool.run(skill, target_url, params)` — 메인 엔트리. 캐시 조회 → SKILL_REGISTRY dispatch.
- `_skill_cache` — `(skill, args)` → `{result, hit_count, …}` 매핑.
- `_skills_ever_called` — 실행된 skill 이름 전체 집합. nudge 에서 "untried" 계산용.
- `_skill_override` — alias → canonical 매핑 (e.g. `test_sqli` → `test_injection`).
- `_reset_cache_for_tests()` — 테스트 전용 리셋 (프로덕션 호출 금지).

## Invariants
- 같은 `(skill, args)` 3회 이상 호출 시 `ok=False, error="stuck_loop"` 강제 반환 — Brain 이 반드시 다른 skill 선택.
- Cache 는 프로세스 글로벌 — scan 간 격리 필요 시 `_reset_cache_for_tests()` 호출 (production 금지).
- SKILL_REGISTRY 미등록 skill 은 `ok=False, error="unknown_skill"` + available list.
- `target_url` 또는 `skill` 비면 `error="missing_args"` 즉시 반환.
- cache hit 카운터는 증가만 — 새 args 로 호출해도 이전 hit 수 유지 (학습 보존).

## Related
- [scan_loop](./scan_loop.md) — run_skill 을 호출하는 Brain 루프
- [brain_first](../../concepts/brain_first.md) — escalation 정책의 근거 (Brain 이 판단 주체)
