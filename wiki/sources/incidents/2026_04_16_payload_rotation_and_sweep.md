---
name: 2026-04-16 Payload Rotation R2/R3 + Skill Sweep Added
type: incident
status: active
when_to_read: 이번 세션 payload rotation 동작 / skill sweep 트리거 / _real_skills_completed / round re-queue alias
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/scan_loop.py
  - ../../../src/vxis/agent/skills/test_injection.py
  - ../../../src/vxis/agent/skills/test_xss.py
related:
  - ../../concepts/payload_rotation.md
  - ../../entities/skills/test_injection.md
  - ../../entities/skills/test_xss.md
  - ../../entities/modules/scan_loop.md
---
# 2026-04-16 — Payload Rotation R2/R3 + Skill Sweep Introduced

## 핵심 사실
| 항목 | 값 |
|---|---|
| Scope | `test_injection.py` / `test_xss.py` / `scan_loop.py` |
| 신규 round | PAYLOADS_ROUND2 (~20 blind/time/OOB), PAYLOADS_ROUND3 (~15 polyglot WAF) |
| XSS 신규 | XSS_PAYLOADS_ROUND2 (~20 filter bypass), XSS_PAYLOADS_ROUND3 (~16 DOM/mutation) |
| Skill sweep 트리거 | `iteration >= 25` + 10-iter gap, 미수행 SKILL_REGISTRY 전부 큐잉 |
| Re-queue 트리거 | `vulnerable=False` + `round < 3` → `round+1` 큐잉 |
| Alias | `{skill}__round{N}_iter{M}` / `{skill}__sweep{M}` — `_skill_override` 로 strip 후 dispatch |
| 수정 커밋 | d13d6d9 |

## TL;DR
WebGoat 같이 WAF / 강한 sanitizer 타겟에서 round 1 classic 만 돌려 clean 판정하던 문제를 해결. test_injection/test_xss 는 내부 `_payloads_for_round(r)` 선택, scan_loop 는 clean 결과 감지해 round+1 로 alias queue. Vector Coverage 차원 plateau 방지로 iter ≥ 25 부터 10-iter 주기로 untried skill 전부 일괄 큐잉 (sweep).

## Symptom
- `test_injection` 이 1 회만 실행되고 clean 처리 → SQLi 있어도 finding 0.
- `test_xss` 동일 — round 1 filter 우회 실패하면 clean.
- Vector Coverage 점수 고정 — 일부 skill 한 번도 미실행.
- Brain 이 "추가 페이로드 시도" 해도 cache 로 같은 결과.

## Root Cause
- skill 에 round 파라미터 없음 → 페이로드 세트 고정.
- scan_loop 에 clean 기반 자동 재시도 경로 없음.
- `_skills_completed` 가 alias-keyed → "진짜 real skill 실행" 추적 불가, sweep 불가능.
- URL-with-params / token / id_pattern 요구 skill 이 enumerate 빈손일 때 영영 미실행.

## Fix
- **Round payload rotation** (`test_injection.py`, `test_xss.py`):
  - R2 — blind/time (SLEEP/WAITFOR/`pg_sleep`), stacked, UNION info_schema, OOB, SSTI, CRLF, XXE, LDAP.
  - R3 — 0xsobky/rsnake polyglot, URL/double-URL 인코딩, Unicode, 주석 우회, null byte, CSS.
  - `_payloads_for_round(r)` / `_xss_payloads_for_round(r)` 셀렉터.
  - `execute(..., round=1)` 시그니처, return dict 에 `round` 포함.
- **scan_loop re-queue** (L1267~L1296): `vulnerable=False` + `round < 3` → `_skill_override` alias 로 `round+1` 큐잉.
- **`_real_skills_completed`** (L557): alias 가 아닌 real skill 이름 트래커. sweep 이 untried 계산 가능.
- **Skill sweep** (L1957~L2015): `iter >= 25` + 10-iter gap → SKILL_REGISTRY - _real_skills_completed 전부 generic default 로 큐잉.
- **Default args**: `test_injection` → `/search?q=test`, `test_idor` → `/api/users/{id}`, token 필요는 `_auth_token` (빈 문자열이라도).

## Lessons
- 페이로드는 데이터 layer — round 분리로 freeze + fresh 가능.
- Skill 실행 추적은 real skill 이름으로 — alias 추적은 sweep 무한루프.
- Vector coverage 는 passive 측정 시 plateau — 명시 sweep 트리거 필요.
- `_skill_override` 패턴 재사용 — 다른 컨텍스트는 alias + override 조합.
