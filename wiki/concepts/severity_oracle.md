---
name: Severity Oracle (Content-Aware)
type: concept
status: active
when_to_read: 정적 severity vs body-aware 조정 / Spring Actuator masked 판단 / raw secret critical 격상
updated: 2026-04-16
sources:
  - ../../src/vxis/agent/skills/test_sensitive_files.py
related:
  - ../entities/skills/test_sensitive_files.md
  - ./brain_first.md
  - ./scoring_model.md
---
# Severity Oracle (Content-Aware)

## 핵심 사실
| 항목 | 값 |
|---|---|
| 대상 skill | `test_sensitive_files` (Actuator·백업·키파일 프로빙) |
| 판단 함수 | `_adjust_severity(path, body, declared) -> (severity, note)` |
| Downgrade 규칙 | `/actuator/env` 에서 `"******"` / `"value":` 비율 > 0.6 → `low` |
| Upgrade 규칙 | body에 `secret` / `password` / `jdbc:` / `mongodb://` / `postgres://` raw 노출 → `critical` |
| 기본 fallback | declared severity 유지 |
| 적용 위치 | `test_sensitive_files.py:167` — finding 생성 직전 |

## TL;DR
정적 경로별 declared severity는 "critical /actuator/env"처럼 과대 flagging을 만든다. `_adjust_severity()`는 실제 body를 읽어 masked 비율 60%↑면 low로 downgrade, raw 시크릿(jdbc:/mongodb:// 등)이 보이면 critical로 upgrade. false positive와 under-triage를 동시에 잡는다.

## What
Severity Oracle은 finding의 심각도를 "경로만 보고 declare"하지 않고 실제 응답 body 내용을 근거로 조정하는 메커니즘이다. Spring Boot Actuator sanitizer가 민감 값을 `"******"`로 마스킹하면 critical 판정이 부적절해진다 — 반대로 마스킹이 뚫려 raw 시크릿이 새면 declared가 high여도 critical로 격상해야 한다.

## Why
2026-04 WebGoat 벤치마크에서 `/actuator/env` 같은 엔드포인트가 masked 상태인데도 critical로 flag돼 리포트가 "늑대가 왔다" 효과를 냈다. Precision 차원(20%, 200점)이 FP로 깎이고 고객 신뢰도 떨어진다. 반대로 비정상적으로 masked를 안 거친 env가 high로만 기록되면 Crown Jewel 경로를 놓친다. Body를 보는 순간 양방향 교정이 가능해진다.

## How
1. `test_sensitive_files.py`가 경로별로 declared severity(예: `/actuator/env` → `critical`)를 가진 프로빙 리스트를 순회.
2. 응답 받으면 `_adjust_severity(path, body, declared)` 호출.
3. 함수 내부: `/actuator/env` 경로면 `body.count('"******"') / max(body.count('"value":') or 1, 1)`로 masked ratio 계산. 0.6 초과 시 `("low", "values masked by Spring Boot sanitizer")`.
4. 이어서 `("secret", "password", "jdbc:", "mongodb://", "postgres://")` needle 탐색 — 하나라도 hit면 `("critical", f"unmasked {needle} leaked in env")`.
5. 둘 다 해당 없으면 declared 유지.
6. 결과 severity와 note를 finding evidence에 기록.

## Related
- [test_sensitive_files](../entities/skills/test_sensitive_files.md) — oracle을 호출하는 skill
- [scoring_model](./scoring_model.md) — Finding Precision 차원이 FP를 penalize
- [brain_first](./brain_first.md) — 정적 판단 금지 원칙의 실제 적용
