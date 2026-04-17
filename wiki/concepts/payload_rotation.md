---
name: Payload Rotation
type: concept
status: active
when_to_read: payload rotation 동작 / 새 페이로드 추가 위치 / WAF 우회 round 매핑 / clean 결과 re-queue / JSON vs 모듈 상수
updated: 2026-04-17
sources:
  - ../../src/vxis/agent/skills/test_injection.py
  - ../../src/vxis/agent/skills/test_xss.py
  - ../../src/vxis/agent/scan_loop.py
  - ../../src/vxis/data/payloads/injection.json
  - ../../src/vxis/data/payloads/xss.json
  - ../../src/vxis/agent/skills/_payload_loader.py
related:
  - ../entities/skills/test_injection.md
  - ../entities/skills/test_xss.md
  - ../entities/modules/scan_loop.md
  - ../decisions/draft_007_payloads_yaml_refactor.md
  - ./brain_first.md
---
# Payload Rotation

## 핵심 사실
| 항목 | 값 |
|---|---|
| Round 1 | classic (`' OR 1=1--`, `<script>alert(1)</script>`) |
| Round 2 | blind + time-based (sleep, second-order, dnslog) |
| Round 3 | WAF bypass (polyglot, case-mixing, encoding) |
| 트리거 | 직전 round가 `vulnerable=False` 로 clean |
| 재시도 cap | round 3까지 (R < 3 일 때만 re-queue) |
| 구현체 | `scan_loop.py:1268` re-queue 로직, skill 측 `_payloads_for_round()` |

## TL;DR
Round 1 classic 페이로드가 clean이면 scan_loop가 `round=2` (blind+time-based)로 재시도, 또 clean이면 `round=3` (polyglot WAF bypass) — skill 당 최대 3 라운드. `_skill_override` alias(`test_injection__round2_iter34`)로 동일 skill을 다른 args로 재실행.

## What
Payload Rotation은 단일 skill이 한 페이로드 세트에 묶이지 않게 한다. `test_injection`, `test_xss` 같은 injection류 skill은 `round: int = 1` 파라미터를 받고, 내부에서 `_payloads_for_round(r)`로 세트를 교체한다. scan_loop가 clean 결과를 감지하면 round를 증가시켜 큐에 재투입한다.

## Why
WAF·sanitizer가 round 1 classic 페이로드를 차단해도 Brain이 포기하지 않게 하려면 페이로드 다양성이 필요하다. 한 skill을 여러 번 호출하되 args가 같으면 skill_runner 캐시가 `[CACHED — hit #N]` nudge로 Brain에게 "다른 args로" 재시도하라고 압박한다(→ [skill_runner](../entities/modules/skill_runner.md)). round 증가는 Brain이 그 압박에 응답하는 공식 경로다.

## How
- **페이로드 정의** (ADR-007 Phase 1~2 적용, 2026-04-17):
  - **injection**: `src/vxis/data/payloads/injection.json` — `rounds.{"1","2","3"}` 키.
  - **xss**: `src/vxis/data/payloads/xss.json` — 동일 구조.
  - 추가 시 JSON 파일에 dict 형태(`{"payload": ..., "context": ...}`) append. 모듈 상수 (`PAYLOADS*`, `XSS_PAYLOADS*`) 는 legacy — Phase 10 이후 제거.
- **Skill 측 선택**: `_payloads_for_round(r)` / `_xss_payloads_for_round(r)` → `_payload_loader.load_skill_payloads(<name>, r)` 위임.
- **Round 벗어난 값** (`r >= 4` 또는 `r <= 0`): 세 라운드 전체 합집합.
- **scan_loop re-queue** (`scan_loop.py:1268`): skill 결과의 `round` 키를 읽어 `_cur_round < 3`이고 `vulnerable=False`면 `_skill_override` alias로 다음 round 큐잉.
- **Alias 규칙**: `{real_skill}__round{N}_iter{M}` — skill_runner가 `_skill_override`를 strip한 뒤 dispatch.

## Related
- [test_injection](../entities/skills/test_injection.md) — SQLi/CMDi 페이로드 라운드
- [test_xss](../entities/skills/test_xss.md) — XSS 페이로드 라운드
- [scan_loop](../entities/modules/scan_loop.md) — re-queue 메커니즘 위치
