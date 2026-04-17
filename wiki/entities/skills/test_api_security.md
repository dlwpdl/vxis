---
name: test_api_security
type: skill
status: active
when_to_read: Mass assignment / rate limiting / verb tampering / param pollution
updated: 2026-04-17
sources:
  - ../../../src/vxis/agent/skills/test_api_security.py
related:
  - ./test_business_logic.md
  - ./test_csrf.md
code_anchors:
  - src/vxis/agent/skills/test_api_security.py:execute
---
# test_api_security

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | api-security |
| Rotation | no |
| Mass assignment fields | 8 (`role`, `isAdmin`, `is_staff`, `verified`, `balance`, `discount`, `price`, `permissions`) |
| Reg paths | 4 (`/api/users`, `/api/register`, `/api/signup`, `/api/account`) |
| Rate-limit paths | 3 — 10 rapid `{admin, wrong}` POST, 429 없으면 medium |
| Verb tampering | 6 paths × 5 methods (GET/PUT/DELETE/PATCH/OPTIONS), 3 개 이상 허용 시 medium |
| Param pollution | `?id=1&id=2` → 200 이면 low |
| Concurrency | `asyncio.Semaphore(15)` |

## TL;DR
API 보안 4 종 복합 skill. (1) mass assignment — 등록 페이로드에 `role=admin` 끼워넣기, 응답에 반영되면 high. (2) rate limit — 10 연속 로그인 실패 후 429 없음. (3) verb tampering — 동일 경로에 5 메서드 중 3 개 이상 통과. (4) param pollution.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL |
| `token` | str \| None | None | Bearer 로 모든 테스트에 동일 적용 |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- Mass assignment 판정은 body 에 `field` + `value` 둘 다 소문자로 포함됐는지 — false-negative 가능 (응답에 반영 안 하는 서버)
- Rate-limit 은 10 회 고정, 임계값도 "429 안 보이면" 으로 단순 — CAPTCHA/지연 기반 제한 miss
- Verb tampering 임계값 3 → 2 개 허용하는 타겟은 miss
- Param pollution 은 `?id=1&id=2` 하나만 — 서로 다른 파싱 동작 (first vs last vs array) 구분 없음
- Test 계정 `testuser`·`Test1234!` 고정 → 서버가 중복 거부 시 모든 reg paths false-negative

## Source Files
- `src/vxis/agent/skills/test_api_security.py`
