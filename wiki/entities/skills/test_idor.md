---
name: test_idor
type: skill
status: active
when_to_read: IDOR sequential ID / auth bypass 탐지 / url_pattern {id} 템플릿
updated: 2026-04-16
sources:
  - ../../../src/vxis/agent/skills/test_idor.py
related:
  - ./post_auth_enum.md
  - ./attempt_auth.md
  - ../modules/scan_loop.md
code_anchors:
  - src/vxis/agent/skills/test_idor.py:execute
---
# test_idor

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | access-control (IDOR) |
| Rotation | no |
| ID range | 1 ~ `max_id` (기본 20) |
| 비교 축 | with-token vs no-token, sequential ID |
| `accessible_ids` | 토큰 있을 때 200 반환한 ID |
| `auth_bypass_ids` | 토큰 없을 때 200 & body > 50B 반환한 ID |
| Vulnerable 조건 | `accessible_ids > 1` or `auth_bypass_ids > 0` |
| Sample 저장 | id <= 5 응답 prefix 300 자 |

## TL;DR
`{id}` placeholder 들어간 url_pattern 을 1 ~ max_id 로 돌며 순차 접근. 토큰 유무 모두 테스트하여 (1) 본인 계정 밖 데이터 접근, (2) 아예 토큰 없이도 열리는 bypass 두 경우 감지.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `url_pattern` | str | 필수 | `{id}` 플레이스홀더 포함 (예: `http://target/api/Users/{id}`) |
| `token` | str \| None | None | 있으면 `Bearer` + `Cookie: token=` 두 헤더로 보냄 |
| `max_id` | int (kwargs) | 20 | 순회 상한 |
| `**kwargs` | Any | — | 기타 무시 |

## Known Limitations
- 순차 정수 ID 만 — UUID / hash / base62 미지원
- `{id}` 하나만 치환 — 복합 경로 (`/api/users/{uid}/orders/{oid}`) 미지원
- 응답 동일성 판정 없음 — 200 이면 무조건 `accessible_ids` 에 추가 (권한 차이 무시)
- max_id 20 작음 — 큰 테넌트에서 IDOR 놓칠 수 있음
- POST/PUT body 기반 IDOR 미테스트 (GET only)

## Source Files
- `src/vxis/agent/skills/test_idor.py`
