---
name: test_business_logic
type: skill
status: active
when_to_read: 음수 수량·가격 0·정수 overflow·coupon 재사용·state skip·race condition
updated: 2026-04-17
sources:
  - ../../../src/vxis/agent/skills/test_business_logic.py
related:
  - ./test_api_security.md
  - ./test_idor.md
code_anchors:
  - src/vxis/agent/skills/test_business_logic.py:execute
---
# test_business_logic

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | business-logic |
| Rotation | no |
| 테스트 케이스 | 12 (LOGIC_TESTS) + 1 race condition |
| 카테고리 | 음수 수량 / 0 가격 / 정수 overflow (2147483647) / coupon 재사용 / 결제 skip / self-verify |
| Error indicator | `invalid / cannot / negative / not allowed / error` — 응답에 없으면 "허용" 로 간주 |
| Race condition | `/api/coupon/apply` 에 `RACE_TEST` 5 병렬 POST, 1 개 초과 성공 시 high |
| Severity 범위 | medium (coupon reuse) ~ critical (0 가격, negative transfer, ship without payment) |

## TL;DR
12 개 결제·주문·계정 시나리오에 비정상 body 전송, status 200/201/202 + error indicator 없음 → 로직 취약. 추가로 coupon 5 병렬 apply 로 double-spend race condition 감지.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | 타겟 base URL |
| `token` | str \| None | None | Bearer 로 전송 (없으면 익명) |
| `**kwargs` | Any | — | 무시 |

## Known Limitations
- 경로는 `/api/cart/add`, `/api/transfer`, `/api/coupon/apply` 등 제네릭 REST 가정 — Juice Shop `/rest/basket/checkout` 구조 미반영
- error indicator 한국어 응답 ("수량이 잘못") 미커버 → 영어권 앱만 정확
- 결제 skip 은 body 만 조작 — 세션 상태 머신 우회 없음
- Race condition 은 한 경로만 — 재고/포인트 차감 다른 endpoint 미테스트
- 실제 "공격자 계정 잔액 증가" 검증 없음 (응답 200 이면 무조건 성공으로 판단)

## Source Files
- `src/vxis/agent/skills/test_business_logic.py`
