---
name: 2026-04-20 browser_fill_form Angular Material & PIVOT fix
type: incident
status: active
when_to_read: Juice Shop 스코어 낮음 / auto-login silent fail / Angular Material formcontrolname / browser_fill_form 이 ok=True 인데 실제 미입력
updated: 2026-04-20
sources:
  - ../../../src/vxis/interaction/eyes.py
  - ../../../src/vxis/agent/tools/browser_tools.py
  - ../../../src/vxis/agent/scan_loop.py
  - ../benchmarks/
related:
  - ./2026_04_16_auto_login_fix.md
  - ../../entities/modules/eyes.md
  - ../../entities/modules/scan_loop.md
---
# 2026-04-20 — browser_fill_form Angular Material & PIVOT

## 핵심 사실
| 항목 | 값 |
|---|---|
| Scope | `eyes.fill_form`, `BrowserFillFormTool`, scan_loop Brain prompt |
| 증상 | Juice Shop 375.7/D; browser_fill_form 호출 성공했는데 인증 안 됨 |
| Root cause 1 | fill_form 3 셀렉터 (name/id/placeholder) 만 — Angular Material `formcontrolname=` 매치 X |
| Root cause 2 | fill_form 실패 시 warning 만, tool 은 ok=True 반환 → Brain 은 성공으로 오해 |
| Root cause 3 | Brain prompt 가 `form`+`email/password` 하드코딩 — SPA 실제 field 이름 확인 안 함 |
| 수정 커밋 | 0b56c54 / b89d0a4 / d67ddce |

## TL;DR
2026-04-16 에 scan_loop `_fill_any()` 는 고쳤지만 별개 경로인 `eyes.fill_form` + `BrowserFillFormTool` 은 그대로였다. Juice Shop (Angular Material) 는 HTML `name=` 없고 `formcontrolname=`·`data-placeholder=` 만 써서 기존 3 셀렉터 전부 miss → silent warning → tool ok=True. Brain 은 로그인했다고 믿고 unauthenticated surface 만 긁어 스코어 낮음. 3 phase 로 수리.

## Symptom
- Juice Shop benchmark 총점 375.7/D, baseline 472 대비 -56.6 (ADR-008 노이즈 내이긴 하나 체감 낮음).
- 로그에 `browser_fill_form` 호출 있고 `Could not fill field: email` warning 있지만 Brain state 엔 실패 신호 없음.
- vxis_belief_verdicts 전부 0, MITRE coverage 62.5% 에서 정체.

## Root Cause
1. `eyes.py:fill_form` 3 셀렉터: `[name='x']`, `#x`, `input[placeholder*='x' i]`. Angular Material 폼은 `formcontrolname=`·`data-placeholder=`·`aria-label=` 를 씀.
2. `BrowserFillFormTool.run()` 이 `fill_form` 의 예외만 처리. warning-only silent fail 은 ok=True 로 흘려보냄.
3. scan_loop 프롬프트 L93-94 에 Juice Shop 전용 하드코딩 (`form`, `email`, `' OR 1=1--`, `#loginButton`) 예시 → Brain 이 browser_analyze_dom 건너뛰고 그대로 복사.

## Fix
- **phase-1** (`eyes.py`): `_fill_form_selectors()` 순수 헬퍼 추출 — name/id/formcontrolname/data-placeholder/aria-label/autocomplete/placeholder + `type='email|password|tel'` + 전역 폴백. fill_form 반환을 `{filled, failed, tried_selectors}` 구조화.
- **phase-2** (`browser_tools.py`): 구조화 반환 소비. `failed` 비어있지 않으면 `ok=False`, `error=fields_not_found`, `data.tried_selectors` 제공. 실패 시 submit 건너뜀.
- **phase-3** (`scan_loop.py`): 프롬프트에서 하드코딩 예시 제거. `browser_analyze_dom` → `browser_fill_form` 2-step 지시 + `ok=False` 시 field_name 키 다양화 가이드.

## Lessons
- 같은 이슈가 두 경로에 존재하면 한쪽 fix 로 안심 금지 — sibling path grep 필수 (`\.fill_form\(`).
- Tool 의 ok=True 는 "실행 실패 아님" 일 뿐, "의도 달성" 은 별개. 구조화 반환으로 의도-달성 여부 surface.
- Brain 프롬프트의 구체적 예시는 template 로 고착되기 쉽다. 예시는 패턴 (2-step flow) 로, 값은 DOM 에서 읽게 강제.
