---
name: test_xss
type: skill
status: active
when_to_read: XSS 전용 payload rotation / 필터 우회 / DOM/mXSS 페이로드 위치 / JSON 데이터 위치
updated: 2026-04-17
sources:
  - ../../../src/vxis/agent/skills/test_xss.py
  - ../../../src/vxis/data/payloads/xss.json
  - ../../../src/vxis/agent/skills/_payload_loader.py
related:
  - ./test_injection.md
  - ../modules/scan_loop.md
  - ../../decisions/draft_007_payloads_yaml_refactor.md
code_anchors:
  - src/vxis/agent/skills/test_xss.py:execute
  - src/vxis/agent/skills/test_xss.py:_xss_payloads_for_round
  - src/vxis/data/payloads/xss.json
---
# test_xss

## 핵심 사실
| 항목 | 값 |
|---|---|
| Category | xss (reflected / stored / DOM / mutation) |
| Rotation | yes (round 1/2/3, else all combined) |
| Round 1 | 기본 벡터 — `<script>`, `onerror`, `<svg onload>`, template literal |
| Round 2 | 필터 우회 — case-mix, whitespace split, entity encode, `<keygen>`, `<srcdoc>` |
| Round 3 | 폴리글롯 + DOM-XSS + 인코딩 (0xsobky, rsnake, base64 data URL) |
| 감지 방식 | payload 가 응답 body 에 그대로 반사되면 finding |
| Concurrency | `asyncio.Semaphore(15)` |

## TL;DR
XSS 전용 skill. `test_injection` 에도 XSS 있지만 여기는 context-labeled 페이로드 (basic/event/svg/mxss/dom 등). `round` 로 3 단계 — 1=고전, 2=필터 우회, 3=폴리글롯/DOM/mXSS.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `url` | str | 필수 | 타겟 URL |
| `param_name` | str \| None | None | 주입 파라미터. 없으면 첫 쿼리키 또는 `q` |
| `round` | int | 1 | 1=classic / 2=filter bypass / 3=polyglot+DOM / else=all |
| `**kwargs` | Any | — | 무시 |

## Payload Rounds

**데이터 위치 (ADR-007 Phase 2, 2026-04-17 적용)**: `src/vxis/data/payloads/xss.json` — `rounds.{1,2,3}` 키. 로더: `_payload_loader.load_skill_payloads("xss", r)`. `test_xss.py:XSS_PAYLOADS*` 모듈 상수는 **legacy** — Phase 10 growth 재배선 후 제거 예정.

- **Round 1 (`rounds.1`, 20개)**: `<script>alert(1)</script>`, `<img onerror>`, `<svg/onload>`, attribute break `"><script>`, template literal ``${alert(1)}``, `<iframe javascript:>`, mXSS (`<math><mi><mglyph>...`).
- **Round 2 (`rounds.2`, 20개)**: 대소문자 혼용 `<ScRiPt>`, whitespace `<script >`, 탭/개행 split, nested `<scr<script>ipt>`, HTML entity `&#40;`, `<keygen autofocus>`, `<isindex>`, `<iframe srcdoc=>`, `<form formaction=javascript:>`, `xlink:href` SVG.
- **Round 3 (`rounds.3`, 16개)**: 0xsobky / rsnake / polyglot_break 폴리글롯, DOM-XSS hash (`#<script>`), base64 data URL, double-URL 인코딩 (`%253C...`), 유니코드 이스케이프 (`\u003c`), mXSS `<noscript><p title=`, CSS expression.

`round >= 4` 또는 `<= 0` → 세 세트 JSON 병합 (exhaustive).

## Known Limitations
- 감지는 단순 body 반사 (unescaped)만 — 실제 실행 여부 (headless) 미검증
- stored XSS 읽기 후속 GET 미포함 (단일 요청 후 바로 reflect 체크)
- CSP 헤더로 실행 차단되는 경우 false-positive 가능
- DOM-sink 분석은 `test_injection`과 중복 없이 별도 hash fragment 페이로드만

## Source Files
- `src/vxis/agent/skills/test_xss.py` — `execute()`, `_xss_payloads_for_round()` (로더 위임)
- `src/vxis/data/payloads/xss.json` — 페이로드 데이터 (ADR-007 Phase 2)
- `src/vxis/agent/skills/_payload_loader.py` — JSON 로더
