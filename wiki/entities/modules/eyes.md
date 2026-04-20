---
name: eyes
type: module
status: active
when_to_read: Playwright 브라우저 / JS 실행 / DOM 분석 / SPA 대응 / 스크린샷 / 쿠키·스토리지 접근
updated: 2026-04-20
sources:
  - ../../../src/vxis/interaction/eyes.py
  - ../../../src/vxis/agent/tools/browser_tools.py
related:
  - ./hands.md
  - ./xray.md
  - ./scan_loop.md
code_anchors:
  - src/vxis/interaction/eyes.py:BrowserEngine
  - src/vxis/agent/tools/browser_tools.py:BrowserNavigateTool
  - src/vxis/agent/tools/browser_tools.py:BrowserEvalJsTool
  - src/vxis/agent/tools/browser_tools.py:BrowserFillFormTool
---
# eyes

## 핵심 사실
| 항목 | 값 |
|---|---|
| Role | Brain 의 "눈" — Playwright + CDP 브라우저 엔진 |
| 의존성 | `playwright` (optional, 없으면 graceful degrade) |
| 브라우저 | Chromium (Docker 이미지에 사전 설치) |
| Tool 어댑터 | `browser_navigate`, `browser_analyze_dom`, `browser_click`, `browser_fill_form`, `browser_eval_js`, `browser_screenshot`, `browser_get_cookies` |
| 캡처 | NetworkLog (모든 요청/응답), ConsoleLog (JS 에러) |
| 격리 | `BrowserContext` 당 독립 쿠키 jar |
| SPA 대응 | JS 실행·대기, DOM snapshot, 접근성 트리 |

## TL;DR
Hands 가 못 보는 JS 렌더링 SPA·동적 DOM·클라이언트 스크립트를 실행해서 보는 계층. 페이지 탐색·폼 입력·JS eval·스크린샷·쿠키 추출 모두 Playwright 래퍼 경유. auto-login 시 scan_loop 이 `browser_fill_form` 사용.

## Key Surfaces
- `BrowserEngine` — Playwright 래퍼. async context manager.
- `BrowserContext` — 격리된 세션 (쿠키/스토리지/네트워크 로그 분리).
- `DockerBrowserManager` — 컨테이너 안에서 Chromium 실행 (CI 환경).
- `BrowserNavigateTool` — `url` 으로 이동, SPA load 대기.
- `BrowserAnalyzeDomTool` — DOM 요소 추출, 가시성·접근성 트리 반환.
- `BrowserClickTool`, `BrowserFillFormTool` — 폼 자동화. auto-login 진입점. `fill_form` 은 name/id/`formcontrolname`/`data-placeholder`/`aria-label`/`autocomplete`/`type=email|password` 순서로 셀렉터 시도, `{filled, failed, tried_selectors}` 구조화 반환. 실패 시 tool 이 `ok=False` + `error=fields_not_found` 로 Brain 에 PIVOT signal (2026-04-20 phase-1/2).
- `BrowserEvalJsTool` — 임의 JS 실행 (e.g. `document.cookie`, `localStorage`).
- `BrowserScreenshotTool` — 시각적 evidence 수집.
- `BrowserGetCookiesTool` — 쿠키·로컬스토리지·세션스토리지 덤프.

## Invariants
- Playwright 미설치 시 `PLAYWRIGHT_AVAILABLE = False` — tool 이 즉시 ok=False 반환, 크래시 금지.
- BrowserContext 는 scan 당 1개 공유 — 쿠키가 이후 iteration 으로 전파.
- `browser_eval_js` 출력은 반드시 JSON-serializable — Brain 해석용.
- Screenshot 은 evidence/ 디렉토리에 저장, finding 에 path 연결.
- SPA 대기 timeout 초과 시 부분 DOM 이라도 반환 — hang 금지.
- Docker 모드는 이미지에 `playwright install chromium` 사전 설치 필요.

## Related
- [hands](./hands.md) — HTTP 계층 (JS 없는 요청)
- [xray](./xray.md) — Hands/Eyes 트래픽 인터셉트
- [scan_loop](./scan_loop.md) — auto-login 에서 browser_fill_form 호출
