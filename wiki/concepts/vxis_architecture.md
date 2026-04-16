---
name: VXIS Architecture — Brain / Hands / Eyes / X-Ray
type: concept
status: active
when_to_read: 모듈 역할 분담 / raw httpx 금지 근거 / 어느 컴포넌트가 무엇 담당 / 파이프라인 진입점
updated: 2026-04-16
sources:
  - ../../CLAUDE.md
related:
  - ./brain_first.md
  - ../entities/modules/brain.md
  - ../entities/modules/hands.md
  - ../entities/modules/eyes.md
  - ../entities/modules/xray.md
  - ../entities/modules/scan_loop.md
---
# VXIS Architecture — Brain / Hands / Eyes / X-Ray

## 핵심 사실
| 컴포넌트 | 역할 | 비유 |
|---|---|---|
| Brain | 분석·판단·전략 (LLM) | 시니어 펜테스터의 두뇌 |
| Hands | HTTP 요청 실행 (Controller 계층) | 손 |
| Eyes | 브라우저 렌더링·JS 실행 | 눈 |
| X-Ray | 트래픽 가로채기·raw packet 분석 | 투시 |
| 금지 | raw `httpx` 직접 호출, AGPL 포크(Strix/PentAGI) | — |
| 리포트 | `ReportGenerator.generate_html_file()` 단일 HTML | NCC Group 스타일 |

## TL;DR
Brain이 전략을 세우면 Hands(HTTP)·Eyes(브라우저)·X-Ray(트래픽)가 실행만 담당한다. 모든 네트워크는 Hands/X-Ray/Controller/Finding 모듈 경유 — raw httpx 금지. AGPL 포크(Strix 등) 금지, 100% 자체 구현.

## What
VXIS는 시니어 펜테스터의 작업 구조를 4 컴포넌트로 분해한 아키텍처다. Brain이 의사결정 주체이고 나머지 3개는 실행 계층이다. 각 계층은 역할별 모듈로 구현돼 있고 scan_loop이 Brain의 tool-calling 인터페이스로 이들을 엮는다.

## Why
역할 분리 없이 Brain이 직접 httpx를 호출하면 (1) 재시도·rate-limit·evidence 캡처 로직이 프롬프트에 섞여 컨텍스트를 오염시키고, (2) Hands 레이어의 공통 기능(auto-login, cookie jar, HAR dump)을 매번 재구현하게 된다. AGPL 포크 금지는 라이선스 위험을 원천 차단 — VXIS 전체가 100% 자체 구현이어야 상업 배포 가능.

## How
- **Brain** (`src/vxis/agent/brain.py`): LLM 호출 (Claude Code 우선, API fallback). `plan/interpret/chain/reflect` 메서드.
- **Hands** (`src/vxis/hands/`): Controller 계층. `httpx.AsyncClient` 를 감싸고 auto-login, retry, HAR 캡처 담당. Skill 코드는 반드시 여기 경유.
- **Eyes** (`src/vxis/eyes/`): Playwright 기반. SPA·JS 렌더링 필요한 벡터(DOM XSS, PostMessage)용.
- **X-Ray** (`src/vxis/xray/`): mitmproxy 스타일 트래픽 interception. raw packet 증거 수집.
- **Scan loop** (`src/vxis/agent/scan_loop.py`): Brain의 tool-call을 Hands/Eyes/X-Ray로 dispatch하는 메인 오케스트레이터.
- **Report** (`src/vxis/reports/report_generator.py`): NCC Group 템플릿 단일 HTML 렌더.

## Related
- [brain_first](./brain_first.md) — Brain이 왜 주체여야 하는지
- [scan_loop](../entities/modules/scan_loop.md) — 4 컴포넌트를 엮는 오케스트레이터
- [skill_runner](../entities/modules/skill_runner.md) — Brain tool-call을 skill로 dispatch
