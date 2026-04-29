---
name: ADR-001 — No AGPL Forking (Strix / PentAGI)
type: decision
status: active
when_to_read: 외부 코드 참고 경계 / Strix·PentAGI 사용 금지 이유 / VXIS 라이센스 전략 / AGPL 오염 위험
updated: 2026-04-16
sources:
  - /Users/eliot/.claude/projects/-Users-eliot-Desktop---vxis/memory/feedback_license.md
related:
  - ../concepts/brain_first.md
---
# ADR-001 — No AGPL Forking (Strix / PentAGI)

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted |
| Date | 2026-04-16 |
| 금지 대상 | Strix (AGPL-3.0), PentAGI 등 AGPL 오픈소스 코드 포크·복사 |
| 허용 경계 | 아키텍처 개념 참고 (plugin 구조, agent graph 등) 만 |
| Tool 호출 | Nuclei / Nmap / ZAP subprocess 호출 OK (라이센스 문제 없음) |
| VXIS 원칙 | 100% 자체 작성 — private repo + 상용 제품 전제 |

## TL;DR
Strix / PentAGI 는 AGPL-3.0 — "서버에서 돌리기만 해도" 소스 공개 의무 발생. VXIS 는 private repo + 상용 제품이므로 한 줄이라도 포크·복사 시 전체 소스 공개. 개념만 참고, 코드는 100% 자체 구현. 외부 도구는 subprocess 로만.

## Context
VXIS 는 상용 배포 목표. 유사 OSS (Strix, PentAGI) 대부분 AGPL-3.0 — 네트워크 서비스 조항으로 SaaS 로 접근만 해도 소스 공개 의무. 포크·copy-paste 하면 전체 코드베이스 오염.

## Options
1. **포크 fast-track** — 속도 최대, 상용화 불가.
2. **개념만 참고 + 100% 자체 구현** — 속도 ↓, 라이센스 자유.
3. **듀얼 라이센스 협상** — 비용·의존 과다.

## Decision
옵션 2 채택. Strix / PentAGI 는 plugin 구조 · agent graph · phase 순서 같은 **아키텍처 개념** 만 참고. 코드는 한 줄도 따라치지 않고 자체 설계·작성. 외부 공격 도구 (Nuclei, Nmap, sqlmap, ZAP) 는 `subprocess` 호출로 — 별개 프로세스는 라이센스 경계 밖.

## Consequences
- **Pro**: 상용 배포 시 전체 소스 공개 의무 없음. private deploy 자유.
- **Pro**: VXIS 독자 아키텍처 (Brain/Hands/Eyes/X-Ray) 정립 — 차별화 자산.
- **Con**: MVP 개발 속도 느림 — agent 루프·skill registry 같은 공통 구조 재설계 필요.
- **Con**: 저자가 Strix/PentAGI 소스 보며 "따라치면 안 된다" 규율 유지 필요. 리뷰 단계 재확인.
- **Enforcement**: 새 모듈 전 "이 로직을 AGPL 프로젝트에서 본 적 있는가?" 자문. 있으면 스펙 수준에서 직접 설계 후 작성.
