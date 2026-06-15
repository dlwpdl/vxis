---
name: ADR-014 — Moat Strategy & Dead-Code Guardrail
type: decision
status: active
when_to_read: vxis 진짜 차별점이 뭔지 / 무엇을 마케팅·벤치마크·README·피치에 써도 되는지 / Strix 약점 공략 / 안 싸울 곳 / NOW-NEXT-LATER 우선순위
updated: 2026-06-15
sources:
  - upstream-sync 26-agent workflow (run wakog40lq, 2026-06-15)
  - moat-strategy 18-agent workflow (run wchxz0770, 2026-06-15)
  - tools/upstream_watch/proposals/2026-06-15.{json,md}
related:
  - ./001_agpl_forbidden.md
  - ./012_verifier_spine.md
  - ./013_profile_scan_policy.md
---
# ADR-014 — Moat Strategy & Dead-Code Guardrail

## 핵심 사실
| 항목 | 값 |
|---|---|
| Status | Accepted (2026-06-15) |
| 검증 집계 | moat 주장 12개 → solid-moat **2** / build-first **10** / illusory 0 |
| 지금 사실인 강점 | ① 실행되는 적대적 verifier ② desktop/cross-surface 1급 시민 |
| 죽은 코드 (마케팅·벤치 금지) | P15 twin · P12 evolution(**DROP**) · P13 biometrics · white-box CODE 융합 · capability-ceiling |
| 안 싸울 곳 | "AI 펜테스터"·멀티에이전트 스웜·provider-agnostic·블랙박스 웹 SaaS(XBOW)·툴허브(HexStrike)·Shannon 화이트박스 벤치 |
| NOW 순서 | verifier FP-gate → box-mode 하드강제 → TUI box/profile/공격레벨 |
| 외부 라이선스 | Strix=Apache-2.0, PentAGI/pentest-ai-agents/pentestagent=MIT (전부 非AGPL — ADR-001 라이선스 기록 정정 필요, 개념참고 자유) |

## TL;DR
경쟁 지형의 대부분 축(AI 펜테스터·스웜·provider-agnostic·블랙박스 웹)은 레드오션. vxis의 유일한 방어가능 wedge = **(cross-surface 비웹) ∩ (executable 검증) ∩ (bilingual NCC 리포트) ∩ (capability governance)** 의 교집합. 단 이 중 상당수가 **현재 죽은 코드**다. **지금 당장 사실인 moat는 2개뿐**이고, 나머지는 "방향은 맞지만 만들어야 함". 죽은 코드 5개는 wire + 통합테스트 전까지 어떤 피치/벤치마크/README에도 쓰지 않는다.

## Context
2026-06-15 두 개의 멀티에이전트 워크플로우로 (a) Strix/PentAGI/pentest-ai-agents/pentestagent 업스트림 델타와 (b) 전체 AI-pentest 지형 대비 vxis moat를 적대적 검증까지 거쳐 분석. 사용자 directive: "성숙도가 낮으니 추적은 하되 결국 밟고 올라가야 한다. strix만 쫓으면 의미없다."

## Decision

### 1. 지금 사실인 강점 (solid-moat ×2) — 여기에 집중
1. **실행되는 적대적 verifier + refuted-memory firewall** (`agent/tools/verifier_tools.py`). Strix의 "zero FP"는 `idor.md`/`ssrf.md`에 붙인 마크다운 2줄(커밋 6942ecb)이 전부 — `.py` 검증기 0개, dedupe는 자기 confidence 무시(`reporting/tool.py:243`). vxis는 finding-type별 executable refute gate가 코드로 동작. → *"저들의 FP 제어는 마크다운 한 문장, 우리는 실행 오라클."*
2. **desktop/cross-surface 1급 시민** (`agent/skills/desktop/*` + DESKTOP gate + `_DESKTOP_SKILL_TO_VECTORS` + pivot graph + `DesktopTargetLauncher`). Strix는 웹 전용이라 `.app`/XPC plist/Mach-O를 탐지조차 못 함(미해결 이슈 #550/#551).

### 2. 죽은 코드 — wire + 통합테스트 전까지 마케팅/벤치마크/README 금지 (×5)
| 항목 | 상태 | 처리 |
|---|---|---|
| P15 Digital Twin (`twin/simulator.py`) | caller 0, phantom registry, 기본 dry_run | wire OR 언급 금지 |
| P12 Evolution (`evolution/agent_synthesizer.py`) | caller 0, generate-and-shelf, LLM코드 실행 위험 | **DROP + registry 엔트리 삭제** |
| P13 Biometrics (`biometrics/analyzer.py`) | 엔진 작동, caller 0 (가장 참신) | days로 wire 가능 |
| White-box CODE 융합 (`interaction/code/` + `code_to_hypothesis.py`) | caller 0, multi_scan서 skip | fix-then-keep (= gap#1) |
| Capability-ceiling (`agent/policy/`) | attach만, enforcement 0 (`scan_pipeline_v2.py:707` 주석이 자백) | wire (= box-mode와 동일) |

부수 결함: cross-surface synth는 Finding↔Evidence 타입 미스매치로 출력 null; P18 "collective"는 brain에 미전달로 early-return; ADR-012 Gap1(verifier high/critical 한정) 열려 있음.

### 3. Strix 약점 공략 포인트
FP가 코드 아닌 산문 · dedupe가 confidence 무시(진짜 finding 삭제) · 글로벌 비용상한 없음(per-agent max_turns=500, 무제한 fan-out) · 웹 전용 · OSS 리포트 thin+영어전용(PDF는 closed) · 0.x vendor SDK 종속(3개월 4패치) · 코드강제 안전장치 0 · 텔레메트리 2곳 phone-home.

### 4. 안 싸울 곳 (parity만 유지)
"AI 펜테스터"/스웜 헤드라인/provider-agnostic 브레드스/블랙박스 웹 SaaS(XBOW 자본전)/툴허브 150개(HexStrike)/Shannon 화이트박스 벤치 숫자. Brain-First도 셀링포인트 아님(공유 thesis) — verifier를 받치는 substrate로만.

### 5. 로드맵
- **NOW**: ① verifier 전 severity + 단일 chokepoint + UNCONFIRMED 제외 + CI FP-rate 게이트 (ADR-012 Gap1) ② capability-ceiling + box-mode 하드강제 결선 + cassette test ③ TUI box/profile/공격레벨 + live bilingual 리포트 증명
- **NEXT**: 글로벌 cost governor · desktop 동적확인+cross-surface fix · white-box 융합(gap#1)
- **LATER**: self-improvement 수렴 · twin/biometrics 결정 · evolution DROP

## Consequences
- **Pro**: 차별화 자원을 레드오션이 아닌 교집합 wedge에 집중. 죽은 코드 가드레일로 신뢰성 보호.
- **Pro**: verifier FP-rate 숫자 = 시장 전체가 주장만 하고 아무도 증명 못 하는 지표를 코드로 증명.
- **Con**: solid moat가 2개뿐 — moat 서사는 build-first 완료 전까지 절제.
- **Enforcement**: 새 기능을 피치/벤치마크에 넣기 전 "이게 통합테스트로 wire돼 실제 스캔에서 도는가?" 자문. twin/evolution/biometrics/CODE융합/capability-ceiling은 현재 답이 No.
