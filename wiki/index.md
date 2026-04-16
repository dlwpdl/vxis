# VXIS LLM Wiki — Index

> wiki 의 카탈로그. 새 페이지 추가 시 해당 섹션에 한 줄.
> 형식: `- [<title>](<relative path>) — <when_to_read hint>`
> ↑ 한 줄 hint 는 페이지 frontmatter 의 `when_to_read` 를 그대로 가져오면 됨.
>
> 작성 규칙은 [CLAUDE.md](CLAUDE.md) 참조. 모든 페이지 = `핵심 사실` 표 + `TL;DR` + 본문.

## 카테고리 → 어떤 질문에 답하나

| 카테고리 | 어떤 질문에 답하나 | 위치 |
|---|---|---|
| Concepts | "X 는 왜·어떻게 동작?" 추상 원칙 | `concepts/` |
| Skills | "이 skill 무엇 하나·payload 어디·param" | `entities/skills/` |
| Modules | "이 모듈 책임·invariant" | `entities/modules/` |
| Pipelines | "P<N> 은 어느 단계·input/output" | `entities/pipelines/` |
| Decisions (ADR) | "왜 X vs Y 결정했나" | `decisions/` |
| Incidents | "옛날에 무슨 사고 났고 어떻게 풀었나" | `sources/incidents/` |
| Sources/Benchmarks | "스캔 결과 데이터" | `sources/benchmarks/` |
| Sources/Research | "외부 논문·CVE 요약" | `sources/research/` |

---

## Concepts

- [Brain-First Architecture](concepts/brain_first.md) — VXIS 절대 원칙 / 하드코딩 금지 이유 / Brain이 공격 주체여야 하는 근거 / claude -p 우선 조건
- [Chain Intelligence](concepts/chain_intelligence.md) — chain nudge 재주입 주기 / _desired 계산식 / finish_scan 거부 조건 / 체인 부족 시 동작
- [Payload Rotation](concepts/payload_rotation.md) — payload rotation 동작 / 새 페이로드 추가 위치 / WAF 우회 round 매핑 / clean 결과 re-queue
- [Severity Oracle (Content-Aware)](concepts/severity_oracle.md) — 정적 severity vs body-aware 조정 / Spring Actuator masked 판단 / raw secret critical 격상
- [VXIS Scoring Model — 5 Dimensions](concepts/scoring_model.md) — 5차원 가중치 / 벡터 ID 매핑 / 새 skill 추가 시 scoring 연결 / 등급 기준
- [Plan-Review and Code-Review Workflow](concepts/plan_review_workflow.md) — 비자명 작업 시작 절차 / 8 subagent 역할 / phased commit 규칙 / CLAUDE.md 길이 제한 근거
- [VXIS Architecture — Brain / Hands / Eyes / X-Ray](concepts/vxis_architecture.md) — 모듈 역할 분담 / raw httpx 금지 근거 / 어느 컴포넌트가 무엇 담당 / 파이프라인 진입점
- [AI Context Hygiene — 4 Principles](concepts/ai_context_hygiene.md) — context window 관리 원칙 / tool 결과 dump 금지 / wiki 가 RAG 구현인 이유 / 5-Loop 매핑

## Entities

### Skills

- [test_injection](entities/skills/test_injection.md) — SQLi/XSS/SSTI/CMDi payload rotation 동작 / round 구분 / time-based 감지 임계값
- [test_xss](entities/skills/test_xss.md) — XSS 전용 payload rotation / 필터 우회 / DOM/mXSS 페이로드 위치
- [enumerate_endpoints](entities/skills/enumerate_endpoints.md) — 120+ common paths blast / SPA baseline detection / accessible/auth_required 분류
- [attempt_auth](entities/skills/attempt_auth.md) — 로그인 우회 / default creds / SQLi bypass / password reset 체크 순서
- [post_auth_enum](entities/skills/post_auth_enum.md) — 인증 후 접근 가능 경로 / broken access control / IDOR 후보 탐지
- [test_sensitive_files](entities/skills/test_sensitive_files.md) — 노출 파일·백업·키 탐지 / body-aware severity 조정 / actuator masking
- [test_idor](entities/skills/test_idor.md) — IDOR sequential ID / auth bypass 탐지 / url_pattern {id} 템플릿
- [test_auth_deep](entities/skills/test_auth_deep.md) — JWT alg:none / RS→HS 혼동 / session fixation / password reset host poisoning
- [test_csrf](entities/skills/test_csrf.md) — CSRF 토큰 없이 state-changing 요청 허용 / SameSite 부재 / invalid token 허용
- [test_ssrf](entities/skills/test_ssrf.md) — SSRF URL 파라미터 탐지 / 클라우드 metadata / protocol smuggling / IP bypass
- [test_api_security](entities/skills/test_api_security.md) — Mass assignment / rate limiting / verb tampering / param pollution
- [test_misconfig](entities/skills/test_misconfig.md) — 보안 헤더 부재 / CORS / debug endpoint / verbose error / server version
- [test_business_logic](entities/skills/test_business_logic.md) — 음수 수량·가격 0·정수 overflow·coupon 재사용·state skip·race condition
- [test_crypto](entities/skills/test_crypto.md) — TLS 약한 버전 / JS 번들 하드코드 시크릿 / MD5/SHA1 해시 노출
- [test_infra](entities/skills/test_infra.md) — .git / .env 노출 / 클라우드 metadata / 서브도메인 DNS / Firebase public

### Modules
_(Phase 4 시드 예정 — scan_loop, skill_runner, report_generator, brain, hands, eyes, xray)_

### Pipelines
_(Phase 4 시드 예정 — P0/P1/P2/P3/P4/P5/P6/P7/P8/P11/P12/P13/P15/P18)_

## Decisions
_(Phase 5 시드 예정 — agpl_forbidden, claude_p_first, no_raw_httpx, ncc_group_report_format, dynamic_not_static)_

## Sources

### Benchmarks
_(유기적 추가 — 새 스캔 리포트 요약)_

### Research
_(유기적 추가 — 외부 논문/블로그/CVE)_

### Incidents
_(Phase 5 시드 예정 — 2026_04_16_seven_disconnections, auto_login_fix, payload_rotation_and_sweep)_
