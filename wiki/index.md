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

- [scan_loop](entities/modules/scan_loop.md) — Brain ReAct 루프 구조 / skill 스케줄·sweep / auto-login / chain nudge / finish_scan gate 조건
- [skill_runner](entities/modules/skill_runner.md) — run_skill 호출 캐시 / escalation 정책 / 중복 호출 방지 / _skill_override aliasing / SKILL_REGISTRY 접근점
- [brain](entities/modules/brain.md) — Brain LLM 호출 choke point / claude -p 우선 조건 / fallback chain / think() 엔트리 / token 카운터
- [hands](entities/modules/hands.md) — HTTP 세션·쿠키·CSRF 자동 관리 / 폼 파싱 / 멀티스텝 체인 / raw httpx 금지 정책
- [eyes](entities/modules/eyes.md) — Playwright 브라우저 / JS 실행 / DOM 분석 / SPA 대응 / 스크린샷 / 쿠키·스토리지 접근
- [xray](entities/modules/xray.md) — 트래픽 인터셉트·변조 / mitmproxy 연동 / 토큰·API 키 자동 추출 / 요청 리플레이 / 패시브 분석
- [report_generator](entities/modules/report_generator.md) — NCC 스타일 HTML 렌더 / generate_html_file 호출점 / bilingual 필터 / ReportData 스키마

### Pipelines

- [P0 Config](entities/pipelines/P0_config.md) — 스캔 설정 로드 / scan profile / target·mode·flag 파싱 / Pydantic 검증
- [P1 Director](entities/pipelines/P1_director.md) — 스캔 오케스트레이션 시작점 / 에이전트 선택 / 가설 큐 관리 / 미션 기반 전략
- [P2 Agents](entities/pipelines/P2_agents.md) — 60+ 전문 에이전트 레지스트리 / 에이전트 동적 스폰 / 도메인별 공격 특화
- [P3 Hypothesis](entities/pipelines/P3_hypothesis.md) — 가설 우선순위 큐 / probability·impact 스코어링 / 테스트 상태 FSM
- [P4 CPR](entities/pipelines/P4_cpr.md) — 초기 recon / Hands·Eyes·X-Ray 통합 / 타겟 인터랙션 entry / 기술 스택 지문
- [P5 Special](entities/pipelines/P5_special.md) — 특화 공격 스킬 실행 / SKILL_REGISTRY 호출점 / exploitation 본체 / skill_runner 와의 관계
- [P6 NCC Style](entities/pipelines/P6_ncc_style.md) — NCC 스타일 HTML 리포트 생성 / ReportData 구성 / bilingual 필수 필드 / Finding 직렬화
- [P7 Hardware](entities/pipelines/P7_hardware.md) — 하드웨어·물리 계층 공격 / DMA·콜드부트·사이드채널 에이전트 / 모바일·IoT 펌웨어
- [P8 Synthesis](entities/pipelines/P8_synthesis.md) — 공격 체인 합성 / 크로스레이어 연결 / 공격 트리 탐색 / 방어 시뮬레이션
- [P11 Mutation](entities/pipelines/P11_mutation.md) — 체인 변이 / 대안 경로 증명 / "부분 패치 허상" 검증 / NetworkX 그래프 탐색
- [P12 Evolution](entities/pipelines/P12_evolution.md) — 자기 진화 에이전트 합성 / 부족 능력 자동 생성 / 안전 검증 / 다음 미션 피드백
- [P13 Biometrics](entities/pipelines/P13_biometrics.md) — 행동 생체인식 OSINT / 직원 행동 패턴 분석 / GitHub·LinkedIn 공개 정보 / 피싱 타이밍
- [P15 Digital Twin](entities/pipelines/P15_digital_twin.md) — 사전 공격 리허설 / Docker 기술 스택 재현 / 공격 성공 확률 사전 평가 / 실타겟 소음 최소화
- [P18 Collective KB](entities/pipelines/P18_collective_kb.md) — 취약점 지식 베이스 / remediation·CWE·OWASP 매핑 / static lookup / 에이전트 추천

## Decisions

- [ADR-001 — No AGPL Forking](decisions/001_agpl_forbidden.md) — 외부 코드 참고 경계 / Strix·PentAGI 사용 금지 이유 / VXIS 라이센스 전략 / AGPL 오염 위험
- [ADR-002 — Brain LLM claude -p First](decisions/002_claude_p_first.md) — Brain LLM 호출 우선순위 / claude -p 서브프로세스 vs API / 다른 모델 벤치마크 예외
- [ADR-003 — No Raw httpx](decisions/003_no_raw_httpx.md) — HTTP 요청 작성 방법 / raw httpx 금지 이유 / Hands·X-Ray·Controller·Finding 모듈 사용 근거
- [ADR-004 — NCC Group Report Format](decisions/004_ncc_group_report_format.md) — 리포트 포맷 규칙 / Finding 필드 구조 / bilingual ||| 사용법 / WEBGOAT_FINDINGS 템플릿
- [ADR-005 — Dynamic Attack Only](decisions/005_dynamic_not_static.md) — 코드 grep 커버리지 측정 금지 이유 / 동적 스캔 필수 근거 / 스코어링 원칙
- [ADR-006 — Code Freeze + Data-Only Updates](decisions/006_code_freeze_data_only_updates.md) — 코드 수정 검토 / 데이터 vs 로직 분리 / 회귀 방지 / AI 할루시네이션 방지
- [ADR-007 — Payloads as External Data Files](decisions/007_payloads_as_data_files.md) — 페이로드 추가 위치 / skills 코드 freeze 전략 / round 로테이션 JSON화 / growth loop 재배선
- [ADR-008 — Finding Precision Bayesian Smoothing](decisions/008_finding_precision_smoothing.md) — 스코어 비교 시 FP 차원 해석 / 판정 수 부족 / baseline vs after 노이즈 / 측정 인프라 수정 정당화

## Sources

### Benchmarks
_(유기적 추가 — 새 스캔 리포트 요약)_

### Research
_(유기적 추가 — 외부 논문/블로그/CVE)_

### Incidents

- [2026-04-16 Seven Disconnections](sources/incidents/2026_04_16_seven_disconnections.md) — scan_loop 동작 이상 / chain 연쇄 안 됨 / skill cache 꼬임 / severity 정적 고정 / IDOR 자동 큐잉 누락
- [2026-04-16 Auto-login Fix](sources/incidents/2026_04_16_auto_login_fix.md) — auto-login 전체 실패 / BrowserPage.fill TypeError / Enter 키 미전달 / login pivot 메시지
- [2026-04-16 Payload Rotation + Sweep](sources/incidents/2026_04_16_payload_rotation_and_sweep.md) — payload rotation R2/R3 동작 / skill sweep 트리거 / _real_skills_completed / round re-queue alias
