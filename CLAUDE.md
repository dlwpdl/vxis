# VXIS — AI-Powered Autonomous Pentesting Platform

> CLAUDE.md는 얇게. 상세한 규칙은 해당 코드의 주석에.
> 여기엔 **워크플로우 · 절대 원칙 · 커맨드**만.

## 절대 원칙 — Brain-First

Brain (AI) = 시니어 펜테스터의 두뇌. 하드코딩된 공격 로직 금지.
Phase = { 분석 → 결정 → 실행 → 해석 → 다음 행동 } 루프. Brain이 체이닝해서 **Crown Jewel** (admin takeover · DB dump · RCE · data exfil) 까지.
정적 코드 grep 스코어링 금지 — 실제 타겟 동적 공격만.

```
Brain  = 두뇌 (분석·판단·전략)
Hands  = 손  (HTTP 요청)
Eyes   = 눈  (브라우저·JS)
X-Ray  = 투시 (트래픽 가로채기)
```

## Workflow

1. **Plan mode first.** 비자명한 작업은 계획부터. 스코프와 성공 기준을 명시한 프롬프트로 `/plan` 돌리고 ExitPlanMode 전에 **`/plan-review`** (8개 서브에이전트: architecture, coding-standards, UX, performance, security, testing, ops, docs — 각자 전용 레퍼런스 문서 `postgres_performance.md`, `python_threading.md`, `software_architecture.md` 등 참조).
2. **Phased commits.** 계획의 각 phase = 1 commit. 커밋마다 **`/code-review`** (같은 8개 에이전트 재사용) → 피드백을 내가 steer.
3. **TDD.** Brain·scoring·skills·pipeline 변경은 실패하는 테스트부터. `pytest tests/ -x --timeout=30` 로컬 확인.

## Git Workflow

- `main` 전용 push. feature 브랜치는 머지 후 삭제.
- 커밋 메시지: `phase-N: <what>` 또는 `feat(scope): <what>`. 본문에 **why**.
- `git commit -m` + HEREDOC. `--no-verify`·`--no-gpg-sign` 금지. pre-commit 실패 시 fix → **새** 커밋 (amend 금지).
- 한 번에 한 배치. PR 템플릿의 Summary / Test plan 채우기.

## Devex Conventions

- `Any` 금지 — Pydantic 런타임 검증.
- 텍스트 바이링구얼: `"English|||한국어"`. 한국어도 영어만큼 상세히.
- 리포트: NCC Group 스타일 단일 HTML, `ReportGenerator.generate_html_file()`.
- 네트워크: Hands/X-Ray/Controller/Finding 모듈. raw `httpx` 금지.
- AGPL 포크 금지 (Strix/PentAGI 등). 100% 자체 구현.
- 100% 공격 벡터 커버리지. Phase 건너뛰기 금지.
- Enterprise 스캔 시 인젝션은 **마지막**, yes/no 승인 후 실행.
- 코드 수정 후 자동 스캔 실행 금지 — 사용자 요청 시만.

## Project Tool Use

```bash
# Benchmark 타겟 기동 (Docker)
docker compose -f infra/benchmarks/juice-shop.yml up -d   # :3000
docker compose -f infra/benchmarks/webgoat.yml up -d      # :8080

# 풀 스캔
python -m vxis.cli scan --target http://localhost:3000 --mode enterprise

# 테스트
pytest tests/ -x --timeout=30
pytest tests/agent/test_scan_loop.py -k "not runs_to_finish"  # 스킵 flaky

# Growth loop (self-improving benchmark)
python scripts/growth_loop.py --weekly

# Smoke: Brain-First 경로
python scripts/smoke_brain_first.py --target http://localhost:3000

# 리포트 생성 (WebGoat/Juice Shop 벤치마크 템플릿)
python scripts/generate_benchmark_reports.py
```

## 파이프라인 구조 (14 active)

```
1 Foundation:     P0 Config → P1 Director
2 Recon:          P4 CPR → P15 Digital Twin → P13 Biometrics
3 Intelligence:   P2 Agents → P3 Hypothesis
4 Exploitation:   P5 Special → P7 Hardware
5 Chain Analysis: P8 Synthesis → P11 Mutation
6 Deferred (승인)
7 Report:         P6 NCC Style
8 Learning:       P12 Evolution → P18 Collective KB
```

GH Actions (외부): `cve-watch.yml`, `domain-intel.yml`, `upstream-watch.yml`, `growth-loop.yml`.

## 핵심 모듈 포인터 (상세 규칙은 해당 파일 주석)

- `src/vxis/agent/scan_loop.py` — Brain 루프, auto-login, 스킬 스케줄·sweep, chain nudge, finish_scan gate.
- `src/vxis/agent/tools/skill_runner.py` — 캐시 escalation (hit#1=soft nudge → #2=strong+untried list → #3+=BLOCK `ok=False`), `_skill_override` aliasing.
- `src/vxis/agent/skills/test_sensitive_files.py` — `_adjust_severity()` body-aware 오라클 (masked>60% → low, raw secret → critical).
- `src/vxis/agent/skills/test_injection.py` — `round=1|2|3` 페이로드 로테이션 (classic / blind+time / WAF-bypass+polyglot).
- `src/vxis/pipeline/scan_pipeline_v2.py` — `_compute_vxis_score()`, `_skill_to_vectors` 매핑. 새 스킬 추가 시 매핑 필수.
- `src/vxis/reports/report_generator.py` — NCC 스타일 HTML 렌더.

## Report Format (MANDATORY — 변경 금지)

템플릿: `scripts/generate_benchmark_reports.py` 의 `WEBGOAT_FINDINGS`.

- `Finding.id`: `타겟약어-NNN`
- `Finding.title` · `description` · `remediation`: `"English|||한국어"`
- `Finding.description` 섹션: **WHAT → HOW → IMPACT → PoC → ATTACK PATH** (한국어도 동일 순서)
- `Finding.remediation`: **Immediate / Short-term / Long-term** (한국어: 즉시 / 단기 / 장기)
- `Finding.evidence`: `list[Evidence]` — raw HTTP·log·packet
- `Finding.severity`: `critical|high|medium|low|informational`
- `Finding.cvss`: `CVSSVector(vector_string=..., base_score=...)` (절대 `cvss_score` 직접 전달 금지)
- `ReportData.client_name`: 영어 고정 (`|||` 금지)
- `ReportData.attack_chains`: `[["ID-001","ID-002"], ...]`
