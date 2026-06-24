# VXIS - Autonomous Security Validation Assistant

> Authorized system -> evidence-guided validation -> reproducible findings -> bilingual report. VXIS learns from Strix-style agent UX, but it is not a Strix clone; the v1 product is a narrow, deep helper for security verification.

## What is VXIS?

VXIS is an autonomous security validation assistant for authorized web black-box assessments. A single LLM "Brain" drives the scan loop, uses browser/proxy/HTTP tools plus sandboxed scanner binaries, validates high-value findings, connects related evidence, and produces professional bilingual reports.

The public v1 surface is intentionally small:

- Web black-box validation scan
- Bug bounty helper profile and replayable PoC export
- Verifier-backed findings and evidence gates
- NCC-style bilingual HTML report
- Reproducible benchmark notes
- MCP scan integration

Source-aware, mobile, game, hardware, and cloud-console runtimes stay in planned/incubator status until they have working runtime tools, scope gates, report evidence, benchmark coverage, and regression tests.

## Core principle - verified Brain-First

```
Phase 시작
  → Brain이 허가된 범위의 현재 상태 분석
  → Brain이 검증 전략 결정
  → Brain이 재현 절차와 확인 요청 생성
  → Hands/Eyes/X-Ray 또는 shell_exec/python_exec로 실행
  → 결과를 Brain이 해석
  → 다음 행동을 Brain이 결정
  → 관련 증거를 연결하여 영향 범위 확인
Phase 완료
```

**금지**: 하드코딩된 엔드포인트/페이로드, Brain 없이 코드 로직만으로 검증, Brain을 단순 "헬퍼"로 축소.
**필수**: Brain이 매 iteration의 핵심 의사결정자이며, high/critical finding은 재현 가능한 evidence contract를 통과해야 함.

## Architecture at a glance

```
User → CLI (src/vxis/cli/main.py)
     → ScanPipeline (src/vxis/pipeline/scan_pipeline_v2.py)  ← Phase A thin shim
       → ScanAgentLoop (src/vxis/agent/scan_loop.py)         ← persistent messages
         → AgentBrain.think_in_loop (src/vxis/agent/brain.py) ← ReAct decision
           → ToolRegistry.dispatch                            ← 11 BrainTools
             ├── Control: finish_scan / think / wait
             ├── Hands/Eyes/X-Ray: http_request / browser_render / intercept_proxy
             ├── Sandbox:       shell_exec / python_exec      ← Docker scanner sandbox
             └── Finding CRUD:  report_finding / query_findings / link_chain
           → ScanContext (findings + chains + score)
     → ReportGenerator → NCC-style HTML report
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the detailed design rationale, and [`PHASE_STATUS.md`](PHASE_STATUS.md) for the migration roadmap status.

## Quick start

```bash
# 1. Install dependencies
uv sync --extra dev --extra export

# 2. Build the sandbox image (one-time)
docker build -t vxis/sandbox:latest docker/sandbox/

# 3. Run the deep validation profile
uv run vxis scan http://localhost:3000 --profile crown --output reports/juice.html

# 4. Run bug bounty helper mode and export accepted PoCs
uv run vxis scan http://localhost:3000 --profile bugbounty --output reports/juice-bb.html
uv run vxis export <scan_id> --format bugbounty --output reports/juice-bugbounty.json
```

**Benchmark targets** (Docker-local):
- Juice Shop: `docker run -d -p 3000:3000 bkimminich/juice-shop`
- WebGoat: `docker run -d -p 8080:8080 webgoat/webgoat`

## Top-level structure

| Path | Purpose |
|---|---|
| `src/vxis/` | Core library (30+ submodules — see [`src/vxis/README.md`](src/vxis/README.md)) |
| `docker/sandbox/` | Dockerfile for the Strix-power sandbox image (sqlmap/nuclei/ffuf/…) |
| `docs/` | Project documentation — [`BLUEPRINT.md`](docs/BLUEPRINT.md), [`CONFIGURATION.md`](docs/CONFIGURATION.md), etc. |
| `docs/superpowers/plans/` | Current implementation plan only |
| `docs/superpowers/DECISIONS.md` | Dated project decisions and why they were made |
| `docs/superpowers/benchmarks/` | Benchmark capture + scan artifacts |
| `incubator/` | Experimental work that is not production-wired yet |
| `tests/` | pytest suite (unit + agent + pipeline + slow) |
| `alembic/` | Database migrations (SQLAlchemy + Alembic) |
| `scripts/` | Operational scripts |
| `tools/` | Local dev tools |
| `reports/` | Generated HTML reports (gitignored) |
| `logs/` | Runtime logs (gitignored) |

## Project rules (CLAUDE.md must-read)

- `any` 타입 사용 금지 — Zod/Pydantic 런타임 검증
- 모든 텍스트 **bilingual** — `"English|||한국어"`
- 리포트는 항상 **NCC Group 스타일** 단일 HTML (VXIS ReportGenerator)
- 외부 펜테스트 툴 포크 금지 — 100% 자체 구현 (Strix·PentAGI 등은 permissive 라이선스지만 own-IP 위해 개념만 참고)
- Hands/X-Ray/Controller/Finding 모듈 사용, raw `httpx` 금지
- Enterprise 스캔 시 injection은 마지막에 **approval gate** 필수
- public surface는 실제 runtime/test가 있는 기능만 노출

Full rules → [`CLAUDE.md`](CLAUDE.md)
