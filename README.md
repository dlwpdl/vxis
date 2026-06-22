# VXIS — AI-Powered Autonomous Pentesting Platform

> Strix-parity single-loop Brain-First pentesting. Build what a senior penetration tester does, but run it autonomously against any target.

## What is VXIS?

VXIS is an autonomous penetration testing platform where a single LLM "Brain" (via ReAct loop) drives an entire security assessment end-to-end. It uses real scanner binaries (sqlmap, nuclei, ffuf, nikto, gobuster) inside a Docker sandbox plus custom Python scripts — just like a human red-team engineer would — instead of hardcoded phase pipelines.

## Core principle — Brain-First

```
Phase 시작
  → Brain이 타겟 현재 상태 분석
  → Brain이 공격 전략 결정
  → Brain이 페이로드 생성
  → Hands/Eyes/X-Ray 또는 shell_exec/python_exec로 실행
  → 결과를 Brain이 해석
  → 다음 행동을 Brain이 결정
  → 체이닝하여 Crown Jewel까지 도달
Phase 완료
```

**금지**: 하드코딩된 엔드포인트/페이로드, Brain 없이 코드 로직만으로 공격, Brain을 "헬퍼"로 취급.
**필수**: Brain이 매 iteration의 핵심 의사결정자.

## Architecture at a glance

```
User → CLI (src/vxis/cli/main.py)
     → ScanPipeline (src/vxis/pipeline/scan_pipeline_v2.py)  ← Phase A thin shim
       → ScanAgentLoop (src/vxis/agent/scan_loop.py)         ← persistent messages
         → AgentBrain.think_in_loop (src/vxis/agent/brain.py) ← ReAct decision
           → ToolRegistry.dispatch                            ← 11 BrainTools
             ├── Control: finish_scan / think / wait
             ├── Hands/Eyes/X-Ray: http_request / browser_render / intercept_proxy
             ├── Strix-power:   shell_exec / python_exec      ← Docker sandbox
             └── Finding CRUD:  report_finding / query_findings / link_chain
           → ScanContext (findings + chains + score)
     → ReportGenerator → NCC-style HTML report
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the detailed design rationale, and [`PHASE_STATUS.md`](PHASE_STATUS.md) for the migration roadmap status.

## Quick start

```bash
# 1. Install dependencies
poetry install

# 2. Build the Strix-power sandbox image (one-time, ~10 min, ~980MB)
docker build -t vxis/sandbox:latest docker/sandbox/

# 3. Run a scan
poetry run vxis scan http://localhost:3000 --profile standard --output reports/juice.html
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

Full rules → [`CLAUDE.md`](CLAUDE.md)
