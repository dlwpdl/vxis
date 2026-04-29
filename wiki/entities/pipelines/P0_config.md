---
name: P0 Config
type: pipeline
status: active
when_to_read: 스캔 설정 로드 / scan profile / target·mode·flag 파싱 / Pydantic 검증
updated: 2026-04-16
sources:
  - ../../../src/vxis/config/schema.py
  - ../../../src/vxis/config/client_manager.py
related:
  - ./P1_director.md
  - ../modules/scan_loop.md
code_anchors:
  - src/vxis/config/schema.py:VXISConfig
  - src/vxis/config/schema.py:ScanProfile
  - src/vxis/config/client_manager.py
---
# P0 — Config

## 핵심 사실
| 항목 | 값 |
|---|---|
| Group | 1 Foundation |
| 앞 단계 | (없음 — entry point) |
| 뒤 단계 | P1 Director |
| 역할 | 스캔 설정 로드·검증 |
| 출력 | `VXISConfig` + `ScanProfile` + target·mode |
| 검증 | Pydantic Settings v2 (env + .env) |

## TL;DR
CLI args / env / .env 를 Pydantic 으로 검증해 `VXISConfig` 생성. scan profile (rate_limit, concurrency, nmap_timing 등) 이 후속 파이프라인 pacing 기준. 잘못된 config 는 스캔 시작 전 fail-fast.

## Stage
Foundation — 모든 파이프라인의 선행 조건. config 없이 P1 진입 불가.

## Inputs-Outputs
- Input: CLI args (`--target`, `--mode`), env vars, `.env` 파일, `clients/<name>.yaml`.
- Output: `VXISConfig` 인스턴스 (scan_profile, tool_settings, client_config, credentials).

## Triggers
- `python -m vxis.cli scan ...` 진입 시 cli/main.py 가 가장 먼저 호출.
- `VXISConfig()` 인스턴스화가 trigger.

## Related Pipelines
- [P1 Director](./P1_director.md) — 뒤 단계, 이 config 를 받아 오케스트레이션 시작
