---
name: test_binary_protections
type: skill
status: active
when_to_read: macOS Mach-O 메모리 안전성 / PIE / stack canary / __RESTRICT segment / DYLD_INSERT_LIBRARIES 차단
updated: 2026-04-23
sources:
  - ../../../src/vxis/agent/skills/desktop/test_binary_protections.py
  - ../../../src/vxis/scoring/vectors.py
related:
  - ../../concepts/cross_surface_synthesis.md
  - ../modules/scan_loop.md
  - ./test_ipc_injection.md
code_anchors:
  - src/vxis/agent/skills/desktop/test_binary_protections.py:execute
  - src/vxis/scoring/vectors.py:DESK-PIE-001
---
# test_binary_protections

## 핵심 사실
| 항목 | 값 |
|---|---|
| Surface | desktop (macOS) |
| 벡터 ID | DESK-PIE-001 / DESK-PIE-002 / DESK-PIE-003 |
| DESK-PIE-001 (high) | MH_PIE 부재 → ASLR 미적용 → ROP 결정적 |
| DESK-PIE-002 (high) | `__stack_chk_guard` 부재 → stack BoF 가 ret addr 덮어써도 미탐 |
| DESK-PIE-003 (medium) | `__RESTRICT,__restrict` segment 부재 → non-Hardened-Runtime 빌드의 DYLD 인젝션 차단 무력 |
| 사용 도구 | `otool -hv` (PIE), `nm` (canary), `otool -l` (restrict) — Xcode CLI tools 필요 |
| Graceful skip | 도구 부재 시 `tested=0 + skipped_reason` 으로 우아하게 종료 |
| 도입 commit | `89235e8`, 2026-04-23 |
| 테스트 | `tests/agent/skills/desktop/test_binary_protections.py` (7/7, subprocess mocked) |

## TL;DR
Mach-O 바이너리의 3개 기초 메모리 안전 플래그 — PIE/stack canary/__RESTRICT — 를 한 번에 점검. .app 번들이 들어오면 `Contents/MacOS/<binary_name>` 으로 자동 해결. otool/nm 가 없으면 우아하게 skip. 서명·entitlement 와 함께 macOS 정적 보호 audit 의 한 축.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | .app 번들·디렉토리·Mach-O 바이너리. .app 이면 `Contents/MacOS/<bin>` 자동 해결 (6 단계 위로) |

## Known Limitations
- otool/nm 외부 의존 — Xcode Command Line Tools 미설치 환경에서는 `skipped_reason="otool unavailable"`.
- Universal binary (fat) 의 경우 `otool -hv` 가 모든 arch 출력 — 첫 arch 의 PIE flag 만 본다.
- `__stack_chk_guard` 가 stripped 된 release 빌드에서 false-negative 가능 (nm 가 심볼 못 봄).
- Hardened Runtime 빌드는 DYLD 인젝션이 OS 차원에서 차단되므로 DESK-PIE-003 은 의미가 없을 수 있음 — 별도 entitlement audit 와 cross-check 권장.

## Source Files
- `src/vxis/agent/skills/desktop/test_binary_protections.py` — `execute()`, `_resolve_binary()`, `_check_pie()`, `_check_canary()`, `_check_restrict()`
- `src/vxis/scoring/vectors.py` — DESK-PIE-001/002/003 벡터 등록 (commit `3ff0e57` 에서 stub, `89235e8` 에서 활성화)
- `src/vxis/pipeline/scan_pipeline_v2.py` — `_DESKTOP_SKILL_TO_VECTORS` 매핑
