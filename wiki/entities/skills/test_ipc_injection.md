---
name: test_ipc_injection
type: skill
status: active
when_to_read: macOS XPC service 위협 / Mach service typosquat 탐지 / writable XPC bundle / DESK-IPC-001 의미
updated: 2026-04-23
sources:
  - ../../../src/vxis/agent/skills/desktop/test_ipc_injection.py
  - ../../../src/vxis/scoring/vectors.py
related:
  - ../../concepts/cross_surface_synthesis.md
  - ../modules/scan_loop.md
  - ./test_binary_protections.md
code_anchors:
  - src/vxis/agent/skills/desktop/test_ipc_injection.py:execute
  - src/vxis/scoring/vectors.py:DESK-IPC-001
---
# test_ipc_injection

## 핵심 사실
| 항목 | 값 |
|---|---|
| Surface | desktop (macOS) |
| 벡터 ID | DESK-IPC-001 |
| 탐지 1 | Writable XPC bundle (group/world-writable) → privilege escalation via bundle replacement (high) |
| 탐지 2 | Mach service name 이 `com.apple.*` 인데 bundle ID 가 `com.apple.*` 아님 → IPC 가로채기 (medium) |
| 검사 위치 | `<root>/Contents/XPCServices/*.xpc/Contents/Info.plist` (최대 6 단계 위로 .app root 자동 해결) |
| Subprocess 사용 | 없음 — 순수 `os.stat()` + `plistlib` (빠르고 안전) |
| 도입 commit | `3ff0e57`, 2026-04-23 |
| 테스트 | `tests/agent/skills/desktop/test_ipc_injection.py` (6/6 green) |

## TL;DR
.app 안의 XPC services 두 가지 위협 표면을 본다. (1) bundle dir 이 group/world-writable 이면 launchd 가 다음에 띄우기 전에 공격자가 바이너리/plist 갈아끼울 수 있다. (2) Mach service name 이 Apple namespace (`com.apple.*`) 를 사칭하면 system daemon 인 척 IPC 메시지 가로챈다. 둘 다 macOS desktop pipeline 의 첫 IPC 공격 벡터.

## Params
| 이름 | 타입 | 기본 | 설명 |
|---|---|---|---|
| `target_url` | str | 필수 | .app 번들·디렉토리·바이너리 경로. 자동으로 .app root 까지 climb |

## Known Limitations
- XPCServices 가 없는 .app (단순 GUI) 은 `tested=0` 으로 즉시 종료.
- Login items / launchd plist 는 별도 skill (미구현) — 이 스킬은 in-bundle XPC 만.
- non-darwin 에서도 코드 자체는 동작하지만 XPCServices 레이아웃이 macOS 전용 → `tested=0`.

## Source Files
- `src/vxis/agent/skills/desktop/test_ipc_injection.py` — `execute()`, `_resolve_app_root()`, `_check_writable()`, `_check_typosquat()`
- `src/vxis/scoring/vectors.py` — DESK-IPC-001 벡터 등록
- `src/vxis/pipeline/scan_pipeline_v2.py` — `_DESKTOP_SKILL_TO_VECTORS` 매핑 (`test_ipc_injection` → `["DESK-IPC-001"]`)
