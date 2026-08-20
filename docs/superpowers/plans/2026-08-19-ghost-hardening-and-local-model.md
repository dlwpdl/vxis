# 2026-08-19 — Ghost Egress 하드닝 + 로컬 모델/툴링 정리

작업 두 갈래를 한 곳에 정리한 기록. 현재 워킹트리엔 이 세션과 **무관한 미커밋 변경이 다수**(총 151 파일) 있으며, 아래는 그 중 이 두 워크스트림에 해당하는 것만 추린 것.

---

## A. Ghost Egress 하드닝 — fail-closed anonymity

목표: ghost 활성 시 직접(direct) egress가 **어느 경로로도 못 새게**, 사용 가능한 프록시가 없으면 조용히 직접 연결로 떨어지지 말고 **fail-closed**.

1. **verifier 직접연결 제거** — `ghost/verifier.py`
   `GhostVerifier.check()`가 raw `TargetSession` 대신 ghost 활성 시 `GhostTransport`를 주입. IP 확인이 프록시 exit IP를 검증하고, 프록시 없이 활성이면 fail-closed → 직접 IP를 "익명화 IP"로 오기록하지 않음.

2. **모든 direct fallback 중앙 차단** — `ghost/layer.py` + `ghost/transport.py`
   - `layer.py:21` `class GhostDirectEgressError`, `layer.py:29` `def direct_egress_allowed()` 신설(최하위 레이어).
   - `GhostTransport.handle_async_request`: ghost 활성 + 프록시 없음 + opt-in 아님 → 예외 차단. **모든 `TargetSession`이 지나는 단일 chokepoint**라 HTTP·체인·크롤·verifier 일괄 커버.
   - 명시적 예외는 `VXIS_ALLOW_DIRECT_EGRESS=1` 뿐 (`agent/egress_policy.py:55`).

3. **WebRTC/UDP 차단** — `interaction/eyes.py` + `agent/tools/browser_tools.py`
   - `eyes.py:48` `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` 상시 추가 → STUN UDP가 프록시 우회 불가.
   - `_ensure_browser`: ghost 활성인데 프록시 미해결이면 직접 브라우저 기동 fail-closed.

4. **셸/컨테이너 네트워크 격리** — `agent/egress_policy.py` + `agent/tools/shell_tools.py`
   - `egress_policy.py:19` `curl --noproxy` / `env -i` / `unset *proxy` 무력화 패턴 탐지.
   - `egress_policy.py:28` `__import__("socket")`, `importlib.import_module("subprocess")` 동적 import 우회 탐지.
   - `shell_tools.py:128` ghost 활성 시 샌드박스 `--network host` → `--network bridge` + `NET_RAW` 제거(원시 소켓 유출 차단). `docker exec` 경로 유지로 셸 기능은 보존.

5. **MCP·manifest·intercept 경로 통합**
   - `primitives/ghost.py`: `ghost_activate("off")`=비활성, 프록시 필요 프로파일이 사용가능 프록시 0개면 거부(`active=False` + error) — 빈 풀로 "활성" 오보 제거.
   - `cli/main.py` + `cli/multi_scan.py`: `--ghost`를 매니페스트 경로로 전파(웹 타겟 `ghost://` 프리픽스) — 멀티스캔 직접연결 누수 제거.
   - `agent/tools/proxy_runtime.py`: intercept replay(`repeat_request`)도 ghost 활성 시 `GhostTransport` 경유.

**검증**: ghost/egress 테스트 63건 green(로컬 재실행 확인). 작성자 보고 기준 신규/수정 80건 통과 — transport fail-closed+opt-in, verifier fail-closed, `--noproxy`/동적 import 차단, 샌드박스 network/caps, `ghost_activate` 정직성, WebRTC 플래그, manifest 전파.

---

## B. 로컬 모델 / 툴링 (오늘 세션)

1. **httpx 신원검증** — `plugins/base.py` + `plugins/recon/httpx_plugin.py`
   `PluginMeta`에 `binary_aliases`·`identity_marker`, `BasePlugin.resolve_binary()`가 `-version`으로 진짜 툴 확인. httpx는 `identity_marker="projectdiscovery"` + 별칭 `httpx-pd`/`httpx-toolkit`. Python `httpx` CLI가 PATH를 가려도 잘못 실행 대신 **깨끗이 스킵**(→ "unexpected error" 크래시 제거). 테스트 `tests/unit/test_binary_identity.py`.

2. **TUI 라이브 화면 깨짐 수정** — `cli/interactive.py` `_execute_scan`
   `logging.basicConfig`(stderr)가 Rich Live 위로 로그를 쏟던 것 → **로그 파일 라우팅**으로 교체(`main.py` 비대화식 경로와 동일). Live 무결.

3. **로컬 모델 repoint** — 6곳
   삭제된 `huihui-qwen3.6-35b-a3b`(a3b 3B-active + abliterated + q4) →
   - director = `Qwen3.8-27B-Uncensored-Q6_K` (`orcarouter/Qwen3.8-27B-Uncensored-GGUF`, dense 27B, Heretic 디센서, MTP)
   - worker = `CyberStrike-OffSec-35B` (레지스트리 등록, **worker 전용** 근거 주석: a3b + 포맷팅 LoRA + 자체평가 42% tool-routing)
   대상: `hybrid_config.py:45`, `model_registry.py`(엔트리 교체+CyberStrike 추가), `config/schema.py:546/550/554`, `brain.py:2195`, `interactive.py:95/2506`.

4. **디스크 정리** — huihui-qwen3.6(20GB) + huihui-CyberStrike 깨진 부분(861MB) 삭제.

**검증**: 관련 테스트 통과(잔여 huihui 참조는 테스트 fixture일 뿐 무해), lint 통과.

---

## 남은 것 (정직하게)

- **컨테이너 bridge 격리는 부분적**: bridge 격리는 프록시가 bridge에서 도달 가능할 때만(원격 프록시 또는 `host.docker.internal`; `127.0.0.1` 단독 불가) 익명화. 완전한 투명프록시 사이드카(transparent-proxy jail)는 인프라 작업이라 코드에서 검증 불가 → 미착수, `ponytail:` 주석으로 상한 명시.
- **원시 TCP/UDP 스캐너(nmap 등)는 HTTP/SOCKS 프록시로 익명화되지 않음** — `ghost_status_snapshot`이 `direct_raw_socket`로 이미 경고. 이번 `NET_RAW` 제거로 ghost 중에는 컨테이너에서 **아예 기동 차단**(익명화 대신 차단으로 fail-closed).
- **기존 실패 8건은 이 변경들과 무관** — 워킹트리에 이미 다수의 미커밋 변경이 있고(건드리지 않은 `preflight.py` httpx import, `model_registry.py`, `brain.py` 등), 이 수정을 stash로 제거해도 8건은 잔존(오히려 총 29건으로 증가) 확인.
- **로컬 모델은 다운로드/파일럿 전**(내일). 어떤 후보도 중립 tool-calling 벤치(BFCL/tau-bench) 없음 → scan_loop 배선 전 juice-shop/webgoat 파일럿 필수(TDD 규칙).

---

## 커밋 제안 (미실행 — 요청 시 실행)

> 주의: 트리에 무관 변경이 섞여 있어 파일 통째 `git add`는 위험. **hunk-level(`git add -p`)** 로 관련 훵크만 담는 걸 권장.

- `feat(ghost): fail-closed egress + verifier + WebRTC/UDP + sandbox isolation`
  → `ghost/{layer,transport,verifier}.py`, `primitives/ghost.py`, `agent/egress_policy.py`, `agent/tools/{shell_tools,proxy_runtime,browser_tools}.py`, `interaction/eyes.py`, `cli/{main,multi_scan}.py`, `agent/{egress,egress_contract}.py` + 관련 테스트
- `fix(recon): verify httpx is ProjectDiscovery, not the Python httpx CLI`
  → `plugins/base.py`, `plugins/recon/httpx_plugin.py`, `tests/unit/test_binary_identity.py`
- `fix(cli): route interactive scan logs to file so Rich Live isn't torn`
  → `cli/interactive.py` (로그 훵크)
- `chore(llm): repoint local llama.cpp default huihui→Qwen3.8-27B, register CyberStrike worker`
  → `hybrid_config.py`, `model_registry.py`, `config/schema.py`, `brain.py`, `interactive.py` (모델 훵크)

※ `interactive.py`는 `fix(cli)`와 `chore(llm)` **양쪽 훵크**를 담고 있어 hunk 분리 필요.
