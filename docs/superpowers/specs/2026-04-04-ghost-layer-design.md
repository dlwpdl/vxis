# GhostLayer Design Spec
**Date:** 2026-04-04
**Status:** Approved

---

## 1. 목적

VXIS가 내부 레드팀 훈련(블랙박스)에서 실제 외부 공격자처럼 보이도록, 모든 스캔 트래픽을 최대한 익명화한다.
블루팀은 공격 출처를 식별할 수 없어야 하며, 탐지/대응 역량을 실제 공격 시나리오 기준으로 측정할 수 있어야 한다.

---

## 2. 트리거 (4가지 — 모두 동일한 GhostLayer.activate() 호출)

**우선순위:** OR 로직 — 4가지 중 하나라도 해당하면 활성화.

| 방법 | 예시 | 파싱 위치 |
|------|------|-----------|
| CLI flag | `python scripts/auto_pentest.py https://target.com --ghost` | `auto_pentest.py` argparse `--ghost` 플래그 |
| URL prefix | `ghost://target.com` → `https://target.com` 으로 정규화 | `parse_ghost_trigger()` in `ghost/trigger.py` |
| Mission Config | `stealth = true` (TOML) | `MissionConfig.stealth` (이미 존재) |
| Brain 자연어 | "ghost mode로 스캔해", "익명화", "stealth scan" | `agent/brain_interactive.py` 입력 전처리 단계 |

`ghost://` URL은 항상 `https://`로 변환. (`http://`가 명시된 경우에만 `http://` 유지 — 미지원.)

---

## 3. 아키텍처

```
Phase 0 (AgentExecutor.run):
    GhostLayer.check_and_activate(target, config)
        ├── URL prefix 감지 (ghost://)
        ├── MissionConfig.stealth 확인
        └── activate() → GhostLayer._active = True

    이후 SessionManager.get_session() → TargetSession 생성 시
        GhostLayer.is_active() 확인 → GhostTransport 주입

Phase 1~N:
    모든 요청이 GhostTransport 경유
        ├── 프록시 rotation (풀에서 랜덤 선택)
        ├── TLS 핑거프린트 (curl_cffi Chrome/Firefox)
        ├── UA rotation (20종 풀)
        ├── 정규분포 딜레이 (μ=3s, σ=2s, min=0.5s)
        └── 브라우저 헤더 복제
```

### 모듈 구조

```
src/vxis/ghost/
    __init__.py
    layer.py          ← GhostLayer 싱글턴
    transport.py      ← GhostTransport (httpx AsyncBaseTransport 구현)
    ua_pool.py        ← User-Agent 풀 (20종 실제 브라우저)
    trigger.py        ← 키워드/URL/config 트리거 파싱 유틸
```

---

## 4. 컴포넌트 상세

### 4.1 GhostLayer (싱글턴)

```python
class GhostLayer:
    _active: bool = False
    _proxy_pool: list[str] = []   # 비어있으면 직접연결 fallback
    _ua_pool: list[str]           # ua_pool.py에서 로드
    _timing: GhostTiming          # μ, σ, min_delay

    def activate(self, proxy_pool: list[str] = []) -> None
    def deactivate(self) -> None
    def is_active(self) -> bool
    def next_proxy(self) -> str | None   # round-robin
    def next_ua(self) -> str             # random
    def next_delay(self) -> float        # 정규분포 샘플링
```

### 4.2 GhostTransport (httpx AsyncBaseTransport)

**Transport 주입 방식:** `TargetSession.__init__`에 `transport: httpx.AsyncBaseTransport | None = None` 파라미터 추가.
`GhostLayer.is_active()`이면 `SessionManager.get_session()`이 `transport=GhostTransport(ghost_layer)` 를 전달.
기존 `proxy: str | None` 파라미터는 유지 (ghost 비활성 시 사용).

**curl_cffi 처리:**
```
try:
    import curl_cffi.requests → Chrome TLS 핑거프린트 impersonation
except ImportError:
    log WARNING "curl_cffi 미설치 — TLS 핑거프린트 익명화 비활성"
    httpx.AsyncHTTPTransport(proxy=proxy_url) fallback
```
- curl_cffi는 선택 의존성 (`pip install vxis[ghost]` 또는 단독 설치)
- 미설치여도 UA/타이밍/헤더 익명화는 정상 작동

**요청마다:**
1. `GhostLayer.next_proxy()` → httpx transport에 주입
2. `GhostLayer.next_ua()` → `User-Agent` 헤더 오버라이드
3. 브라우저 헤더 세트 적용 (Accept, Accept-Language, Accept-Encoding, Sec-Fetch-* 등)

### 4.3 UA Pool

실제 Chrome/Firefox/Safari/Edge 최신 UA 20종. OS는 Windows/macOS/Linux 혼합.
요청마다 랜덤 선택. 동일 세션 내에서도 변경 가능.

### 4.4 타이밍

```python
@dataclass
class GhostTiming:
    mean: float = 3.0    # 초
    sigma: float = 2.0
    min_delay: float = 0.5
    max_delay: float = 15.0
```

`random.gauss(mean, sigma)`를 clamp(min, max).

**`TargetSession._throttle()` 통합:**
- `GhostLayer.is_active()`이면: `max(GhostLayer.next_delay(), self._min_delay)` 사용 (WAF 적응 딜레이와 ghost 딜레이 중 더 큰 값)
- ghost 비활성 시: 기존 `self._min_delay` 로직 그대로
- WAF 감지로 `self._min_delay`가 증가해도 ghost 최솟값(0.5s)은 항상 보장

### 4.5 트리거 — Brain 자연어 감지

`brain_interactive.py`에서 사용자 입력에 다음 키워드 포함 시 `GhostLayer.activate()`:
- 영어: `ghost`, `stealth`, `anonymous`, `anonymize`
- 한국어: `익명`, `스텔스`, `고스트`

감지 시 응답에 `[GHOST MODE ACTIVATED]` 표시.

---

## 5. Phase 0 통합 (AgentExecutor) + 싱글턴 라이프사이클

### 5.1 Phase 0 코드

```python
# Phase 0 시작부에 추가 (CPR 인터랙션 레이어 이전)
from vxis.ghost.layer import ghost_layer
from vxis.ghost.trigger import parse_ghost_trigger

ghost_activated, clean_target = parse_ghost_trigger(target, self._config)
if ghost_activated:
    proxy_pool = getattr(self._config, "proxy_pool", [])
    ghost_layer.activate(proxy_pool)
    logger.info("[Ghost] 익명화 모드 활성화 — 프록시: %d개", len(proxy_pool))
    target = clean_target  # ghost:// 제거된 clean URL
    self._ghost_activated_here = True  # 스캔 종료 시 deactivate 위해 추적
```

스캔 종료 시 `AgentExecutor.run()` finally 블록에서:
```python
if getattr(self, "_ghost_activated_here", False):
    ghost_layer.deactivate()
```

`parse_ghost_trigger`는:
1. `target.startswith("ghost://")` 확인 → `https://` 로 변환
2. `config.stealth == True` 확인
3. 둘 중 하나라도 해당하면 `(True, cleaned_url)` 반환

### 5.2 싱글턴 라이프사이클

```
AgentExecutor.run() 시작
    → Phase 0: parse_ghost_trigger() → ghost_layer.activate()
    → Phase 1~N: ghost_layer.is_active() == True
                 SessionManager → TargetSession(transport=GhostTransport)
    → Scan 종료: ghost_layer.deactivate()
```

**동시 스캔:** `ghost_layer`는 프로세스 레벨 싱글턴. 동시에 여러 스캔이 실행되는 경우, 하나라도 ghost 활성화하면 전체 적용.
현재 VXIS는 단일 프로세스 단일 스캔이 기본 사용 패턴이므로 허용 가능. 향후 multi-scan 지원 시 per-scan 컨텍스트로 리팩토링.

---

## 6. 익명화 스택 (최대)

| 레이어 | 구현 | Fallback |
|--------|------|----------|
| IP | 프록시 풀 round-robin | 직접 연결 |
| TLS 핑거프린트 | curl_cffi Chrome impersonation | httpx 기본 |
| User-Agent | 20종 랜덤 rotation | Chrome 최신 고정 |
| 타이밍 | 정규분포 딜레이 | 0.5s 고정 |
| 헤더 | 브라우저 Accept/Accept-Language/Accept-Encoding | 기존 헤더 |

---

## 7. MissionConfig 변경 (최소)

`stealth: bool` 이미 존재. `proxy_pool: list[str] = []` 필드만 추가.

```toml
[mission]
target = "https://kinetics-dev.protopie.works"
stealth = true
proxy_pool = ["socks5://1.2.3.4:1080", "http://5.6.7.8:8080"]
```

---

## 8. 테스트 전략

- `GhostLayer` unit: activate/deactivate, next_proxy round-robin, next_delay 범위
- `GhostTransport` unit: curl_cffi 없을 때 fallback 동작
- `parse_ghost_trigger` unit: 4가지 트리거 케이스
- Integration: `AgentExecutor`가 ghost mode로 실행 시 `TargetSession`에 transport 주입 확인

---

## 9. 비고

- AGPL 코드 사용 금지 — curl_cffi는 MIT 라이선스 (허용)
- 프록시 풀이 비어있어도 나머지 익명화(UA/타이밍/헤더)는 항상 적용
- `deactivate()`는 테스트 격리용 — 프로덕션에서는 호출 안 함
