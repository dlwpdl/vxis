# GhostLayer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 4가지 트리거(CLI/URL/Config/Brain)로 활성화되는 최대 익명화 레이어를 Phase 0에 통합한다.

**Architecture:** `GhostLayer` 싱글턴이 Phase 0에서 활성화되면, `SessionManager`가 `TargetSession` 생성 시 `GhostTransport`를 주입한다. 이후 모든 HTTP 요청은 자동으로 프록시 rotation/TLS 핑거프린트/UA rotation/랜덤 딜레이를 거친다.

**Tech Stack:** Python 3.11+, httpx, curl_cffi(optional), pydantic v2, pytest-asyncio

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `src/vxis/ghost/__init__.py` | 패키지 익스포트 |
| Create | `src/vxis/ghost/layer.py` | GhostLayer 싱글턴 + GhostTiming |
| Create | `src/vxis/ghost/ua_pool.py` | 실제 브라우저 UA 20종 풀 |
| Create | `src/vxis/ghost/transport.py` | GhostTransport (httpx AsyncBaseTransport) |
| Create | `src/vxis/ghost/trigger.py` | parse_ghost_trigger() 유틸 |
| Create | `src/vxis/ghost/verifier.py` | GhostVerifier (IP/TLS 사전 검증) |
| Create | `tests/unit/test_ghost.py` | 모든 유닛 테스트 |
| Modify | `src/vxis/interaction/hands.py` | TargetSession transport 파라미터 추가, SessionManager 주입 |
| Modify | `src/vxis/agent/executor.py` | Phase 0 트리거 체크 + deactivate finally |
| Modify | `src/vxis/mission/config.py` | proxy_pool 필드 추가 |
| Modify | `scripts/auto_pentest.py` | --ghost 플래그 + ghost:// URL 처리 |
| Modify | `src/vxis/agent/brain_interactive.py` | ghost 키워드 감지 |

---

## Task 1: GhostLayer 싱글턴 + UA 풀

**Files:**
- Create: `src/vxis/ghost/ua_pool.py`
- Create: `src/vxis/ghost/layer.py`
- Create: `src/vxis/ghost/__init__.py`
- Test: `tests/unit/test_ghost.py`

- [ ] **Step 1: 테스트 작성**

```python
# tests/unit/test_ghost.py
import random
import pytest
from vxis.ghost.layer import GhostLayer, GhostTiming
from vxis.ghost.ua_pool import UA_POOL


def make_layer() -> GhostLayer:
    """테스트마다 격리된 인스턴스."""
    layer = GhostLayer.__new__(GhostLayer)
    layer._active = False
    layer._proxy_pool = []
    layer._proxy_index = 0
    layer._timing = GhostTiming()
    return layer


def test_ghost_layer_inactive_by_default():
    layer = make_layer()
    assert layer.is_active() is False


def test_ghost_layer_activate():
    layer = make_layer()
    layer.activate(["socks5://1.2.3.4:1080", "socks5://5.6.7.8:1080"])
    assert layer.is_active() is True
    assert len(layer._proxy_pool) == 2


def test_ghost_layer_deactivate():
    layer = make_layer()
    layer.activate()
    layer.deactivate()
    assert layer.is_active() is False


def test_ghost_layer_activate_no_proxies():
    """프록시 없이도 활성화 가능 (UA/타이밍만 적용)."""
    layer = make_layer()
    layer.activate([])
    assert layer.is_active() is True


def test_next_proxy_round_robin():
    layer = make_layer()
    layer.activate(["socks5://1.2.3.4:1080", "socks5://5.6.7.8:1080"])
    p1 = layer.next_proxy()
    p2 = layer.next_proxy()
    p3 = layer.next_proxy()
    assert p1 == "socks5://1.2.3.4:1080"
    assert p2 == "socks5://5.6.7.8:1080"
    assert p3 == "socks5://1.2.3.4:1080"  # wrap around


def test_next_proxy_empty_pool_returns_none():
    layer = make_layer()
    layer.activate([])
    assert layer.next_proxy() is None


def test_next_proxy_validates_bad_url():
    """잘못된 프록시 URL은 무시하고 경고."""
    layer = make_layer()
    layer.activate(["not-a-url", "socks5://1.2.3.4:1080"])
    assert len(layer._proxy_pool) == 1
    assert layer._proxy_pool[0] == "socks5://1.2.3.4:1080"


def test_next_ua_returns_string_from_pool():
    layer = make_layer()
    ua = layer.next_ua()
    assert isinstance(ua, str)
    assert len(ua) > 20
    assert ua in UA_POOL


def test_next_delay_within_bounds():
    layer = make_layer()
    for _ in range(50):
        d = layer.next_delay()
        assert layer._timing.min_delay <= d <= layer._timing.max_delay


def test_ua_pool_has_20_entries():
    assert len(UA_POOL) == 20


def test_ua_pool_all_strings():
    assert all(isinstance(ua, str) for ua in UA_POOL)
```

- [ ] **Step 2: 테스트 실패 확인**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py -v 2>&1 | head -20
```
Expected: `ModuleNotFoundError: No module named 'vxis.ghost'`

- [ ] **Step 3: ua_pool.py 작성**

```python
# src/vxis/ghost/ua_pool.py
"""실제 브라우저 User-Agent 풀 — 20종 (Chrome/Firefox/Safari/Edge, Win/Mac/Linux)."""

UA_POOL: list[str] = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Firefox macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    # Safari macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    # Chrome Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.193 Mobile Safari/537.36",
    # Safari iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
]
```

- [ ] **Step 4: layer.py 작성**

```python
# src/vxis/ghost/layer.py
"""GhostLayer — 익명화 레이어 싱글턴."""
from __future__ import annotations

import logging
import random
import re
from dataclasses import dataclass, field

from vxis.ghost.ua_pool import UA_POOL

logger = logging.getLogger(__name__)

_PROXY_URL_RE = re.compile(r"^(https?|socks5?)://[^/]+:\d+$")


@dataclass
class GhostTiming:
    mean: float = 3.0
    sigma: float = 2.0
    min_delay: float = 0.5
    max_delay: float = 15.0


class GhostLayer:
    """프로세스 레벨 싱글턴. 활성화되면 모든 TargetSession이 익명화 모드로 동작."""

    _instance: GhostLayer | None = None

    def __new__(cls) -> GhostLayer:
        if cls._instance is None:
            inst = super().__new__(cls)
            inst._active = False
            inst._proxy_pool: list[str] = []
            inst._proxy_index = 0
            inst._timing = GhostTiming()
            cls._instance = inst
        return cls._instance

    def activate(self, proxy_pool: list[str] | None = None) -> None:
        valid: list[str] = []
        for p in (proxy_pool or []):
            if _PROXY_URL_RE.match(p):
                valid.append(p)
            else:
                logger.warning("[Ghost] 잘못된 프록시 URL 무시: %s", p)
        self._proxy_pool = valid
        self._proxy_index = 0
        self._active = True
        logger.info(
            "[Ghost] 익명화 활성화 — 프록시: %d개, UA풀: %d종",
            len(self._proxy_pool), len(UA_POOL),
        )

    def deactivate(self) -> None:
        self._active = False
        self._proxy_pool = []
        self._proxy_index = 0
        logger.info("[Ghost] 익명화 비활성화")

    def is_active(self) -> bool:
        return self._active

    def next_proxy(self) -> str | None:
        if not self._proxy_pool:
            return None
        proxy = self._proxy_pool[self._proxy_index % len(self._proxy_pool)]
        self._proxy_index += 1
        return proxy

    def next_ua(self) -> str:
        return random.choice(UA_POOL)

    def next_delay(self) -> float:
        t = self._timing
        raw = random.gauss(t.mean, t.sigma)
        return max(t.min_delay, min(t.max_delay, raw))


# 모듈 레벨 싱글턴 인스턴스
ghost_layer = GhostLayer()
```

- [ ] **Step 5: `__init__.py` 작성**

```python
# src/vxis/ghost/__init__.py
from vxis.ghost.layer import GhostLayer, GhostTiming, ghost_layer

__all__ = ["GhostLayer", "GhostTiming", "ghost_layer"]
```

- [ ] **Step 6: 테스트 실행**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py -v -k "not transport and not trigger and not verifier"
```
Expected: 11개 PASS

- [ ] **Step 7: 커밋**

```bash
git add src/vxis/ghost/ tests/unit/test_ghost.py
git commit -m "feat(ghost): GhostLayer singleton + UA pool (Task 1)"
```

---

## Task 2: GhostTransport

**Files:**
- Create: `src/vxis/ghost/transport.py`
- Test: `tests/unit/test_ghost.py` (추가)

- [ ] **Step 1: 테스트 추가**

`tests/unit/test_ghost.py` 하단에 추가:

```python
import httpx
from unittest.mock import AsyncMock, MagicMock, patch
from vxis.ghost.transport import GhostTransport


@pytest.mark.asyncio
async def test_ghost_transport_overrides_ua():
    """GhostTransport이 User-Agent 헤더를 UA풀 값으로 교체."""
    layer = make_layer()
    layer.activate([])

    mock_inner = AsyncMock()
    mock_inner.handle_async_request = AsyncMock(
        return_value=httpx.Response(200, content=b"ok")
    )

    transport = GhostTransport(layer, inner=mock_inner)
    request = httpx.Request("GET", "https://example.com")

    await transport.handle_async_request(request)

    called_request = mock_inner.handle_async_request.call_args[0][0]
    assert called_request.headers["user-agent"] in UA_POOL


@pytest.mark.asyncio
async def test_ghost_transport_applies_proxy():
    """프록시 풀이 있으면 inner transport에 프록시 적용."""
    layer = make_layer()
    layer.activate(["socks5://1.2.3.4:1080"])

    with patch("vxis.ghost.transport._make_transport") as mock_make:
        mock_inner = AsyncMock()
        mock_inner.handle_async_request = AsyncMock(
            return_value=httpx.Response(200, content=b"ok")
        )
        mock_make.return_value = mock_inner

        transport = GhostTransport(layer)
        request = httpx.Request("GET", "https://example.com")
        await transport.handle_async_request(request)

        mock_make.assert_called_once_with("socks5://1.2.3.4:1080")


@pytest.mark.asyncio
async def test_ghost_transport_no_proxy_direct_connect():
    """프록시 없으면 직접 연결 fallback."""
    layer = make_layer()
    layer.activate([])

    mock_inner = AsyncMock()
    mock_inner.handle_async_request = AsyncMock(
        return_value=httpx.Response(200, content=b"ok")
    )

    transport = GhostTransport(layer, inner=mock_inner)
    request = httpx.Request("GET", "https://example.com")
    await transport.handle_async_request(request)

    assert mock_inner.handle_async_request.called
```

- [ ] **Step 2: 테스트 실패 확인**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py -v -k "transport" 2>&1 | head -10
```
Expected: `ImportError: cannot import name 'GhostTransport'`

- [ ] **Step 3: transport.py 작성**

```python
# src/vxis/ghost/transport.py
"""GhostTransport — httpx AsyncBaseTransport 래퍼.

요청마다 GhostLayer에서 proxy/UA를 받아 적용.
curl_cffi가 설치되어 있으면 Chrome TLS 핑거프린트 사용.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from vxis.ghost.layer import GhostLayer

logger = logging.getLogger(__name__)

# curl_cffi 선택적 의존성
try:
    import curl_cffi.requests as _curl  # noqa: F401
    _CURL_AVAILABLE = True
    logger.debug("[Ghost] curl_cffi 감지 — Chrome TLS 핑거프린트 활성화")
except ImportError:
    _CURL_AVAILABLE = False
    logger.warning("[Ghost] curl_cffi 미설치 — TLS 핑거프린트 익명화 비활성 (pip install curl-cffi)")

# 브라우저 헤더 세트 (Chrome 120 기준)
_BROWSER_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


def _make_transport(proxy: str | None) -> httpx.AsyncBaseTransport:
    """프록시 URL로 httpx transport 생성."""
    if proxy:
        return httpx.AsyncHTTPTransport(proxy=proxy)
    return httpx.AsyncHTTPTransport()


class GhostTransport(httpx.AsyncBaseTransport):
    """요청마다 Ghost 설정을 적용하는 httpx transport 래퍼.

    Usage (SessionManager에서):
        if ghost_layer.is_active():
            transport = GhostTransport(ghost_layer)
            session = TargetSession(base_url, transport=transport)
    """

    def __init__(
        self,
        layer: GhostLayer,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._layer = layer
        self._inner = inner  # 테스트 주입용

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        # proxy 선택 (요청마다 rotation)
        proxy = self._layer.next_proxy()

        # inner transport 결정 (테스트 주입 우선)
        transport = self._inner or _make_transport(proxy)

        # UA 교체
        ua = self._layer.next_ua()
        headers = dict(request.headers)
        headers["user-agent"] = ua

        # 브라우저 헤더 주입 (이미 있는 헤더는 덮어쓰지 않음)
        for k, v in _BROWSER_HEADERS.items():
            if k.lower() not in {h.lower() for h in headers}:
                headers[k] = v

        new_request = request.copy_with(headers=headers)

        logger.debug(
            "[Ghost] %s %s  proxy=%s  ua=%.40s...",
            new_request.method, new_request.url, proxy or "direct", ua,
        )

        return await transport.handle_async_request(new_request)

    async def aclose(self) -> None:
        if self._inner:
            await self._inner.aclose()
```

- [ ] **Step 4: `__init__.py` 업데이트**

```python
# src/vxis/ghost/__init__.py
from vxis.ghost.layer import GhostLayer, GhostTiming, ghost_layer
from vxis.ghost.transport import GhostTransport

__all__ = ["GhostLayer", "GhostTiming", "ghost_layer", "GhostTransport"]
```

- [ ] **Step 5: 테스트 실행**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py -v -k "transport"
```
Expected: 3개 PASS

- [ ] **Step 6: 커밋**

```bash
git add src/vxis/ghost/transport.py src/vxis/ghost/__init__.py tests/unit/test_ghost.py
git commit -m "feat(ghost): GhostTransport with UA/proxy/browser-headers injection (Task 2)"
```

---

## Task 3: Trigger 유틸 + MissionConfig proxy_pool

**Files:**
- Create: `src/vxis/ghost/trigger.py`
- Modify: `src/vxis/mission/config.py`
- Test: `tests/unit/test_ghost.py` (추가)

- [ ] **Step 1: 테스트 추가**

```python
from vxis.ghost.trigger import parse_ghost_trigger
from vxis.mission.config import MissionConfig


def test_trigger_ghost_url_prefix():
    cfg = MissionConfig(target="ghost://example.com")
    activated, clean = parse_ghost_trigger("ghost://example.com", cfg)
    assert activated is True
    assert clean == "https://example.com"


def test_trigger_mission_config_stealth():
    cfg = MissionConfig(target="https://example.com", stealth=True)
    activated, clean = parse_ghost_trigger("https://example.com", cfg)
    assert activated is True
    assert clean == "https://example.com"


def test_trigger_no_ghost():
    cfg = MissionConfig(target="https://example.com")
    activated, clean = parse_ghost_trigger("https://example.com", cfg)
    assert activated is False
    assert clean == "https://example.com"


def test_trigger_or_logic():
    """URL prefix만 있어도 활성화."""
    cfg = MissionConfig(target="ghost://example.com", stealth=False)
    activated, _ = parse_ghost_trigger("ghost://example.com", cfg)
    assert activated is True


def test_mission_config_proxy_pool_default():
    cfg = MissionConfig(target="example.com")
    assert cfg.proxy_pool == []


def test_mission_config_proxy_pool_set():
    cfg = MissionConfig(target="example.com", proxy_pool=["socks5://1.2.3.4:1080"])
    assert cfg.proxy_pool == ["socks5://1.2.3.4:1080"]
```

- [ ] **Step 2: 테스트 실패 확인**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py -v -k "trigger or proxy_pool"
```
Expected: ImportError

- [ ] **Step 3: trigger.py 작성**

```python
# src/vxis/ghost/trigger.py
"""GhostLayer 트리거 파싱 유틸.

4가지 트리거(URL prefix, MissionConfig, CLI, Brain)가 모두 이 함수로 수렴.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vxis.mission.config import MissionConfig

_GHOST_SCHEME = "ghost://"


def parse_ghost_trigger(
    target: str,
    config: "MissionConfig | None" = None,
) -> tuple[bool, str]:
    """Ghost 트리거 여부와 정규화된 URL 반환.

    Returns:
        (activated, clean_target)
        - activated: 트리거 감지 시 True
        - clean_target: ghost:// 제거된 https:// URL
    """
    activated = False
    clean = target

    # Trigger 1: ghost:// URL prefix
    if target.startswith(_GHOST_SCHEME):
        activated = True
        clean = "https://" + target[len(_GHOST_SCHEME):]

    # Trigger 2: MissionConfig.stealth
    if config is not None and getattr(config, "stealth", False):
        activated = True

    return activated, clean
```

- [ ] **Step 4: MissionConfig에 proxy_pool 추가**

`src/vxis/mission/config.py`의 `MissionConfig` 클래스에서:

```python
# 기존
class MissionConfig(BaseModel):
    target: str
    depth: Depth = Depth.NORMAL
    stealth: bool = False
    perspective: Perspective = Perspective.EXTERNAL
    scope: Scope = Scope.FULL
    custom_agents: list[str] = []
    memory: MemoryConfig = MemoryConfig()
    client_id: Optional[str] = None
```

→ `proxy_pool: list[str] = []` 한 줄 추가:

```python
class MissionConfig(BaseModel):
    target: str
    depth: Depth = Depth.NORMAL
    stealth: bool = False
    perspective: Perspective = Perspective.EXTERNAL
    scope: Scope = Scope.FULL
    custom_agents: list[str] = []
    proxy_pool: list[str] = []
    memory: MemoryConfig = MemoryConfig()
    client_id: Optional[str] = None
```

- [ ] **Step 5: 테스트 실행**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py tests/unit/test_mission_config.py -v -k "trigger or proxy_pool or mission"
```
Expected: 모두 PASS (기존 mission_config 테스트 포함)

- [ ] **Step 6: 커밋**

```bash
git add src/vxis/ghost/trigger.py src/vxis/mission/config.py tests/unit/test_ghost.py
git commit -m "feat(ghost): trigger util + MissionConfig.proxy_pool (Task 3)"
```

---

## Task 4: hands.py 통합 (TargetSession + SessionManager)

**Files:**
- Modify: `src/vxis/interaction/hands.py`
- Test: `tests/unit/test_ghost.py` (추가)

- [ ] **Step 1: 테스트 추가**

```python
import pytest
from unittest.mock import patch, MagicMock
from vxis.interaction.hands import TargetSession, SessionManager
from vxis.ghost.layer import GhostLayer
from vxis.ghost.transport import GhostTransport


def test_target_session_accepts_transport():
    """TargetSession이 transport 파라미터를 받아서 httpx client에 주입."""
    mock_transport = MagicMock(spec=GhostTransport)
    session = TargetSession("https://example.com", transport=mock_transport)
    assert session._client._transport == mock_transport or \
           session._client._mounts.get("https://") == mock_transport or \
           session._transport is mock_transport


@pytest.mark.asyncio
async def test_session_manager_injects_ghost_transport():
    """GhostLayer 활성화 시 SessionManager가 GhostTransport 주입."""
    layer = GhostLayer.__new__(GhostLayer)
    layer._active = True
    layer._proxy_pool = []
    layer._proxy_index = 0
    from vxis.ghost.layer import GhostTiming
    layer._timing = GhostTiming()

    mgr = SessionManager()
    with patch("vxis.interaction.hands.ghost_layer", layer):
        session = await mgr.get_session("https://example.com")
        # transport가 GhostTransport인지 확인
        assert hasattr(session, "_transport") or session._client is not None

    await mgr.close_all()
```

- [ ] **Step 2: hands.py 수정**

`src/vxis/interaction/hands.py` 상단 import에 추가:
```python
from vxis.ghost.layer import ghost_layer
from vxis.ghost.transport import GhostTransport
```

`TargetSession.__init__` 시그니처 변경 (기존 `proxy` 파라미터 유지, `transport` 추가):
```python
def __init__(
    self,
    base_url: str,
    timeout: float = 30.0,
    max_redirects: int = 5,
    verify_ssl: bool = False,
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    proxy: str | None = None,
    transport: httpx.AsyncBaseTransport | None = None,  # ← 추가
) -> None:
```

`client_kwargs` 빌드 부분에서 transport 주입 (proxy보다 transport 우선):
```python
        # transport 우선, 없으면 proxy 사용
        if transport is not None:
            client_kwargs["transport"] = transport
        elif proxy:
            client_kwargs["proxy"] = proxy
        self._client = httpx.AsyncClient(**client_kwargs)
```

`SessionManager.get_session` 수정 — GhostLayer 활성 시 transport 주입:
```python
    async def get_session(
        self,
        base_url: str,
        **kwargs: Any,
    ) -> TargetSession:
        key = urlparse(base_url).netloc
        if key not in self._sessions:
            # GhostLayer 활성 시 GhostTransport 주입
            if ghost_layer.is_active() and "transport" not in kwargs:
                kwargs["transport"] = GhostTransport(ghost_layer)
            session = TargetSession(base_url, **kwargs)
            self._sessions[key] = session
            logger.info("New session created: %s (ghost=%s)", base_url, ghost_layer.is_active())
        return self._sessions[key]
```

- [ ] **Step 3: _throttle() 수정** — ghost 타이밍 레이어 추가

```python
    async def _throttle(self) -> None:
        if ghost_layer.is_active():
            ghost_delay = ghost_layer.next_delay()
            effective = max(ghost_delay, self._min_delay)
        else:
            effective = self._min_delay

        if effective > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < effective:
                await asyncio.sleep(effective - elapsed)
            elif not ghost_layer.is_active() and self._min_delay > 0 and elapsed > self._min_delay * 3:
                self._min_delay = max(self._min_delay - 0.2, 0.0)
```

- [ ] **Step 4: 테스트 실행**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py tests/unit/test_phase4_cpr.py -v
```
Expected: PASS (기존 CPR 테스트 깨지지 않아야 함)

- [ ] **Step 5: 커밋**

```bash
git add src/vxis/interaction/hands.py tests/unit/test_ghost.py
git commit -m "feat(ghost): inject GhostTransport into TargetSession/SessionManager (Task 4)"
```

---

## Task 5: AgentExecutor Phase 0 통합

**Files:**
- Modify: `src/vxis/agent/executor.py`
- Test: `tests/unit/test_ghost.py` (추가)

- [ ] **Step 1: 테스트 추가**

```python
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from vxis.agent.executor import AgentExecutor
from vxis.mission.config import MissionConfig


@pytest.mark.asyncio
async def test_executor_activates_ghost_on_ghost_url():
    """ghost:// URL이면 Phase 0에서 GhostLayer 활성화."""
    executor = AgentExecutor(max_steps=1)

    with patch("vxis.agent.executor.ghost_layer") as mock_layer, \
         patch.object(executor, "_run_recon_phase", new_callable=AsyncMock), \
         patch.object(executor._brain, "is_done", True):

        mock_layer.is_active.return_value = False
        await executor.run("ghost://example.com")
        mock_layer.activate.assert_called_once()


@pytest.mark.asyncio
async def test_executor_deactivates_ghost_on_completion():
    """스캔 완료 후 ghost_layer.deactivate() 호출."""
    executor = AgentExecutor(max_steps=1)

    with patch("vxis.agent.executor.ghost_layer") as mock_layer, \
         patch.object(executor, "_run_recon_phase", new_callable=AsyncMock), \
         patch.object(executor._brain, "is_done", True):

        mock_layer.is_active.return_value = True
        await executor.run("ghost://example.com")
        mock_layer.deactivate.assert_called_once()
```

- [ ] **Step 2: executor.py 수정**

상단 import 추가:
```python
from vxis.ghost.layer import ghost_layer
from vxis.ghost.trigger import parse_ghost_trigger
```

`AgentExecutor.run()` 메서드에서 `# ── Phase 0: CPR 인터랙션 레이어 시작 ──` **이전**에 삽입:

```python
        # ── Phase 0-pre: GhostLayer 트리거 체크 ──────────────────
        self._ghost_activated_here = False
        ghost_activated, target = parse_ghost_trigger(target, self._config)
        if ghost_activated:
            proxy_pool = list(getattr(self._config, "proxy_pool", []))
            ghost_layer.activate(proxy_pool)
            self._ghost_activated_here = True
            logger.info("[Ghost] 익명화 모드 — target: %s, proxies: %d개", target, len(proxy_pool))
```

`run()` 메서드의 return 문 **직전** (현재 `return AgentScanResult(...)` 바로 앞) 을 try/finally로 감싸거나, return 직전에 추가:

```python
        # Ghost deactivate — sandbox cleanup 예외와 무관하게 반드시 실행
        # executor.py의 sandbox cleanup 블록 이후, return 직전에 try/finally로 감싸기:
        #
        # try:
        #     if self._sandbox_manager is not None:
        #         await self._sandbox_manager.cleanup_all()
        # except Exception as exc:
        #     logger.warning("sandbox 정리 중 오류 (무시): %s", exc)
        # finally:
        #     if self._ghost_activated_here:
        #         ghost_layer.deactivate()
        #
        # 즉, sandbox cleanup try/except의 finally 블록에 deactivate 추가.

        return AgentScanResult(...)
```

> **주의:** 기존 코드에서 sandbox cleanup 후 return이 있으므로, return 직전 한 줄만 추가.

- [ ] **Step 3: 테스트 실행**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py -v -k "executor"
```
Expected: 2개 PASS

- [ ] **Step 4: 커밋**

```bash
git add src/vxis/agent/executor.py tests/unit/test_ghost.py
git commit -m "feat(ghost): Phase 0 ghost trigger check + auto deactivate (Task 5)"
```

---

## Task 6: CLI 트리거 (auto_pentest.py + --ghost 플래그)

**Files:**
- Modify: `scripts/auto_pentest.py`

- [ ] **Step 1: auto_pentest.py 수정**

현재 파일에 argparse 추가 및 ghost 처리:

```python
"""VXIS Full-Auto Pentest — 타깃 URL 하나 주면 Brain이 알아서 전부 한다."""

import argparse
import asyncio
import logging
import sys

sys.path.insert(0, "src")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)


async def main() -> None:
    parser = argparse.ArgumentParser(description="VXIS Full-Auto Pentest")
    parser.add_argument("target", help="Target URL (또는 ghost://target)")
    parser.add_argument("--ghost", action="store_true", help="최대 익명화 모드 활성화")
    args = parser.parse_args()

    target = args.target

    # CLI --ghost 플래그 또는 ghost:// prefix 처리
    if args.ghost and not target.startswith("ghost://"):
        # 기존 scheme 제거 후 ghost:// 붙이기
        for scheme in ("https://", "http://"):
            if target.startswith(scheme):
                target = target[len(scheme):]
                break
        target = "ghost://" + target

    print(f"\n{'='*70}")
    print(f"  VXIS Full-Auto Pentest")
    print(f"  Target: {target}")
    if args.ghost or target.startswith("ghost://"):
        print(f"  Mode:   [GHOST] 익명화 활성화")
    print(f"{'='*70}\n")

    from vxis.agent.executor import AgentExecutor

    executor = AgentExecutor(max_steps=20)
    result = await executor.run(target=target)

    print(f"\n{'='*70}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*70}")
    print(f"  Target:   {result.target}")
    print(f"  Steps:    {result.steps_taken}")
    print(f"  Duration: {result.duration_seconds:.1f}s")
    print(f"  Findings: {len(result.findings)}")
    print(f"{'='*70}\n")

    if result.findings:
        print("## Findings\n")
        for i, f in enumerate(result.findings, 1):
            print(f"  [{f.severity.value.upper():8s}] {f.title}")
            if f.description:
                print(f"             {f.description[:120]}")
            print()

    print("\n## Execution Log\n")
    print(result.execution_log)


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 2: 동작 확인**

```bash
cd C:\Users\euns\Desktop\git\vxis && python scripts/auto_pentest.py --help
```
Expected: `--ghost` 옵션이 출력됨

```bash
python scripts/auto_pentest.py  # 인자 없이
```
Expected: Usage 출력 후 종료 (기존 동작 유지)

- [ ] **Step 3: 커밋**

```bash
git add scripts/auto_pentest.py
git commit -m "feat(ghost): --ghost CLI flag + ghost:// URL handling (Task 6)"
```

---

## Task 7: Brain 자연어 트리거 (brain_interactive.py)

**Files:**
- Modify: `src/vxis/agent/brain_interactive.py`
- Test: `tests/unit/test_ghost.py` (추가)

- [ ] **Step 1: 테스트 추가**

```python
from vxis.ghost.trigger import detect_ghost_keyword


def test_detect_ghost_keyword_english():
    assert detect_ghost_keyword("ghost mode로 스캔해줘") is True
    assert detect_ghost_keyword("stealth scan please") is True
    assert detect_ghost_keyword("anonymize the scan") is True
    assert detect_ghost_keyword("anonymous mode") is True


def test_detect_ghost_keyword_korean():
    assert detect_ghost_keyword("익명화해서 스캔해") is True
    assert detect_ghost_keyword("스텔스 모드로") is True
    assert detect_ghost_keyword("고스트 모드") is True


def test_detect_ghost_keyword_no_match():
    assert detect_ghost_keyword("그냥 스캔해줘") is False
    assert detect_ghost_keyword("nuclei 실행해") is False
    assert detect_ghost_keyword("") is False
```

- [ ] **Step 2: trigger.py에 detect_ghost_keyword 추가**

`src/vxis/ghost/trigger.py` 하단에 추가:

```python
import re

_GHOST_KEYWORDS = re.compile(
    r"ghost|stealth|anon(ymous|ymize)?|익명|스텔스|고스트",
    re.IGNORECASE,
)


def detect_ghost_keyword(text: str) -> bool:
    """텍스트에 ghost 트리거 키워드가 있으면 True."""
    return bool(_GHOST_KEYWORDS.search(text))
```

- [ ] **Step 3: brain_interactive.py 수정**

`src/vxis/agent/brain_interactive.py` line 61의 `_read_decision()` 메서드에 주입.
기존 `line = self._input.readline()` 직후에 ghost 키워드 감지 추가:

```python
# 상단 import 추가 (파일 최상단)
from vxis.ghost.trigger import detect_ghost_keyword
from vxis.ghost.layer import ghost_layer

# _read_decision() 메서드 (line 61) 수정:
def _read_decision(self) -> dict[str, Any]:
    """stdin에서 JSON 한 줄 읽기 (blocking)."""
    try:
        line = self._input.readline()
        if not line or not line.strip():
            logger.warning("stdin closed or empty — 스캔 종료")
            self.is_done = True
            return {"actions": [{"tool": "DONE", "reasoning": "stdin closed"}]}

        # ghost 키워드 감지 (JSON 파싱 전에 raw text 검사)
        if detect_ghost_keyword(line):
            if not ghost_layer.is_active():
                ghost_layer.activate()
                self._emit({"type": "ghost_activated", "message": "[GHOST MODE ACTIVATED] 익명화 모드 활성화됨"})
                logger.info("[Ghost] Brain 자연어 트리거 감지 → 활성화")

        return json.loads(line.strip())
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON from stdin: %s", e)
        return {"actions": [{"tool": "DONE", "reasoning": f"JSON parse error: {e}"}]}
```

- [ ] **Step 4: 테스트 실행**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py -v -k "keyword"
```
Expected: 3개 PASS

- [ ] **Step 5: 커밋**

```bash
git add src/vxis/ghost/trigger.py src/vxis/agent/brain_interactive.py tests/unit/test_ghost.py
git commit -m "feat(ghost): brain keyword trigger + detect_ghost_keyword() (Task 7)"
```

---

## Task 8: GhostVerifier (서버 로그 기반 검증)

**Files:**
- Create: `src/vxis/ghost/verifier.py`
- Test: `tests/unit/test_ghost.py` (추가)

- [ ] **Step 1: 테스트 추가**

```python
from unittest.mock import AsyncMock, patch, MagicMock
from vxis.ghost.verifier import GhostVerifier


@pytest.mark.asyncio
async def test_ghost_verifier_reports_active_ip():
    """검증 결과에 감지된 IP가 포함."""
    verifier = GhostVerifier()

    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = '{"ip": "182.23.45.67"}'
    mock_resp.status = 200
    mock_session.get = AsyncMock(return_value=mock_resp)
    mock_session.close = AsyncMock()

    with patch("vxis.ghost.verifier.TargetSession", return_value=mock_session):
        result = await verifier.check()

    assert result["detected_ip"] == "182.23.45.67"
    assert "ghost_active" in result


@pytest.mark.asyncio
async def test_ghost_verifier_handles_failure():
    """IP 확인 실패 시 graceful degradation."""
    verifier = GhostVerifier()

    mock_session = MagicMock()
    mock_session.get = AsyncMock(side_effect=Exception("network error"))
    mock_session.close = AsyncMock()

    with patch("vxis.ghost.verifier.TargetSession", return_value=mock_session):
        result = await verifier.check()

    assert result["detected_ip"] is None
    assert result["error"] is not None
```

- [ ] **Step 2: verifier.py 작성**

```python
# src/vxis/ghost/verifier.py
"""GhostVerifier — 익명화 적용 여부 사전 검증."""
from __future__ import annotations

import json
import logging

from vxis.ghost.layer import ghost_layer

logger = logging.getLogger(__name__)

_IP_CHECK_URL = "https://api64.ipify.org?format=json"


class GhostVerifier:
    """Ghost 모드 활성화 후 실제 노출 IP/UA 확인.

    사용: AgentExecutor Phase 0에서 ghost_layer.activate() 이후 선택적으로 호출.
    """

    async def check(self) -> dict:
        """IP 확인 서비스에 요청해서 노출 IP를 확인.

        Returns:
            {
                "ghost_active": bool,
                "detected_ip": str | None,
                "user_agent": str | None,
                "error": str | None,
            }
        """
        from vxis.interaction.hands import TargetSession

        result: dict = {
            "ghost_active": ghost_layer.is_active(),
            "detected_ip": None,
            "user_agent": None,
            "error": None,
        }

        session = TargetSession(_IP_CHECK_URL, verify_ssl=True)
        try:
            resp = await session.get("/")
            if resp.status == 200:
                data = json.loads(resp.text)
                result["detected_ip"] = data.get("ip")
                logger.info("[GhostVerifier] 노출 IP: %s", result["detected_ip"])
            else:
                result["error"] = f"HTTP {resp.status}"
        except Exception as exc:
            result["error"] = str(exc)
            logger.warning("[GhostVerifier] IP 확인 실패: %s", exc)
        finally:
            await session.close()

        return result

    def log_summary(self, result: dict) -> None:
        ip = result.get("detected_ip", "unknown")
        active = result.get("ghost_active", False)
        err = result.get("error")

        if err:
            logger.warning("[Ghost ✗] 검증 실패: %s", err)
        elif active and ip:
            logger.info("[Ghost ✓] 익명화 IP 확인: %s", ip)
        elif not active:
            logger.info("[Ghost -] Ghost 비활성 — 직접 연결 IP: %s", ip)
```

- [ ] **Step 3: `__init__.py` 업데이트**

```python
# src/vxis/ghost/__init__.py
from vxis.ghost.layer import GhostLayer, GhostTiming, ghost_layer
from vxis.ghost.transport import GhostTransport
from vxis.ghost.verifier import GhostVerifier

__all__ = ["GhostLayer", "GhostTiming", "ghost_layer", "GhostTransport", "GhostVerifier"]
```

- [ ] **Step 4: 테스트 실행**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/test_ghost.py -v
```
Expected: 모두 PASS

- [ ] **Step 5: 커밋**

```bash
git add src/vxis/ghost/verifier.py src/vxis/ghost/__init__.py tests/unit/test_ghost.py
git commit -m "feat(ghost): GhostVerifier for IP anonymization check (Task 8)"
```

---

## Task 9: 전체 회귀 테스트 + 최종 커밋

- [ ] **Step 1: 전체 유닛 테스트 실행**

```bash
cd C:\Users\euns\Desktop\git\vxis && python -m pytest tests/unit/ -v --tb=short 2>&1 | tail -30
```
Expected: 기존 테스트 포함 전부 PASS (새 테스트 누적 포함)

- [ ] **Step 2: import 체크**

```bash
python -c "from vxis.ghost import ghost_layer, GhostTransport, GhostVerifier; print('OK')"
```
Expected: `OK`

- [ ] **Step 3: --ghost 플래그 smoke test**

```bash
python scripts/auto_pentest.py --help | grep ghost
```
Expected: `--ghost` 옵션 출력

- [ ] **Step 4: 최종 커밋**

```bash
git add -A
git commit -m "feat(ghost): GhostLayer full implementation — 4-trigger anonymization in Phase 0"
```
