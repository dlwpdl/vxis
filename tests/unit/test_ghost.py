"""GhostLayer 유닛 테스트."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from vxis.ghost.layer import GhostLayer, GhostTiming
from vxis.ghost.transport import GhostTransport
from vxis.ghost.trigger import detect_ghost_keyword, parse_ghost_trigger
from vxis.ghost.verifier import GhostVerifier
from vxis.mission.config import MissionConfig
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
    assert p3 == "socks5://1.2.3.4:1080"


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


# ── Transport 테스트 ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ghost_transport_overrides_ua():
    """GhostTransport이 User-Agent 헤더를 UA풀 값으로 교체."""
    layer = make_layer()
    layer.activate([])

    mock_inner = AsyncMock()
    mock_inner.handle_async_request = AsyncMock(return_value=httpx.Response(200, content=b"ok"))

    transport = GhostTransport(layer, inner=mock_inner)
    request = httpx.Request("GET", "https://example.com")

    await transport.handle_async_request(request)

    called_request = mock_inner.handle_async_request.call_args[0][0]
    assert called_request.headers["user-agent"] in UA_POOL


@pytest.mark.asyncio
async def test_ghost_transport_applies_proxy():
    """프록시 풀이 있으면 _make_transport에 프록시 전달."""
    layer = make_layer()
    layer.activate(["socks5://1.2.3.4:1080"])

    with patch("vxis.ghost.transport._make_transport") as mock_make:
        mock_inner = AsyncMock()
        mock_inner.handle_async_request = AsyncMock(return_value=httpx.Response(200, content=b"ok"))
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
    mock_inner.handle_async_request = AsyncMock(return_value=httpx.Response(200, content=b"ok"))

    transport = GhostTransport(layer, inner=mock_inner)
    request = httpx.Request("GET", "https://example.com")
    await transport.handle_async_request(request)

    assert mock_inner.handle_async_request.called


# ── Trigger 테스트 ────────────────────────────────────────────────


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


# ── Verifier 테스트 ───────────────────────────────────────────────


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

    with patch("vxis.interaction.hands.TargetSession", return_value=mock_session):
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

    with patch("vxis.interaction.hands.TargetSession", return_value=mock_session):
        result = await verifier.check()

    assert result["detected_ip"] is None
    assert result["error"] is not None
