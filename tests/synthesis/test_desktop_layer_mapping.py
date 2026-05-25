"""G.2 — OSILayer.DESKTOP 추가 + agent map 테스트.

spec:
  - OSILayer.DESKTOP = "desktop" 존재.
  - _agent_to_layer(agent_id) 공개 헬퍼 함수로 에이전트 → 레이어 조회.
  - desktop_local_storage_secrets → DESKTOP.
  - test_dylib_hijack → DESKTOP (명시적 맵 또는 prefix 폴백).
  - 기존 web / cloud 매핑이 깨지지 않음.
"""

from __future__ import annotations


from vxis.synthesis.cross_protocol import OSILayer, _agent_to_layer


# ── OSILayer.DESKTOP 존재 ────────────────────────────────────────


def test_osilayer_desktop_value() -> None:
    """OSILayer.DESKTOP 은 문자열 값 'desktop' 을 가져야 한다."""
    assert OSILayer.DESKTOP == "desktop"
    assert OSILayer.DESKTOP.value == "desktop"


def test_osilayer_desktop_is_str_enum() -> None:
    """OSILayer 는 str Enum 이어야 한다."""
    assert isinstance(OSILayer.DESKTOP, str)


# ── _agent_to_layer 명시적 매핑 ──────────────────────────────────


def test_desktop_layer_mapping() -> None:
    """TDD 명세 — 두 desktop 에이전트가 DESKTOP 레이어로 해석돼야 한다."""
    assert _agent_to_layer("desktop_local_storage_secrets") == OSILayer.DESKTOP
    assert _agent_to_layer("test_dylib_hijack") == OSILayer.DESKTOP


def test_desktop_explicit_map_wins() -> None:
    """_AGENT_LAYER_MAP 에 등록된 desktop_* 이름은 DESKTOP 을 반환한다."""
    desktop_agents = [
        "desktop_local_storage_secrets",
        "desktop_electron_misconfig",
        "desktop_ipc_injection",
        "desktop_update_mitm",
        "desktop_deeplink_abuse",
        "desktop_binary_protections",
        "desktop_privilege_escalation",
        "desktop_dependency_confusion",
    ]
    for agent in desktop_agents:
        assert _agent_to_layer(agent) == OSILayer.DESKTOP, f"{agent} should map to DESKTOP"


def test_desktop_prefix_fallback() -> None:
    """_AGENT_LAYER_MAP 에 없는 desktop_ 접두사 에이전트도 DESKTOP 으로 폴백."""
    assert _agent_to_layer("desktop_something_new") == OSILayer.DESKTOP


# ── 기존 매핑 회귀 ──────────────────────────────────────────────


def test_web_agent_maps_to_application() -> None:
    assert _agent_to_layer("web") == OSILayer.APPLICATION


def test_cloud_agent_maps_to_cloud() -> None:
    assert _agent_to_layer("cloud") == OSILayer.CLOUD


def test_network_agent_maps_to_network() -> None:
    assert _agent_to_layer("network") == OSILayer.NETWORK


def test_unknown_agent_defaults_to_application() -> None:
    """매핑이 없고 prefix 도 없으면 APPLICATION(웹 바이어스) 이 기본값이다."""
    assert _agent_to_layer("totally_unknown_agent_xyz") == OSILayer.APPLICATION


# ── test_dylib_hijack 특별 케이스 ───────────────────────────────


def test_dylib_hijack_maps_to_desktop() -> None:
    """macOS dylib hijacking 스킬은 DESKTOP 레이어에 속한다."""
    assert _agent_to_layer("test_dylib_hijack") == OSILayer.DESKTOP
