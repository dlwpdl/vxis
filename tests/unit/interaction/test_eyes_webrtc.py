"""WebRTC opsec flags must stay wired into the browser launch args."""

from vxis.interaction.eyes import _WEBRTC_OPSEC_ARGS


def test_webrtc_non_proxied_udp_is_disabled():
    joined = " ".join(_WEBRTC_OPSEC_ARGS)
    assert "disable_non_proxied_udp" in joined
    assert any(a.startswith("--force-webrtc-ip-handling-policy") for a in _WEBRTC_OPSEC_ARGS)
