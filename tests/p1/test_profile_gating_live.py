from vxis.config.schema import resolve_scan_profile


def test_only_p1_profile_enables_live_capabilities() -> None:
    assert resolve_scan_profile("standard").live_capabilities is False
    assert resolve_scan_profile("aggressive").live_capabilities is False

    p1 = resolve_scan_profile("p1-adversary-emulation")
    assert p1.requires_engagement is True
    assert p1.live_capabilities is True
    assert {"recon", "emulate", "c2", "lateral", "persist"}.issubset(p1.allowed_techniques)
