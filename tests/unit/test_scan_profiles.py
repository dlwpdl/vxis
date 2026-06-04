from __future__ import annotations

from vxis.config.schema import (
    VXISConfig,
    normalize_scan_profile_name,
    resolve_scan_profile,
)


def test_crown_is_default_core_profile() -> None:
    config = VXISConfig()

    assert config.active_profile == "crown"
    assert config.profiles["crown"].intent == "crown_jewel"
    assert config.profiles["crown"].is_business_profile is False


def test_business_profiles_are_scaffolded_without_replacing_crown() -> None:
    config = VXISConfig()

    assert config.profiles["vc-portfolio-monitor"].is_business_profile is True
    assert config.profiles["vc-portfolio-monitor"].is_scaffold is True
    assert config.profiles["continuous-devsec"].public_tool_disclosure is False
    assert config.profiles["compliance-mapping"].intent == "compliance_mapping"
    assert normalize_scan_profile_name("default") == "crown"


def test_profile_alias_resolution() -> None:
    config = VXISConfig()

    assert resolve_scan_profile("vc", config.profiles).name == "vc-portfolio-monitor"
    assert resolve_scan_profile("vc-baseline", config.profiles).name == "vc-portfolio-monitor"
    assert resolve_scan_profile("b2b-standard", config.profiles).name == "continuous-devsec"
    assert resolve_scan_profile("due-diligence", config.profiles).name == "pre-investment-dd"
    assert resolve_scan_profile("", config.profiles).name == "crown"
