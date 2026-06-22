import pytest
from vxis.mission.config import MissionConfig, Depth, Perspective, Scope


def test_mission_config_defaults():
    cfg = MissionConfig(target="example.com")
    assert cfg.depth == Depth.NORMAL
    assert not cfg.stealth
    assert cfg.perspective == Perspective.EXTERNAL


def test_mission_config_full():
    cfg = MissionConfig(
        target="*.acme.com",
        depth=Depth.ELITE,
        stealth=True,
        perspective=Perspective.BOTH,
        scope=Scope.FULL,
        client_id="acme-corp",
    )
    assert cfg.target == "*.acme.com"
    assert cfg.depth == Depth.ELITE
    assert cfg.stealth


def test_mission_config_from_toml(tmp_path):
    toml_content = """
[mission]
target = "*.acme.com"
depth = "elite"
stealth = true
perspective = "external"
scope = "full"

[memory]
client_id = "acme-corp"
learn = true
"""
    cfg_file = tmp_path / "mission.toml"
    cfg_file.write_text(toml_content)
    cfg = MissionConfig.from_file(str(cfg_file))
    assert cfg.target == "*.acme.com"
    assert cfg.depth == Depth.ELITE


def test_invalid_depth_raises():
    with pytest.raises(ValueError):
        MissionConfig(target="example.com", depth="ultra")
