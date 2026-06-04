from __future__ import annotations

from vxis.scoring.benchmark_league import (
    default_crown_benchmark_league,
    render_benchmark_league_markdown,
)


def test_crown_benchmark_league_has_multiple_target_tiers() -> None:
    league = default_crown_benchmark_league()

    assert league.profile == "crown"
    assert league.targets_by_tier("known_vulnerable")
    assert league.targets_by_tier("api_auth")
    assert league.targets_by_tier("negative_control")
    assert league.targets_by_tier("randomized_arena")
    assert league.targets_by_tier("secret_holdout")
    assert any(target.target_id == "juice-shop" for target in league.targets)
    assert any("single-target" in rule for rule in league.anti_overfit_rules)


def test_crown_benchmark_league_renders_markdown() -> None:
    rendered = render_benchmark_league_markdown()

    assert "crown-default-v1" in rendered
    assert "juice-shop" in rendered
    assert "Anti-Overfit" in rendered
