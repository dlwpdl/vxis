"""NOW-3 #2 — attack-level badge derived from a profile's ScanPolicy.

Quantifies "공격레벨 딱 수치화": a 0–3 rank from exploitation_ceiling
(none→read-only→lateral→full) plus risk flags (lab-only / evasion-on /
approval-required) read straight from PROFILE_POLICY_TABLE, so the TUI/dashboard
display can never drift from the policy actually enforced.
"""
from vxis.agent.policy.scan_policy import attack_level_badge


def test_badge_ranks_by_ceiling():
    assert attack_level_badge("compliance-mapping")["rank"] == 0  # none
    assert attack_level_badge("standard")["rank"] == 1  # read-only
    assert attack_level_badge("crown")["rank"] == 2  # lateral
    assert attack_level_badge("aggressive")["rank"] == 3  # full


def test_badge_exposes_ceiling_and_bars():
    crown = attack_level_badge("crown")
    assert crown["ceiling"] == "lateral"
    assert crown["bars"].count("●") == 2  # ● filled = rank
    assert len(crown["bars"]) == 3  # always 3 cells (filled + empty)


def test_badge_risk_flags():
    agg = attack_level_badge("aggressive")
    assert "lab-only" in agg["flags"]  # scope_strictness == lab-allowlist
    assert "evasion-on" in agg["flags"]  # evasion_allowed
    crown = attack_level_badge("crown")
    assert "approval-required" in crown["flags"]  # deferred_mutation_approval
    assert "lab-only" not in crown["flags"]
    assert "evasion-on" not in crown["flags"]


def test_badge_unknown_profile_fails_closed_to_none():
    b = attack_level_badge("totally-not-a-profile")
    assert b["rank"] == 0  # FAIL_CLOSED_DEFAULT ceiling == none
    assert b["ceiling"] == "none"


def test_badge_normalizes_profile_name():
    # accepts the same aliases as resolve_policy
    assert attack_level_badge("CROWN")["rank"] == attack_level_badge("crown")["rank"]
