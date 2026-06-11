import pytest
from pydantic import ValidationError

from vxis.agent.policy.scan_policy import (
    FAIL_CLOSED_DEFAULT,
    PROFILE_POLICY_TABLE,
    ScanPolicy,
    ceiling_rank,
    resolve_policy,
)
from vxis.config.schema import _PROFILE_ALIASES, _default_profiles, normalize_scan_profile_name


def _policy(**overrides):
    base = dict(
        exploitation_ceiling="lateral",
        scope_strictness="strict-authorized",
        tenant_isolation=True,
        secret_handling="encrypt-redact",
        evasion_allowed=False,
        deferred_mutation_approval=True,
    )
    base.update(overrides)
    return ScanPolicy(**base)


def test_scan_policy_is_frozen():
    p = _policy()
    with pytest.raises(ValidationError):
        p.exploitation_ceiling = "full"


def test_scan_policy_rejects_unknown_ceiling():
    with pytest.raises(ValidationError):
        _policy(exploitation_ceiling="god-mode")


def test_ceiling_rank_is_ordered():
    assert (
        ceiling_rank("none")
        < ceiling_rank("read-only")
        < ceiling_rank("lateral")
        < ceiling_rank("full")
    )


def test_ceiling_rank_unknown_is_most_restrictive():
    assert ceiling_rank("god-mode") == 0
    assert ceiling_rank("") == 0


class _Cfg:
    def __init__(self, active_profile):
        self.active_profile = active_profile


def test_resolve_crown_is_lateral():
    assert resolve_policy(_Cfg("crown")).exploitation_ceiling == "lateral"


def test_resolve_aggressive_is_full_lab():
    p = resolve_policy(_Cfg("aggressive"))
    assert p.exploitation_ceiling == "full"
    assert p.scope_strictness == "lab-allowlist"
    assert p.secret_handling == "plaintext-lab"


def test_resolve_p1_alias_is_full():
    assert resolve_policy(_Cfg("p1")).exploitation_ceiling == "full"


def test_resolve_compliance_mapping_is_none():
    assert resolve_policy(_Cfg("compliance-mapping")).exploitation_ceiling == "none"


def test_resolve_unknown_profile_is_fail_closed():
    assert resolve_policy(_Cfg("totally-made-up")) == FAIL_CLOSED_DEFAULT
    assert resolve_policy(_Cfg("totally-made-up")).exploitation_ceiling == "none"


def test_resolve_none_config_is_fail_closed():
    assert resolve_policy(None) == FAIL_CLOSED_DEFAULT


def test_resolve_empty_profile_is_fail_closed():
    assert resolve_policy(_Cfg("")).exploitation_ceiling == "none"
    assert resolve_policy(_Cfg(None)).exploitation_ceiling == "none"


def test_every_builtin_profile_has_an_explicit_policy_row():
    for name in _default_profiles():
        assert name in PROFILE_POLICY_TABLE, f"profile {name!r} missing from PROFILE_POLICY_TABLE"


def test_every_alias_target_has_an_explicit_policy_row():
    for alias, target in _PROFILE_ALIASES.items():
        resolved = normalize_scan_profile_name(alias)
        assert resolved in PROFILE_POLICY_TABLE, f"alias {alias!r}->{resolved!r} has no policy row"
