import pytest
from pydantic import ValidationError

from vxis.agent.policy.scan_policy import ScanPolicy, ceiling_rank


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
