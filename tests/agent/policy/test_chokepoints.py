from vxis.agent.policy.chokepoints import permit_strategy
from vxis.agent.policy.scan_policy import ScanPolicy


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


def test_permit_strategy_denies_on_none_policy():
    d = permit_strategy("ghost", None)
    assert d.allowed is False
    assert d.verdict == "FORBIDDEN"


def test_permit_strategy_blocks_evasion_when_not_allowed():
    d = permit_strategy("ghost", _policy(evasion_allowed=False))
    assert d.allowed is False


def test_permit_strategy_allows_evasion_when_allowed():
    d = permit_strategy("ghost", _policy(evasion_allowed=True))
    assert d.allowed is True
    assert d.verdict == "ALLOW"


def test_permit_strategy_allows_non_evasion_strategy():
    d = permit_strategy("skill_mutation", _policy(evasion_allowed=False))
    assert d.allowed is True
