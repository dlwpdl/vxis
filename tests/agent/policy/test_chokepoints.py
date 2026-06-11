import hashlib

from vxis.agent.policy.chokepoints import permit_strategy, persist_secret
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


def test_persist_secret_denies_on_none_policy():
    d = persist_secret("hunter2", None)
    assert d.allowed is False
    assert d.verdict == "FORBIDDEN"
    assert d.stored_value is None


def test_persist_secret_fingerprints_when_encrypt_redact():
    d = persist_secret("supersecrettoken", _policy(secret_handling="encrypt-redact"))
    assert d.allowed is True
    assert "supersecrettoken" not in d.stored_value
    expected = hashlib.sha256(b"supersecrettoken").hexdigest()
    assert expected in d.stored_value
    assert d.stored_value.endswith("oken")  # last4 retained


def test_persist_secret_returns_raw_when_plaintext_lab():
    d = persist_secret("supersecrettoken", _policy(secret_handling="plaintext-lab"))
    assert d.allowed is True
    assert d.stored_value == "supersecrettoken"


def test_persist_secret_short_secret_not_exposed_under_encrypt_redact():
    d = persist_secret("pin", _policy(secret_handling="encrypt-redact"))
    assert d.allowed is True
    assert "pin" not in d.stored_value  # short secret: no raw tail
    assert d.stored_value.endswith(":")  # empty last4 segment
