"""Unit tests for vxis.core.scope.

All tests are synchronous — no async I/O is required for scope validation.
"""

from __future__ import annotations

import pytest

from vxis.core.scope import ScopeValidator, ScopeViolationError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def basic_validator() -> ScopeValidator:
    """Validator with a mix of CIDR and domain targets, and one exclusion."""
    return ScopeValidator(
        targets=["192.168.1.0/24", "example.com", "*.staging.example.com"],
        exclude_targets=["malicious.example.com"],
        exclude_ports=[22, 23],
    )


# ---------------------------------------------------------------------------
# Domain matching
# ---------------------------------------------------------------------------


class TestDomainScoping:
    def test_exact_domain_is_in_scope(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_in_scope("example.com") is True

    def test_subdomain_is_in_scope(self, basic_validator: ScopeValidator) -> None:
        # sub.example.com is a subdomain of example.com
        assert basic_validator.is_in_scope("sub.example.com") is True

    def test_unrelated_domain_is_out_of_scope(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_in_scope("attacker.com") is False

    def test_partial_suffix_is_not_a_subdomain(self, basic_validator: ScopeValidator) -> None:
        # 'notexample.com' should NOT match 'example.com'
        assert basic_validator.is_in_scope("notexample.com") is False


# ---------------------------------------------------------------------------
# Wildcard / multi-level subdomain targets
# ---------------------------------------------------------------------------


class TestWildcardTargets:
    def test_wildcard_target_matches_direct_subdomain(self) -> None:
        # *.example.com is stored as 'example.com' so subdomains match
        validator = ScopeValidator(
            targets=["*.example.com"],
            exclude_targets=[],
        )
        assert validator.is_in_scope("app.example.com") is True

    def test_wildcard_target_matches_nested_subdomain(self) -> None:
        validator = ScopeValidator(
            targets=["*.example.com"],
            exclude_targets=[],
        )
        assert validator.is_in_scope("deep.sub.example.com") is True

    def test_wildcard_does_not_match_different_domain(self) -> None:
        validator = ScopeValidator(
            targets=["*.example.com"],
            exclude_targets=[],
        )
        assert validator.is_in_scope("example.org") is False


# ---------------------------------------------------------------------------
# IP / CIDR matching
# ---------------------------------------------------------------------------


class TestIPScoping:
    def test_ip_inside_cidr_is_in_scope(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_in_scope("192.168.1.100") is True

    def test_network_address_itself_is_in_scope(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_in_scope("192.168.1.0") is True

    def test_broadcast_address_is_in_scope(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_in_scope("192.168.1.255") is True

    def test_ip_outside_cidr_is_out_of_scope(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_in_scope("192.168.2.1") is False

    def test_completely_different_ip_is_out_of_scope(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_in_scope("10.0.0.1") is False

    def test_single_ip_target(self) -> None:
        validator = ScopeValidator(
            targets=["10.10.10.5"],
            exclude_targets=[],
        )
        assert validator.is_in_scope("10.10.10.5") is True
        assert validator.is_in_scope("10.10.10.6") is False


# ---------------------------------------------------------------------------
# Exclusions
# ---------------------------------------------------------------------------


class TestExclusions:
    def test_excluded_domain_is_out_of_scope(self, basic_validator: ScopeValidator) -> None:
        # malicious.example.com would match example.com but is explicitly excluded
        assert basic_validator.is_in_scope("malicious.example.com") is False

    def test_exclusion_overrides_inclusion(self) -> None:
        """An excluded CIDR takes priority over an included parent CIDR."""
        validator = ScopeValidator(
            targets=["10.0.0.0/8"],
            exclude_targets=["10.99.0.0/16"],
        )
        assert validator.is_in_scope("10.99.0.5") is False
        assert validator.is_in_scope("10.1.2.3") is True

    def test_non_excluded_subdomain_is_still_in_scope(
        self, basic_validator: ScopeValidator
    ) -> None:
        assert basic_validator.is_in_scope("benign.example.com") is True


# ---------------------------------------------------------------------------
# validate() raises / passes
# ---------------------------------------------------------------------------


class TestValidate:
    def test_validate_raises_for_out_of_scope_target(
        self, basic_validator: ScopeValidator
    ) -> None:
        with pytest.raises(ScopeViolationError) as exc_info:
            basic_validator.validate("evil.com")

        err = exc_info.value
        assert err.target == "evil.com"
        assert "192.168.1.0/24" in err.scope_targets

    def test_validate_does_not_raise_for_in_scope_target(
        self, basic_validator: ScopeValidator
    ) -> None:
        assert basic_validator.validate("192.168.1.50") is None

    def test_scope_violation_error_message_contains_target(
        self, basic_validator: ScopeValidator
    ) -> None:
        with pytest.raises(ScopeViolationError) as exc_info:
            basic_validator.validate("unknown.net")
        assert "unknown.net" in str(exc_info.value)

    def test_scope_violation_error_attributes(self) -> None:
        err = ScopeViolationError("bad.com", ["good.com", "10.0.0.0/8"])
        assert err.target == "bad.com"
        assert err.scope_targets == ["good.com", "10.0.0.0/8"]


# ---------------------------------------------------------------------------
# Port allowance
# ---------------------------------------------------------------------------


class TestPortAllowance:
    def test_allowed_port_returns_true(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_port_allowed(80) is True
        assert basic_validator.is_port_allowed(443) is True

    def test_excluded_port_returns_false(self, basic_validator: ScopeValidator) -> None:
        assert basic_validator.is_port_allowed(22) is False
        assert basic_validator.is_port_allowed(23) is False

    def test_no_excluded_ports_all_allowed(self) -> None:
        validator = ScopeValidator(
            targets=["example.com"],
            exclude_targets=[],
            exclude_ports=None,
        )
        assert validator.is_port_allowed(22) is True
        assert validator.is_port_allowed(3389) is True
