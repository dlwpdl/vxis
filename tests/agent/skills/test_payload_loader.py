"""Unit tests for the ADR-007 payload loader.

Pins the loader's behavioural contract so the skill-by-skill migration can
proceed without regressions. The legacy in-file constants are still present
during the migration window (Phase 1–9); these tests depend on that.
"""
from __future__ import annotations

import pytest

from vxis.agent.skills import _payload_loader
from vxis.agent.skills._payload_loader import (
    PayloadDatasetMissingError,
    PayloadDataMissingError,
    clear_cache,
    load_skill_dataset,
    load_skill_payloads,
)


@pytest.fixture(autouse=True)
def _reset_loader_cache():
    clear_cache()
    yield
    clear_cache()


class TestInjectionParity:
    """Loader output must equal the legacy PAYLOADS constants, byte-for-byte."""

    def test_round1_matches_legacy_constant(self):
        from vxis.agent.skills.test_injection import PAYLOADS

        assert load_skill_payloads("injection", 1) == PAYLOADS

    def test_round2_matches_legacy_constant(self):
        from vxis.agent.skills.test_injection import PAYLOADS_ROUND2

        assert load_skill_payloads("injection", 2) == PAYLOADS_ROUND2

    def test_round3_matches_legacy_constant(self):
        from vxis.agent.skills.test_injection import PAYLOADS_ROUND3

        assert load_skill_payloads("injection", 3) == PAYLOADS_ROUND3

    def test_round4_returns_union_of_all_rounds(self):
        from vxis.agent.skills.test_injection import (
            PAYLOADS,
            PAYLOADS_ROUND2,
            PAYLOADS_ROUND3,
        )

        assert load_skill_payloads("injection", 4) == (
            PAYLOADS + PAYLOADS_ROUND2 + PAYLOADS_ROUND3
        )

    def test_round0_also_returns_union(self):
        """Scan_loop may pass r<=0 if round counter underflows — treat as exhaustive."""
        r0 = load_skill_payloads("injection", 0)
        r4 = load_skill_payloads("injection", 4)
        assert r0 == r4


class TestXssParity:
    """ADR-007 Phase 2 — xss.json must match legacy XSS_PAYLOADS* byte-for-byte."""

    def test_round1_matches_legacy_constant(self):
        from vxis.agent.skills.test_xss import XSS_PAYLOADS

        assert load_skill_payloads("xss", 1) == XSS_PAYLOADS

    def test_round2_matches_legacy_constant(self):
        from vxis.agent.skills.test_xss import XSS_PAYLOADS_ROUND2

        assert load_skill_payloads("xss", 2) == XSS_PAYLOADS_ROUND2

    def test_round3_matches_legacy_constant(self):
        from vxis.agent.skills.test_xss import XSS_PAYLOADS_ROUND3

        assert load_skill_payloads("xss", 3) == XSS_PAYLOADS_ROUND3

    def test_round4_returns_union_of_all_rounds(self):
        from vxis.agent.skills.test_xss import (
            XSS_PAYLOADS,
            XSS_PAYLOADS_ROUND2,
            XSS_PAYLOADS_ROUND3,
        )

        assert load_skill_payloads("xss", 4) == (
            XSS_PAYLOADS + XSS_PAYLOADS_ROUND2 + XSS_PAYLOADS_ROUND3
        )

    def test_xss_payloads_for_round_delegates_to_loader(self):
        from vxis.agent.skills.test_xss import _xss_payloads_for_round

        for r in (1, 2, 3, 4):
            assert _xss_payloads_for_round(r) == load_skill_payloads("xss", r)


class TestLoaderContract:
    def test_missing_skill_raises_fail_loud(self):
        with pytest.raises(PayloadDataMissingError):
            load_skill_payloads("skill_does_not_exist_xyz", 1)

    def test_load_is_cached(self):
        """Second call must hit the functools.cache, not re-read the file."""
        load_skill_payloads("injection", 1)
        cache_info_before = _payload_loader._load_file.cache_info()
        load_skill_payloads("injection", 2)
        cache_info_after = _payload_loader._load_file.cache_info()
        assert cache_info_after.hits == cache_info_before.hits + 1
        assert cache_info_after.misses == cache_info_before.misses

    def test_payload_for_round_in_test_injection_delegates_to_loader(self):
        """`_payloads_for_round(r)` must now return the loader's output verbatim."""
        from vxis.agent.skills.test_injection import _payloads_for_round

        for r in (1, 2, 3, 4):
            assert _payloads_for_round(r) == load_skill_payloads("injection", r)


class TestSkillDataset:
    """ADR-007 Phase 3-9 — non-rotation datasets for 12 skills."""

    def test_missing_dataset_raises_fail_loud(self):
        with pytest.raises(PayloadDatasetMissingError):
            load_skill_dataset("attempt_auth", "does_not_exist_key")

    @pytest.mark.parametrize("skill,key,expected_count", [
        ("attempt_auth", "default_creds", 13),
        ("attempt_auth", "sqli_creds", 4),
        ("attempt_auth", "login_paths", 11),
        ("attempt_auth", "reset_paths", 5),
        ("enumerate_endpoints", "common_paths", 130),
        ("post_auth_enum", "auth_paths", 37),
        ("test_sensitive_files", "sensitive_paths", 54),
        ("test_auth_deep", "jwt_alg_none_headers", 4),
        ("test_auth_deep", "reset_paths", 6),
        ("test_csrf", "state_changing_paths", 14),
        ("test_ssrf", "ssrf_payloads", 20),
        ("test_ssrf", "url_params", 11),
        ("test_api_security", "mass_assign_fields", 8),
        ("test_api_security", "verb_tamper_paths", 6),
        ("test_misconfig", "required_headers", 7),
        ("test_misconfig", "debug_paths", 15),
        ("test_misconfig", "cors_origins", 3),
        ("test_business_logic", "logic_tests", 12),
        ("test_crypto", "secret_patterns", 10),
        ("test_crypto", "js_paths", 10),
        ("test_infra", "git_paths", 6),
        ("test_infra", "env_paths", 9),
        ("test_infra", "cloud_endpoints", 4),
        ("test_infra", "subdomain_prefixes", 20),
    ])
    def test_dataset_count_pinned(self, skill, key, expected_count):
        """Pin item counts so growth loop appends are caught in review."""
        assert len(load_skill_dataset(skill, key)) == expected_count

    def test_skill_module_constant_matches_loader_output(self):
        """Skill module constants must equal loader output (normalized for tuples)."""
        def norm(x):
            if isinstance(x, (list, tuple)):
                return [norm(i) for i in x]
            return x

        import importlib

        cases = [
            ("attempt_auth", "DEFAULT_CREDS", "default_creds"),
            ("enumerate_endpoints", "COMMON_PATHS", "common_paths"),
            ("test_sensitive_files", "SENSITIVE_PATHS", "sensitive_paths"),
            ("test_csrf", "STATE_CHANGING_PATHS", "state_changing_paths"),
            ("test_ssrf", "SSRF_PAYLOADS", "ssrf_payloads"),
            ("test_misconfig", "REQUIRED_HEADERS", "required_headers"),
            ("test_business_logic", "LOGIC_TESTS", "logic_tests"),
            ("test_crypto", "SECRET_PATTERNS", "secret_patterns"),
            ("test_infra", "GIT_PATHS", "git_paths"),
        ]
        for skill, const, key in cases:
            mod = importlib.import_module(f"vxis.agent.skills.{skill}")
            assert norm(getattr(mod, const)) == norm(load_skill_dataset(skill, key)), (
                f"{skill}.{const} diverges from datasets.{key}"
            )
