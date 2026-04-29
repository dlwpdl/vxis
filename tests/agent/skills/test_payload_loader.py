"""Unit tests for the ADR-007 payload loader.

Pins the loader's behavioural contract. After Phase 11 the legacy
in-file ``PAYLOADS*`` / ``XSS_PAYLOADS*`` constants are gone — parity is
enforced by per-skill dataset counts + module-constant comparisons (for
skills that still surface loader output as a module-level constant).
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


class TestRotationContract:
    """Rotation count pins + union semantics for r<=0 / r>=4."""

    @pytest.mark.parametrize("skill,r,expected_count", [
        ("injection", 1, 32),
        ("injection", 2, 21),
        ("injection", 3, 16),
        ("xss", 1, 20),
        ("xss", 2, 20),
        ("xss", 3, 16),
    ])
    def test_round_count_pinned(self, skill, r, expected_count):
        assert len(load_skill_payloads(skill, r)) == expected_count

    @pytest.mark.parametrize("skill", ["injection", "xss"])
    def test_round4_returns_union_of_all_rounds(self, skill):
        r1 = load_skill_payloads(skill, 1)
        r2 = load_skill_payloads(skill, 2)
        r3 = load_skill_payloads(skill, 3)
        assert load_skill_payloads(skill, 4) == r1 + r2 + r3

    @pytest.mark.parametrize("skill", ["injection", "xss"])
    def test_round0_also_returns_union(self, skill):
        """Scan_loop may pass r<=0 if round counter underflows — treat as exhaustive."""
        assert load_skill_payloads(skill, 0) == load_skill_payloads(skill, 4)

    def test_payload_for_round_in_test_injection_delegates_to_loader(self):
        from vxis.agent.skills.test_injection import _payloads_for_round

        for r in (1, 2, 3, 4):
            assert _payloads_for_round(r) == load_skill_payloads("injection", r)

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
