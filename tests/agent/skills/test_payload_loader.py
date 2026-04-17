"""Unit tests for the ADR-007 payload loader.

Pins the loader's behavioural contract so the skill-by-skill migration can
proceed without regressions. The legacy in-file constants are still present
during the migration window (Phase 1–9); these tests depend on that.
"""
from __future__ import annotations

import pytest

from vxis.agent.skills import _payload_loader
from vxis.agent.skills._payload_loader import (
    PayloadDataMissingError,
    clear_cache,
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
