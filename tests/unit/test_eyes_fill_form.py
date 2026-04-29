"""Tests for Eyes.fill_form selector generation and structured return.

Covers Angular Material + a11y selector fallback chain (Juice Shop regression)
and structured-dict return so that BrowserFillFormTool can surface failures to Brain.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from vxis.interaction.eyes import (
    BrowserPage,
    _detect_input_type,
    _fill_form_selectors,
)


# ── _detect_input_type ────────────────────────────────────────────────

class TestDetectInputType:
    @pytest.mark.parametrize("name", ["email", "Email", "E-Mail", "e-mail", "mail"])
    def test_email_variants(self, name):
        assert _detect_input_type(name) == "email"

    @pytest.mark.parametrize("name", ["password", "Password", "passwd", "pwd", "pass"])
    def test_password_variants(self, name):
        assert _detect_input_type(name) == "password"

    @pytest.mark.parametrize("name", ["phone", "tel", "mobile"])
    def test_tel_variants(self, name):
        assert _detect_input_type(name) == "tel"

    @pytest.mark.parametrize("name", ["firstname", "address", "username", "user", "comment"])
    def test_unknown_returns_none(self, name):
        assert _detect_input_type(name) is None


# ── _fill_form_selectors ──────────────────────────────────────────────

class TestFillFormSelectors:
    def test_returns_non_empty_list(self):
        result = _fill_form_selectors("form", "email")
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(s, str) for s in result)

    def test_includes_html_name_scoped(self):
        result = _fill_form_selectors("form", "email")
        assert "form [name='email']" in result

    def test_includes_id_scoped(self):
        result = _fill_form_selectors("form", "email")
        assert "form #email" in result

    def test_includes_angular_formcontrolname_scoped(self):
        """Angular Material reactive forms use formcontrolname=."""
        result = _fill_form_selectors("form", "email")
        assert "form [formcontrolname='email']" in result

    def test_includes_mat_data_placeholder_scoped(self):
        """Angular Material mat-form-field uses data-placeholder."""
        result = _fill_form_selectors("form", "email")
        assert "form [data-placeholder*='email' i]" in result

    def test_includes_aria_label_scoped(self):
        result = _fill_form_selectors("form", "email")
        assert "form [aria-label*='email' i]" in result

    def test_includes_autocomplete_scoped(self):
        result = _fill_form_selectors("form", "email")
        assert "form [autocomplete*='email' i]" in result

    def test_includes_placeholder_scoped(self):
        result = _fill_form_selectors("form", "email")
        assert "form [placeholder*='email' i]" in result

    def test_email_field_adds_type_selector(self):
        result = _fill_form_selectors("form", "email")
        assert "form input[type='email']" in result

    def test_password_field_adds_type_selector(self):
        result = _fill_form_selectors("form", "password")
        assert "form input[type='password']" in result

    def test_unknown_field_no_type_selector(self):
        result = _fill_form_selectors("form", "firstname")
        assert not any("input[type=" in s for s in result)

    def test_includes_global_fallback(self):
        """Scoped selectors may miss if form_selector is wrong; global rescue."""
        result = _fill_form_selectors("form", "email")
        assert "[name='email']" in result
        assert "[formcontrolname='email']" in result

    def test_scoped_before_global(self):
        """Most-specific first; global fallback after."""
        result = _fill_form_selectors("form", "email")
        scoped_idx = result.index("form [name='email']")
        global_idx = result.index("[name='email']")
        assert scoped_idx < global_idx

    def test_empty_form_selector_no_prefix(self):
        """Empty form_selector means only global selectors, no leading space."""
        result = _fill_form_selectors("", "email")
        assert "[name='email']" in result
        assert not any(s.startswith(" ") for s in result)

    def test_field_name_trimmed(self):
        result = _fill_form_selectors("form", "  email  ")
        assert "form [name='email']" in result

    def test_all_selectors_unique(self):
        result = _fill_form_selectors("form", "email")
        assert len(result) == len(set(result))


# ── BrowserPage.fill_form (structured return) ─────────────────────────

@pytest.fixture
def bp_with_mock_page():
    """Yield (bp, mock_page, match_selectors).

    match_selectors is a set — query_selector returns a truthy element
    only when the selector is in this set; caller mutates it per test.
    """
    bp = BrowserPage.__new__(BrowserPage)
    mock_page = MagicMock()
    match_selectors: set[str] = set()

    async def fake_query_selector(sel: str):
        if sel in match_selectors:
            el = MagicMock()
            el.fill = AsyncMock()
            return el
        return None

    mock_page.query_selector = AsyncMock(side_effect=fake_query_selector)
    bp._page = mock_page
    return bp, mock_page, match_selectors


@pytest.mark.asyncio
async def test_fill_form_returns_structured_dict_on_success(bp_with_mock_page):
    bp, _page, matches = bp_with_mock_page
    matches.add("form [name='email']")
    matches.add("form [name='password']")

    result = await bp.fill_form("form", {"email": "a@b.c", "password": "x"})

    assert isinstance(result, dict)
    assert set(result.keys()) == {"filled", "failed", "tried_selectors"}
    assert result["filled"] == ["email", "password"]
    assert result["failed"] == []


@pytest.mark.asyncio
async def test_fill_form_marks_failures(bp_with_mock_page):
    bp, _page, matches = bp_with_mock_page
    matches.add("form [name='email']")
    # password has no match — all selectors fail

    result = await bp.fill_form("form", {"email": "a@b.c", "password": "x"})

    assert "email" in result["filled"]
    assert "password" in result["failed"]


@pytest.mark.asyncio
async def test_fill_form_records_tried_selectors(bp_with_mock_page):
    bp, _page, matches = bp_with_mock_page
    # no matches at all
    result = await bp.fill_form("form", {"email": "x"})

    tried = result["tried_selectors"]["email"]
    assert "form [name='email']" in tried
    assert "form [formcontrolname='email']" in tried
    assert "form input[type='email']" in tried


@pytest.mark.asyncio
async def test_fill_form_angular_material_fallback(bp_with_mock_page):
    """Juice Shop regression: HTML name= absent, Angular formcontrolname= present."""
    bp, _page, matches = bp_with_mock_page
    matches.add("form [formcontrolname='email']")

    result = await bp.fill_form("form", {"email": "admin@juice-sh.op"})

    assert result["filled"] == ["email"]
    assert result["failed"] == []


@pytest.mark.asyncio
async def test_fill_form_global_fallback_when_form_misses(bp_with_mock_page):
    """If form_selector doesn't match, global selectors should rescue."""
    bp, _page, matches = bp_with_mock_page
    matches.add("[formcontrolname='email']")  # global only

    result = await bp.fill_form("form", {"email": "x"})

    assert result["filled"] == ["email"]
