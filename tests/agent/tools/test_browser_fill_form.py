"""Tests for BrowserFillFormTool failure propagation.

When fill_form can't locate a field, the tool MUST return ok=False and
surface `failed` + `tried_selectors` to Brain so it can PIVOT (e.g., call
browser_analyze_dom before retrying).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from vxis.agent.tools import browser_tools as bt
from vxis.agent.tools.browser_tools import BrowserFillFormTool


@pytest.fixture
def mock_page(monkeypatch):
    """Install a mock BrowserPage as the module-level singleton."""
    page = SimpleNamespace()
    page.fill_form = AsyncMock()
    page.click = AsyncMock()
    page.wait_for_navigation = AsyncMock()
    page.snapshot = AsyncMock(
        return_value=SimpleNamespace(
            url="http://x/home",
            title="Home",
            text_content="ok",
            cookies=[],
            forms=[],
            js_errors=[],
        )
    )
    monkeypatch.setattr(bt, "_page", page)
    return page


@pytest.mark.asyncio
async def test_all_fields_filled_returns_ok(mock_page):
    mock_page.fill_form.return_value = {
        "filled": ["email", "password"],
        "failed": [],
        "tried_selectors": {},
    }
    tool = BrowserFillFormTool()

    result = await tool.run(
        form_selector="form",
        fields={"email": "a@b.c", "password": "x"},
        submit_selector="#loginButton",
    )

    assert result.ok is True
    mock_page.click.assert_awaited_once_with("#loginButton")


@pytest.mark.asyncio
async def test_any_field_failed_returns_not_ok(mock_page):
    mock_page.fill_form.return_value = {
        "filled": ["email"],
        "failed": ["password"],
        "tried_selectors": {
            "password": ["form [name='password']", "form [formcontrolname='password']"]
        },
    }
    tool = BrowserFillFormTool()

    result = await tool.run(
        form_selector="form",
        fields={"email": "a@b.c", "password": "x"},
        submit_selector="#loginButton",
    )

    assert result.ok is False
    assert "password" in result.summary or "failed" in result.summary.lower()
    assert result.data is not None
    assert "password" in result.data["failed"]
    assert "tried_selectors" in result.data


@pytest.mark.asyncio
async def test_failed_fill_skips_submit(mock_page):
    """Broken form — don't click submit (wastes a POST with empty field)."""
    mock_page.fill_form.return_value = {
        "filled": [],
        "failed": ["email", "password"],
        "tried_selectors": {},
    }
    tool = BrowserFillFormTool()

    await tool.run(
        form_selector="form",
        fields={"email": "x", "password": "y"},
        submit_selector="#loginButton",
    )

    mock_page.click.assert_not_called()


@pytest.mark.asyncio
async def test_no_submit_selector_still_ok_on_full_fill(mock_page):
    mock_page.fill_form.return_value = {
        "filled": ["q"],
        "failed": [],
        "tried_selectors": {},
    }
    tool = BrowserFillFormTool()

    result = await tool.run(form_selector="form", fields={"q": "search"})

    assert result.ok is True
    mock_page.click.assert_not_called()


@pytest.mark.asyncio
async def test_missing_page_returns_error():
    tool = BrowserFillFormTool()
    # no monkeypatch — _page is None unless fixture runs
    result = await tool.run(form_selector="form", fields={"x": "y"})
    assert result.ok is False
    assert result.error == "no_page"


@pytest.mark.asyncio
async def test_missing_args_returns_error(mock_page):
    tool = BrowserFillFormTool()
    result = await tool.run(form_selector="", fields={})
    assert result.ok is False
    assert result.error == "missing_args"
