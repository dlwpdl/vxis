from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from vxis.agent.tools import browser_tools as bt
from vxis.agent.tools.browser_tools import BrowserEvalJsTool


@pytest.mark.asyncio
async def test_strict_egress_blocks_browser_javascript(monkeypatch) -> None:
    page = SimpleNamespace(evaluate=AsyncMock())
    monkeypatch.setattr(bt, "_page", page)
    monkeypatch.setenv("VXIS_EGRESS_STRICT", "1")

    result = await BrowserEvalJsTool().run(
        expression="fetch('https://example.net/relay', {method: 'POST'})"
    )

    assert result.ok is False
    assert result.error == "egress_blocked"
    page.evaluate.assert_not_awaited()


@pytest.mark.asyncio
async def test_browser_javascript_remains_available_outside_strict_mode(monkeypatch) -> None:
    page = SimpleNamespace(evaluate=AsyncMock(return_value="ok"))
    monkeypatch.setattr(bt, "_page", page)
    monkeypatch.delenv("VXIS_EGRESS_STRICT", raising=False)

    result = await BrowserEvalJsTool().run(expression="document.title")

    assert result.ok is True
    page.evaluate.assert_awaited_once_with("document.title")
