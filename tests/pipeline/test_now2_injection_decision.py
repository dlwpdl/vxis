"""NOW-2/2e (F3) — the injection-approval decision is actually resolved.

The CLI injection gate (and auto_approve_injection) used to be stored but never
invoked, so the approval UI applied no protection. _resolve_injection_decision now
calls the callback / honors auto-approve once per scan (when the capability-ceiling
policy is active) and publishes the decision for the dispatch injection gate.
"""
import pytest

from vxis.pipeline.scan_pipeline_v2 import ScanPipeline


class _Ctx:
    target = "http://t"
    scan_id = "scan-1"


@pytest.mark.asyncio
async def test_auto_approve_resolves_to_full(monkeypatch):
    monkeypatch.setenv("VXIS_V3_POLICY", "1")
    p = ScanPipeline(brain=object(), auto_approve_injection=True)
    assert await p._resolve_injection_decision(_Ctx()) == "full"


@pytest.mark.asyncio
async def test_callback_deny_is_honored(monkeypatch):
    monkeypatch.setenv("VXIS_V3_POLICY", "1")
    calls = []

    async def cb(summary):
        calls.append(summary)
        return "deny"

    p = ScanPipeline(brain=object(), injection_approval_callback=cb)
    assert await p._resolve_injection_decision(_Ctx()) == "deny"
    assert calls and calls[0]["target"] == "http://t"  # callback was actually invoked


@pytest.mark.asyncio
async def test_callback_readonly_is_honored(monkeypatch):
    monkeypatch.setenv("VXIS_V3_POLICY", "1")

    async def cb(summary):
        return "readonly"

    p = ScanPipeline(brain=object(), injection_approval_callback=cb)
    assert await p._resolve_injection_decision(_Ctx()) == "readonly"


@pytest.mark.asyncio
async def test_callback_exception_fails_closed_deny(monkeypatch):
    monkeypatch.setenv("VXIS_V3_POLICY", "1")

    async def cb(summary):
        raise RuntimeError("ui crashed")

    p = ScanPipeline(brain=object(), injection_approval_callback=cb)
    assert await p._resolve_injection_decision(_Ctx()) == "deny"  # fail-closed


@pytest.mark.asyncio
async def test_no_mechanism_is_legacy_none(monkeypatch):
    monkeypatch.setenv("VXIS_V3_POLICY", "1")
    p = ScanPipeline(brain=object())  # no auto-approve, no callback
    assert await p._resolve_injection_decision(_Ctx()) is None
