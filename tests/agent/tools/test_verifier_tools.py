from __future__ import annotations

import pytest

from vxis.agent.tools.verifier_tools import VerifyFindingTool


class _FakeBrain:
    _provider = "openai"
    _model = "gpt-5.4"

    def _call_llm_with_fallback(self, system: str, user: str) -> str:
        return (
            "VERDICT: CONFIRMED\n"
            "CONFIDENCE: high\n"
            "REASONING: The transcript contains a concrete exploit attempt and matching response."
        )


class _WeirdBrain:
    _provider = "openai"
    _model = "gpt-5.4"

    def _call_llm_with_fallback(self, system: str, user: str):
        return {"not": "text"}


class _RoleBrain:
    _provider = "openai"
    _model = "gpt-5.4-mini"

    def __init__(self) -> None:
        self.roles: list[str] = []

    def _call_llm_for_role(self, role: str, system: str, user: str) -> str:
        self.roles.append(role)
        return "VERDICT: CONFIRMED\nCONFIDENCE: high\nREASONING: Verifier role was used."


@pytest.mark.asyncio
async def test_verify_finding_refutes_incomplete_high_severity_report() -> None:
    tool = VerifyFindingTool(brain=_FakeBrain())
    result = await tool.run(
        title="SQLi",
        severity="high",
        finding_type="sql_injection",
        affected_component="/login",
        description="Possible SQLi",
        evidence="payload worked",
    )
    assert result.ok is True
    assert result.data["verdict"] == "REFUTED"
    assert result.data["preflight_blocked"] is True


@pytest.mark.asyncio
async def test_verify_finding_marks_high_risk_finding_unconfirmed_without_control() -> None:
    tool = VerifyFindingTool(brain=_FakeBrain())
    result = await tool.run(
        title="Auth bypass",
        severity="high",
        finding_type="auth_bypass",
        affected_component="/api/login",
        description="Login accepted forged token",
        impact="Attacker obtains authenticated access.",
        technical_analysis="The forged token was accepted and the server returned a session.",
        poc_description="Send a forged token and observe a valid session response.",
        poc_script_code=(
            "POST /api/login HTTP/1.1\n"
            "Host: app.local\n"
            "Authorization: Bearer forged-token\n\n"
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: session=abc\n\n"
            '{"role":"user"}'
        ),
        evidence="HTTP/1.1 200 OK\nSet-Cookie: session=abc",
    )
    assert result.ok is True
    assert result.data["verdict"] == "UNCONFIRMED"
    assert result.data["preflight_blocked"] is True


@pytest.mark.asyncio
async def test_verify_finding_calls_llm_when_poc_and_control_exist() -> None:
    tool = VerifyFindingTool(brain=_FakeBrain())
    result = await tool.run(
        title="IDOR",
        severity="high",
        finding_type="idor",
        affected_component="/api/users/2",
        description="Access to another user's record",
        impact="Attacker can read another user's data.",
        technical_analysis=(
            "Control check: unauthenticated request to /api/users/2 returned 401, "
            "but the same low-privilege session could access /api/users/3 and receive another user's profile."
        ),
        poc_description="Compare the control request and the authenticated replay against adjacent user IDs.",
        poc_script_code=(
            "GET /api/users/2 HTTP/1.1\n"
            "Host: app.local\n\n"
            "HTTP/1.1 401 Unauthorized\n\n"
            "GET /api/users/3 HTTP/1.1\n"
            "Host: app.local\n"
            "Cookie: session=low-user\n\n"
            "HTTP/1.1 200 OK\n\n"
            '{"id":3,"email":"victim@app.local"}'
        ),
        evidence='HTTP/1.1 200 OK\n{"id":3,"email":"victim@app.local"}',
    )
    assert result.ok is True
    assert result.data["verdict"] == "CONFIRMED"
    assert result.data.get("preflight_blocked") is not True


@pytest.mark.asyncio
async def test_verify_finding_uses_verifier_role_when_available() -> None:
    brain = _RoleBrain()
    tool = VerifyFindingTool(brain=brain)
    result = await tool.run(
        title="IDOR",
        severity="high",
        finding_type="idor",
        affected_component="/api/users/2",
        description="Access to another user's record",
        impact="Attacker can read another user's data.",
        technical_analysis=(
            "Control check: unauthenticated request to /api/users/2 returned 401, "
            "but the same low-privilege session could access /api/users/3 and receive another user's profile."
        ),
        poc_description="Compare the control request and the authenticated replay against adjacent user IDs.",
        poc_script_code=(
            "GET /api/users/2 HTTP/1.1\n"
            "Host: app.local\n\n"
            "HTTP/1.1 401 Unauthorized\n\n"
            "GET /api/users/3 HTTP/1.1\n"
            "Host: app.local\n"
            "Cookie: session=low-user\n\n"
            "HTTP/1.1 200 OK\n\n"
            '{"id":3,"email":"victim@app.local"}'
        ),
        evidence='HTTP/1.1 200 OK\n{"id":3,"email":"victim@app.local"}',
    )

    assert result.ok is True
    assert result.data["verdict"] == "CONFIRMED"
    assert brain.roles == ["verifier"]


@pytest.mark.asyncio
async def test_verify_finding_rejects_non_text_llm_responses() -> None:
    tool = VerifyFindingTool(brain=_WeirdBrain())
    result = await tool.run(
        title="IDOR",
        severity="high",
        finding_type="idor",
        affected_component="/api/users/2",
        description="Access to another user's record",
        impact="Attacker can read another user's data.",
        technical_analysis=(
            "Control check: unauthenticated request to /api/users/2 returned 401, "
            "but the same low-privilege session could access /api/users/3 and receive another user's profile."
        ),
        poc_description="Compare the control request and the authenticated replay against adjacent user IDs.",
        poc_script_code=(
            "GET /api/users/2 HTTP/1.1\n"
            "Host: app.local\n\n"
            "HTTP/1.1 401 Unauthorized\n\n"
            "GET /api/users/3 HTTP/1.1\n"
            "Host: app.local\n"
            "Cookie: session=low-user\n\n"
            "HTTP/1.1 200 OK\n\n"
            '{"id":3,"email":"victim@app.local"}'
        ),
        evidence='HTTP/1.1 200 OK\n{"id":3,"email":"victim@app.local"}',
    )
    assert result.ok is False
    assert result.error == "non_text_response"


# Fix 1 — legacy else-branch must not mutate brain._model across an await
class _LegacyBrain:
    """Brain with only _call_llm_with_fallback (no _call_llm_for_role).

    Represents the older/fake brain objects that fall into the legacy else-branch.
    The _model is set to a mini variant so the old mutation condition triggers.
    """

    _provider = "openai"
    _model = "gpt-5.4-mini"

    def _call_llm_with_fallback(self, system: str, user: str) -> str:
        # Record model value at call time; should NOT be "gpt-5.4" (the swapped value)
        self._model_at_call_time = self._model
        return "VERDICT: CONFIRMED\nCONFIDENCE: high\nREASONING: Legacy path used."


@pytest.mark.asyncio
async def test_legacy_branch_does_not_mutate_brain_model(monkeypatch: pytest.MonkeyPatch) -> None:
    """The legacy else-branch must not write brain._model to 'gpt-5.4' during a call,
    confirming the TOCTOU race is gone.

    We set OPENAI_API_KEY so the old mutation condition in the else-branch fires,
    then assert brain._model is unchanged at call time and after the call.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-fake")
    brain = _LegacyBrain()
    original_model = brain._model
    tool = VerifyFindingTool(brain=brain)
    await tool.run(
        title="IDOR",
        severity="low",  # low severity to skip the high-severity preflight checks
        finding_type="idor",
        affected_component="/api/users/2",
        description="Access to another user's record",
        evidence=(
            "GET /api/users/2 HTTP/1.1\n"
            "Host: app.local\n\n"
            "HTTP/1.1 200 OK\n\n"
            '{"id":2,"email":"victim@app.local"}'
        ),
    )
    # brain._model must be unchanged — the legacy branch must not mutate shared state
    assert brain._model == original_model, (
        f"Legacy branch mutated brain._model from {original_model!r} to {brain._model!r}"
    )
    # Also assert the model at call time was never swapped to the stronger model
    assert getattr(brain, "_model_at_call_time", original_model) == original_model, (
        "brain._model was temporarily swapped to a stronger model during the LLM call — "
        "this creates a TOCTOU race for concurrent coroutines"
    )
