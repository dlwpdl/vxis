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
            "{\"role\":\"user\"}"
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
            "{\"id\":3,\"email\":\"victim@app.local\"}"
        ),
        evidence="HTTP/1.1 200 OK\n{\"id\":3,\"email\":\"victim@app.local\"}",
    )
    assert result.ok is True
    assert result.data["verdict"] == "CONFIRMED"
    assert result.data.get("preflight_blocked") is not True


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
            "{\"id\":3,\"email\":\"victim@app.local\"}"
        ),
        evidence="HTTP/1.1 200 OK\n{\"id\":3,\"email\":\"victim@app.local\"}",
    )
    assert result.ok is False
    assert result.error == "non_text_response"
