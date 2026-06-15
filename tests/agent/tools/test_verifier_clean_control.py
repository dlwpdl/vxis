"""NOW-1/1.4 — CI clean-control false-positive gate.

Proves the adversarial verifier's FP control is EXECUTABLE CODE, not an LLM prompt
(the core moat vs Strix, whose FP rules are two markdown bullets): a corpus of
benign "clean-target" finding shapes is killed by the DETERMINISTIC preflight
(`used_stronger_model=False` — the LLM is never consulted) so ZERO reach CONFIRMED.

This is the sellable number — false-positives on clean input == 0 — and a
regression gate: weakening any deterministic FP oracle breaks this test.
"""
import pytest

from vxis.agent.tools.verifier_tools import VerifyFindingTool


# Benign FP-shapes a CLEAN target legitimately produces. Each MUST be refuted/
# unconfirmed by the deterministic preflight (no LLM), never CONFIRMED.
CLEAN_CORPUS = {
    "high_incomplete_report_contract": dict(
        title="x", finding_type="sqli", affected_component="/a", severity="high",
        evidence="something happened", impact="", technical_analysis="",
        poc_description="", poc_script_code="",
    ),
    "high_poc_without_http_exchange": dict(
        title="x", finding_type="sqli", affected_component="/a", severity="high",
        evidence="e", impact="i", technical_analysis="t", poc_description="p",
        poc_script_code="just a note, no request/response transcript",
    ),
    "binary_blob_info_disclosure": dict(
        title="x", finding_type="information_disclosure", affected_component="/a.gz",
        severity="medium", evidence="\\x1f\\x8b\\x08\\x00" * 50,
    ),
    "xss_plain_echo_not_executable": dict(
        title="x", finding_type="xss", affected_component="/s", severity="high",
        evidence="reflected: <b>test</b>", impact="i",
        technical_analysis="Doctrine: prefer executable reflection over plain echo. Observed plain echo only.",
        poc_description="reflected value in body",
        poc_script_code="GET /s?q=test HTTP/1.1\nHost: t\n\nHTTP/1.1 200 OK\n\n<b>test</b>",
    ),
    "ssrf_size_only_delta": dict(
        title="x", finding_type="ssrf", affected_component="/f?url=", severity="high",
        evidence="response 1200 bytes vs baseline 1000", impact="i",
        technical_analysis="Doctrine: size-only delta is weak; prefer internal markers. Only a size delta seen.",
        poc_description="size delta only",
        poc_script_code="GET /f?url=http://169.254.169.254 HTTP/1.1\nHost: t\n\nHTTP/1.1 200 OK\n\n(1200 bytes, no metadata)",
    ),
}


@pytest.mark.asyncio
async def test_clean_control_zero_confirmed_killed_deterministically():
    # No brain → the LLM is unavailable. A CONFIRMED verdict could therefore only
    # come from deterministic code; on clean input there must be none.
    tool = VerifyFindingTool()
    confirmed: list[str] = []
    relied_on_llm: list[str] = []

    for name, args in CLEAN_CORPUS.items():
        result = await tool.run(**args)
        data = result.data or {}
        verdict = data.get("verdict") if result.ok else None
        if verdict == "CONFIRMED":
            confirmed.append(name)
        if data.get("used_stronger_model"):
            relied_on_llm.append(name)
        # killed by the deterministic firewall, not escalated to the LLM
        assert verdict in (None, "REFUTED", "UNCONFIRMED"), f"{name}: unexpected verdict {verdict!r}"
        assert data.get("used_stronger_model") in (False, None), f"{name}: relied on LLM, not code"

    total = len(CLEAN_CORPUS)
    fp_rate = len(confirmed) / total
    assert fp_rate == 0.0, f"clean-control FP-rate={fp_rate} (CONFIRMED: {confirmed})"
    assert not relied_on_llm, f"FP control must be executable code, not a prompt; LLM used for {relied_on_llm}"
    print(
        f"\n[clean-control] FP-rate={fp_rate:.3f} — 0/{total} CONFIRMED; "
        f"{total}/{total} killed deterministically (no LLM)."
    )
