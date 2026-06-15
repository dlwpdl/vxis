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

    for name, args in CLEAN_CORPUS.items():
        result = await tool.run(**args)
        data = result.data or {}
        verdict = data.get("verdict")
        # Assert the POSITIVE deterministic-kill signal per shape — this is what
        # makes the gate real (review fix F4): if any deterministic oracle is
        # removed/weakened, the shape stops being preflight-blocked and falls
        # through to the no-brain guard (ok=False / verdict=None / no
        # preflight_blocked), failing HERE instead of passing silently.
        assert result.ok is True, f"{name}: not handled deterministically (ok={result.ok}, err={result.error})"
        assert data.get("preflight_blocked") is True, f"{name}: not killed by the deterministic preflight"
        assert data.get("used_stronger_model") is False, f"{name}: relied on the LLM, not code"
        assert verdict in ("REFUTED", "UNCONFIRMED"), f"{name}: unexpected verdict {verdict!r}"
        if verdict == "CONFIRMED":  # unreachable given the assert above; kept for the metric
            confirmed.append(name)

    total = len(CLEAN_CORPUS)
    fp_rate = len(confirmed) / total
    assert fp_rate == 0.0, f"clean-control FP-rate={fp_rate} (CONFIRMED: {confirmed})"
    print(
        f"\n[clean-control] FP-rate={fp_rate:.3f} — 0/{total} CONFIRMED; "
        f"{total}/{total} killed deterministically (preflight, no LLM)."
    )
