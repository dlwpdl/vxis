"""Adversarial verifier tool — Phase C first brick.

Takes a claimed finding and runs an INDEPENDENT LLM call whose job is to
REFUTE it. If the verifier cannot refute, the finding is confirmed. If it
can provide a plausible refutation, the finding is marked as unconfirmed
(likely false positive).

Key design: uses a stronger model than the scan loop (gpt-5.4 full vs
mini) and a prompt explicitly framed as "prove this wrong". This asymmetry
— cheap model to find, expensive model to refute — is the Strix validation
agent pattern and the core of Phase C's adversarial verification.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

_HTTP_MARKERS = ("HTTP/1.", "HTTP/2", "GET ", "POST ", "PUT ", "PATCH ", "DELETE ")
_RESULT_MARKERS = (
    "200 OK",
    "201 Created",
    "202 Accepted",
    "500 Internal Server Error",
    "Set-Cookie:",
    "\"token\"",
    "\"role\"",
    "\"data\"",
    "\"status\"",
    "stack trace",
    "Traceback",
    "sqlmap identified",
    "dumped",
)
_CONTROL_MARKERS = (
    "control",
    "negative",
    "baseline",
    "unauthenticated",
    "authenticated",
    "without auth",
    "with auth",
    "token:null",
    "token=\"\"",
    "id=1",
    "id=2",
    "before:",
    "after:",
)


_REFUTER_SYSTEM_PROMPT = """\
You are a senior pentester adjudicating a claimed vulnerability finding.
Your job is to reach the CORRECT verdict — not to rubber-stamp and not to
reflexively refute. Be fair: real findings must be CONFIRMED, fake ones
REFUTED, and only genuinely ambiguous ones UNCONFIRMED.

Output this exact format, nothing else:
VERDICT: CONFIRMED | UNCONFIRMED | REFUTED
CONFIDENCE: high | medium | low
REASONING: <2-3 sentences citing specific bytes/status/keywords from the evidence>

Decision rubric (apply in order):

1) REFUTED — clear false positive. Pick this when:
   - Response size matches SPA baseline (Brain reported shell echo as leak)
   - finding_type claims injection/RCE but evidence shows no payload, no
     delta, no error, no output
   - Evidence is just the wordlist/tool output with no HTTP response
   - Claim contradicts the evidence (e.g. "credentials leaked" but body is HTML 404)

2) CONFIRMED — concrete proof. Pick this when ANY of:
   - Evidence contains real sensitive content: actual credentials, API
     keys, private config, stack traces with file paths, SQL errors,
     dumped data rows
   - The PoC includes both the exploit attempt and the observed result
     (request + response, payload + reflected output, or command +
     extracted data) and they line up with the claim
   - HTTP status + body size + content together rule out baseline/shell
     (e.g. 200 OK on /.env with KEY=VALUE lines, or 500 with stack trace
     naming internal modules)
   - Broken access control: resource returned to unauthenticated request
     that should require auth, with body proving the resource is real
   - IDOR/auth bypass with a response body showing another user's data
   - HTTP 500 is CONFIRMED only if the body contains a real stack trace,
     error message naming internal code, or sensitive debug info — NOT
     if the body is generic "Internal Server Error"

3) UNCONFIRMED — genuine ambiguity. Use SPARINGLY, only when:
   - Evidence is suggestive but incomplete (status + size but no body excerpt)
   - The PoC shows a positive signal but lacks the control comparison
     expected for auth bypass, IDOR, access-control, or injection claims
   - Could be a real bug or could be environmental noise, and no single
     piece of evidence tips the balance
   - More probing would resolve it but current data doesn't

Bias rule: if you find yourself writing "might be" or "could be" for
CONFIRMED evidence, re-read the raw evidence. Concrete bytes beat vibes.
If the evidence genuinely proves the claim, say CONFIRMED.

---

DESKTOP / NATIVE APP RUBRIC (apply when affected_component is a file
path, file:// URL, .app bundle, or when evidence mentions codesign /
plistlib / otool / dylib / entitlement / Electron / nodeIntegration /
contextIsolation / Mach-O. The SPA baseline and HTTP status rules above
DO NOT APPLY — those are web-only signals. Use the checks below instead.):

1) CONFIRMED on desktop when ANY of:
   - codesign output proves the stated misconfig: unsigned ("not signed
     at all"), ad-hoc signed (Authority=- or (unknown)), hardened runtime
     flag missing (no "runtime" in flags=0x...).
   - plistlib-parsed entitlements XML contains the claimed dangerous key
     set to <true/>: disable-library-validation, allow-dyld-environment-
     variables, allow-jit, allow-unsigned-executable-memory.
   - Electron config regex matched in main process JS:
     nodeIntegration: true, contextIsolation: false, webSecurity: false.
   - Secret pattern match with the recognized prefix/suffix (AKIA...,
     ghp_..., eyJ...eyJ...sig, -----BEGIN * PRIVATE KEY-----,
     sk_live_...) — even when masked, the fingerprint is diagnostic.
   - otool -L / -l shows @rpath resolving into a user-writable dir that
     is part of the binary's search path.

2) REFUTED on desktop when:
   - Evidence is empty, only "command failed", or unrelated noise.
   - Claim is "unsigned" but codesign output shows a real Authority line.
   - Claim is "Electron misconfig" but evidence shows
     `Electron Framework.framework` absent — i.e. target isn't Electron.
   - Claim references an HTTP status/SPA baseline on a desktop target
     (category confusion — the skill misfired).

3) UNCONFIRMED on desktop only when the evidence is ambiguous between
   the two rubrics above and more probing would disambiguate.

Never REFUTE a desktop finding just because the evidence lacks an HTTP
response — desktop evidence is subprocess output, file-system walk
results, and plist dumps. That is the correct shape, not a gap."""


def _looks_like_http_exchange(blob: str) -> bool:
    return any(marker in blob for marker in _HTTP_MARKERS)


def _has_observed_result(blob: str) -> bool:
    lower = blob.lower()
    return any(marker.lower() in lower for marker in _RESULT_MARKERS)


def _has_control_signal(blob: str) -> bool:
    lower = blob.lower()
    return any(marker in lower for marker in _CONTROL_MARKERS)


def _finding_type_needs_control(finding_type: str) -> bool:
    ft = finding_type.lower()
    return any(
        needle in ft
        for needle in (
            "auth",
            "idor",
            "access",
            "privilege",
            "sql",
            "xss",
            "ssrf",
            "csrf",
        )
    )


def _normalize_poc_blob(text: str) -> str:
    blob = str(text or "").strip()
    if not blob:
        return ""
    blob = re.sub(r"\r\n?", "\n", blob)
    return blob[:4000]


def _looks_like_binary_only_evidence(blob: str) -> bool:
    text = str(blob or "")
    if not text:
        return False
    lower = text.lower()
    hex_escapes = lower.count("\\x")
    if hex_escapes < 8:
        return False
    readable_markers = (
        "http/1.1 200",
        "http 200",
        "content-type",
        "server:",
        "host:",
        "head",
        "refs",
        "description",
        "[core]",
        "repositoryformatversion",
        "remote ",
        "author ",
        "commit ",
        "tree ",
        "blob ",
        "name:",
        "email:",
    )
    readable_hits = sum(1 for marker in readable_markers if marker in lower)
    if readable_hits >= 3:
        return False
    return any(token in lower for token in ("git_exposed", ".git/", "compressed", "zlib", "pack")) or hex_escapes >= 16


class VerifyFindingTool:
    name = "verify_finding"
    description = (
        "Adversarially verify a claimed finding. Runs an independent LLM "
        "call with a stronger model whose job is to REFUTE the finding. "
        "Returns a verdict: CONFIRMED (verifier couldn't refute), "
        "UNCONFIRMED (some doubt), or REFUTED (clear false positive). "
        "Use this BEFORE submitting high-severity findings to reduce "
        "false positive rate. Cheap findings don't need it."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string"},
            "finding_type": {"type": "string"},
            "affected_component": {"type": "string"},
            "description": {"type": "string"},
            "impact": {"type": "string"},
            "technical_analysis": {"type": "string"},
            "poc_description": {"type": "string"},
            "poc_script_code": {"type": "string"},
            "evidence": {"type": "string", "description": "Raw HTTP req/resp or tool output that supports the finding"},
            "baseline_size": {
                "type": "integer",
                "description": "SPA baseline response size if known, so verifier can check for shell-echo false positive",
            },
        },
        "required": ["title", "finding_type", "affected_component", "evidence"],
    }

    def __init__(self, brain: Any | None = None) -> None:
        # Brain instance is injected at registry build time so the tool can
        # reuse the provider fallback chain + counter instrumentation.
        self._brain = brain

    def bind_brain(self, brain: Any) -> None:
        self._brain = brain

    async def run(self, **kwargs: Any) -> ToolResult:
        title = str(kwargs.get("title", ""))
        finding_type = str(kwargs.get("finding_type", ""))
        component = str(kwargs.get("affected_component", ""))
        evidence = str(kwargs.get("evidence", ""))
        severity = str(kwargs.get("severity", "unknown"))
        description = str(kwargs.get("description", ""))
        impact = str(kwargs.get("impact", ""))
        technical_analysis = str(kwargs.get("technical_analysis", ""))
        poc_description = str(kwargs.get("poc_description", ""))
        poc_script_code = _normalize_poc_blob(kwargs.get("poc_script_code", ""))
        baseline_size = kwargs.get("baseline_size")

        if not evidence and poc_script_code:
            evidence = poc_script_code

        if not (finding_type and component and evidence):
            return ToolResult(
                ok=False,
                summary="verify_finding: finding_type, affected_component, and evidence are required",
                error="missing_fields",
            )

        if finding_type.lower() in {"misconfiguration", "information_disclosure"} and _looks_like_binary_only_evidence(
            "\n".join(part for part in (evidence, technical_analysis, poc_script_code) if part)
        ):
            return ToolResult(
                ok=True,
                data={
                    "verdict": "REFUTED",
                    "confidence": "high",
                    "reasoning": "The captured response is dominated by escaped binary/compressed blob data without readable secret material or clear exposed repository metadata, so this does not yet prove a meaningful disclosure.",
                    "finding_type": finding_type,
                    "affected_component": component,
                    "used_stronger_model": False,
                    "preflight_blocked": True,
                },
                summary="verify_finding: REFUTED (high) — binary blob without readable disclosure",
            )

        if severity.lower() in {"high", "critical"}:
            if not all(
                field.strip()
                for field in (impact, technical_analysis, poc_description, poc_script_code)
            ):
                return ToolResult(
                    ok=True,
                    data={
                        "verdict": "REFUTED",
                        "confidence": "high",
                        "reasoning": "High/critical claim is missing structured PoC or analysis fields required by the Strix-style reporting contract.",
                        "finding_type": finding_type,
                        "affected_component": component,
                        "used_stronger_model": False,
                        "preflight_blocked": True,
                    },
                    summary="verify_finding: REFUTED (high) — incomplete high-severity report contract",
                )
            if not (_looks_like_http_exchange(poc_script_code) or _has_observed_result(poc_script_code)):
                return ToolResult(
                    ok=True,
                    data={
                        "verdict": "REFUTED",
                        "confidence": "high",
                        "reasoning": "PoC transcript does not show a replayable exploit attempt paired with an observed result.",
                        "finding_type": finding_type,
                        "affected_component": component,
                        "used_stronger_model": False,
                        "preflight_blocked": True,
                    },
                    summary="verify_finding: REFUTED (high) — PoC lacks attempt/result transcript",
                )
            combined = "\n".join([technical_analysis, poc_description, poc_script_code])
            if _finding_type_needs_control(finding_type) and not _has_control_signal(combined):
                return ToolResult(
                    ok=True,
                    data={
                        "verdict": "UNCONFIRMED",
                        "confidence": "medium",
                        "reasoning": "PoC shows a positive signal, but no control comparison is recorded for this finding type.",
                        "finding_type": finding_type,
                        "affected_component": component,
                        "used_stronger_model": False,
                        "preflight_blocked": True,
                    },
                    summary="verify_finding: UNCONFIRMED (medium) — no control comparison recorded",
                )

        if self._brain is None or not hasattr(self._brain, "_call_llm_with_fallback"):
            return ToolResult(
                ok=False,
                summary="verify_finding: no brain instance bound (tool was instantiated without brain)",
                error="no_brain",
            )

        user_prompt = (
            f"Finding to review:\n"
            f"  title: {title}\n"
            f"  finding_type: {finding_type}\n"
            f"  severity (claimed): {severity}\n"
            f"  affected_component: {component}\n"
            f"  description: {description[:500]}\n"
            f"  impact: {impact[:400]}\n"
            f"  technical_analysis: {technical_analysis[:800]}\n"
            f"  poc_description: {poc_description[:800]}\n"
            f"  poc_script_code: {poc_script_code[:1500]}\n"
            f"  evidence (raw): {evidence[:1500]}\n"
        )
        if baseline_size is not None:
            user_prompt += f"  SPA baseline size: {baseline_size} bytes\n"

        user_prompt += "\nReview this finding. Can you REFUTE it?"

        # Temporarily swap model to gpt-5.4 full if we're currently on mini.
        orig_model = getattr(self._brain, "_model", None)
        use_stronger = False
        if (
            getattr(self._brain, "_provider", None) == "openai"
            and os.environ.get("OPENAI_API_KEY")
            and orig_model
            and "mini" in str(orig_model)
        ):
            self._brain._model = "gpt-5.4"
            use_stronger = True

        try:
            response = await asyncio.to_thread(
                self._brain._call_llm_with_fallback,
                _REFUTER_SYSTEM_PROMPT,
                user_prompt,
            )
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"verify_finding: LLM call failed: {type(e).__name__}: {e}",
                error=str(e),
            )
        finally:
            if use_stronger and orig_model is not None:
                self._brain._model = orig_model

        if not response:
            return ToolResult(
                ok=False,
                summary="verify_finding: verifier returned no response",
                error="no_response",
            )
        if not isinstance(response, str):
            return ToolResult(
                ok=False,
                summary=f"verify_finding: verifier returned non-text response ({type(response).__name__})",
                error="non_text_response",
            )

        # Parse the verdict
        verdict = "UNCONFIRMED"
        confidence = "low"
        reasoning = response.strip()[:500]
        for line in response.splitlines():
            line_s = line.strip()
            if line_s.upper().startswith("VERDICT:"):
                v = line_s.split(":", 1)[1].strip().upper()
                if v in ("CONFIRMED", "UNCONFIRMED", "REFUTED"):
                    verdict = v
            elif line_s.upper().startswith("CONFIDENCE:"):
                c = line_s.split(":", 1)[1].strip().lower()
                if c in ("high", "medium", "low"):
                    confidence = c
            elif line_s.upper().startswith("REASONING:"):
                reasoning = line_s.split(":", 1)[1].strip()[:500]

        return ToolResult(
            ok=True,
            data={
                "verdict": verdict,
                "confidence": confidence,
                "reasoning": reasoning,
                "finding_type": finding_type,
                "affected_component": component,
                "used_stronger_model": use_stronger,
            },
            summary=(
                f"verify_finding: {verdict} ({confidence}) — "
                f"{reasoning[:100]}"
            ),
        )
