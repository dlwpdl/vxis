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
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)


_REFUTER_SYSTEM_PROMPT = """\
You are a skeptical senior pentester reviewing a claimed vulnerability
finding. Your job is to REFUTE the finding if possible. Default stance:
this is a false positive until proven real.

For each finding you review, answer in this exact format:
VERDICT: CONFIRMED | UNCONFIRMED | REFUTED
CONFIDENCE: high | medium | low
REASONING: <2-3 sentences explaining WHY — cite specific details from
the evidence that either prove or disprove the finding>

Refutation guidelines:
- If the evidence shows a SPA shell being echoed, REFUTED (not a real leak)
- If the HTTP status is 500 but the body is empty/generic, UNCONFIRMED
  (might be a backend timeout, not a logic bug)
- If the size differs from the baseline AND the body shows real sensitive
  content (paths, credentials, configs), CONFIRMED
- If the finding type says "SQL injection" but no payload delta is shown,
  REFUTED
- If the evidence is just "200 OK on /something" with no content analysis,
  UNCONFIRMED (need more proof)

Output NOTHING else. No JSON, no markdown fences. Just the three fields."""


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
        baseline_size = kwargs.get("baseline_size")

        if not (finding_type and component and evidence):
            return ToolResult(
                ok=False,
                summary="verify_finding: finding_type, affected_component, and evidence are required",
                error="missing_fields",
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
