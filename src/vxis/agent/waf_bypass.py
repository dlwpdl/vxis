"""Adaptive WAF Bypass Engine.

When an attack payload is blocked by a WAF, this engine asks the Brain to
generate a mutated payload that may evade the WAF. Up to N iterations per
attack vector. Graceful degradation: if Brain is unavailable, returns None.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger(__name__)


# WAF detection signatures — header keys (lowercased) and body fingerprints
_WAF_HEADER_KEYS = (
    "x-sucuri-id",
    "x-sucuri-cache",
    "x-amz-waf-id",
    "x-amzn-waf-action",
    "x-amzn-requestid",
    "cf-ray",
    "cf-mitigated",
    "x-akamai-transformed",
    "akamai-grn",
    "x-iinfo",  # Imperva Incapsula
    "x-cdn",
    "x-mod-security",
    "x-waf-event-info",
)

_WAF_SERVER_VALUES = (
    "cloudflare",
    "sucuri",
    "akamaighost",
    "awselb",
    "imperva",
    "incapsula",
    "barracuda",
    "modsecurity",
    "f5",
    "big-ip",
)

_WAF_BODY_MARKERS = (
    "blocked",
    "forbidden",
    "not allowed",
    "security violation",
    "request blocked",
    "access denied",
    "mod_security",
    "modsecurity",
    "cloudflare",
    "attention required",
    "ray id",
    "sucuri website firewall",
    "incident id",
    "waf",
    "cf-error-details",
    "request rejected",
    "the requested url was rejected",
)


class WAFBypassEngine:
    """Brain-driven WAF evasion engine.

    Usage:
        engine = WAFBypassEngine(max_iterations=3)
        new_payload = await engine.evolve_payload(
            original_payload, response_body, response_status,
            vector_type, brain,
        )
    """

    def __init__(self, max_iterations: int = 3) -> None:
        self.max_iterations = max_iterations
        # vector_type -> list[str] of payloads already tried (for prompt context)
        self._history: dict[str, list[str]] = {}

    # ------------------------------------------------------------------ #
    # Detection
    # ------------------------------------------------------------------ #
    # Servers that are NOT WAFs — generic 403/401 from these is just a
    # protocol/permission denial, not a WAF block. Whitelisting them prevents
    # the bypass loop from burning LLM credits on Streamlit/Tornado/Werkzeug
    # responses.
    _NON_WAF_SERVERS = (
        "tornadoserver", "werkzeug", "gunicorn", "uvicorn", "hypercorn",
        "waitress", "wsgiserver", "rocket", "puma", "thin", "webrick",
        "node.js", "bun", "deno", "kestrel", "lighttpd",
        "uwsgi", "daphne", "twisted",
    )

    def _detect_waf(
        self,
        response_body: str,
        response_status: int,
        headers: Optional[dict[str, str]] = None,
    ) -> Optional[str]:
        """Return WAF name string if a WAF block is detected, else None.

        Conservative — false positives waste LLM credits on bypass loops.
        We only flag a WAF when we have STRONG evidence: explicit header,
        known WAF Server value, or a real WAF challenge page. Generic 403
        from a known app server is NOT a WAF block.
        """
        body_lower = (response_body or "").lower()
        body_len = len(body_lower)
        hdrs = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}

        # Header signatures — strongest signal
        for key in _WAF_HEADER_KEYS:
            if key in hdrs:
                return f"header:{key}"

        server = hdrs.get("server", "")

        # Known non-WAF app servers — never flag as WAF
        if any(nw in server for nw in self._NON_WAF_SERVERS):
            return None

        # Known WAF Server header values
        for value in _WAF_SERVER_VALUES:
            if value in server:
                if response_status in (401, 403, 406, 419, 429, 451, 503):
                    return f"server:{value}"

        # Status + body marker — but only when body is substantial AND
        # contains a STRONG WAF marker (not just the word "forbidden").
        # A 69-byte "Forbidden" page from Tornado is not a WAF.
        if response_status in (403, 406, 419, 429, 451, 503) and body_len >= 200:
            for marker in _WAF_BODY_MARKERS:
                if marker in body_lower:
                    # Skip overly generic markers that vanilla error pages also use
                    if marker in ("forbidden", "blocked", "access denied", "waf"):
                        # Require a SECOND signal for these vague markers
                        second_signal = any(
                            other in body_lower
                            for other in (
                                "ray id", "incident id", "request id",
                                "challenge", "captcha", "mod_security",
                                "sucuri", "cloudflare", "imperva", "akamai",
                            )
                        )
                        if not second_signal:
                            continue
                    return f"body:{marker}"

        # Cloudflare/CloudFront challenge pages always indicate WAF
        if "cf-chl" in body_lower or "challenge-platform" in body_lower:
            return "cloudflare:challenge"
        if "generated by cloudfront" in body_lower:
            return "cloudfront"

        return None

    # ------------------------------------------------------------------ #
    # Public entrypoint
    # ------------------------------------------------------------------ #
    async def evolve_payload(
        self,
        original_payload: str,
        response_body: str,
        response_status: int,
        vector_type: str,
        brain: Any,
        headers: Optional[dict[str, str]] = None,
    ) -> Optional[str]:
        """Analyze response, ask Brain for a mutated payload.

        Returns the new payload string, or None if no bypass should be tried
        (no WAF detected, max iterations exceeded, or Brain unavailable).
        """
        waf_marker = self._detect_waf(response_body, response_status, headers)
        if not waf_marker:
            return None

        history = self._history.setdefault(vector_type, [])
        if original_payload and original_payload not in history:
            history.append(original_payload)

        if len(history) > self.max_iterations:
            logger.debug(
                "[WAF-BYPASS] max iterations (%d) reached for %s",
                self.max_iterations,
                vector_type,
            )
            return None

        if brain is None or not hasattr(brain, "_call_llm_with_fallback"):
            logger.debug("[WAF-BYPASS] Brain unavailable — graceful skip")
            return None

        system_prompt = (
            "You are a WAF evasion expert. Given a blocked payload and WAF "
            "response, generate ONE alternative payload that may bypass the "
            "WAF. Output ONLY the payload string, no explanation. "
            "Common techniques: case variation, URL/Unicode/hex encoding, "
            "inline comments (/*!50000*/), whitespace tricks, "
            "SQL UNION/**/SELECT, XSS event handlers / javascript: / data: "
            "URIs, command injection ${IFS}, $'\\x', backticks."
        )

        previous_attempts = "\n".join(f"- {p}" for p in history[-5:]) or "(none)"
        body_excerpt = (response_body or "")[:500]
        user_prompt = (
            f"Vector type: {vector_type}\n"
            f"Blocked payload: {original_payload}\n"
            f"WAF response: {body_excerpt}\n"
            f"Techniques tried:\n{previous_attempts}\n"
            f"Generate next payload:"
        )

        try:
            response = brain._call_llm_with_fallback(system_prompt, user_prompt)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[WAF-BYPASS] Brain call failed: %s", exc)
            return None

        if not response:
            return None

        new_payload = self._clean_payload(response)
        if not new_payload or new_payload == original_payload:
            return None
        if new_payload in history:
            return None

        history.append(new_payload)
        logger.info(
            "[WAF-BYPASS] %s evolved (%s): %s -> %s",
            vector_type,
            waf_marker,
            (original_payload or "")[:60],
            new_payload[:60],
        )
        return new_payload

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _clean_payload(text: str) -> str:
        """Strip code fences / quotes / leading 'Payload:' labels."""
        s = (text or "").strip()
        if not s:
            return ""
        # Remove triple-backtick fenced blocks
        if s.startswith("```"):
            lines = s.splitlines()
            # drop first fence
            lines = lines[1:]
            # drop trailing fence
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            s = "\n".join(lines).strip()
        # Take first line if multi-line response
        if "\n" in s:
            s = s.splitlines()[0].strip()
        # Strip common label prefixes
        for prefix in ("payload:", "next payload:", "answer:", "output:"):
            if s.lower().startswith(prefix):
                s = s[len(prefix):].strip()
        # Strip surrounding matching quotes
        if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"', "`"):
            s = s[1:-1]
        return s

    def reset(self, vector_type: Optional[str] = None) -> None:
        """Reset history for one vector or all vectors."""
        if vector_type is None:
            self._history.clear()
        else:
            self._history.pop(vector_type, None)
