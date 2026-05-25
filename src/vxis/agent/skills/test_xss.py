"""Skill: test_xss — reflected, stored, and DOM-based XSS testing."""

from __future__ import annotations
import asyncio
import logging
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

_REFLECTIVE_PARAM_HINTS = tuple(_load_ds("xss", "reflective_params"))
_XSS_DOCTRINE = list(_load_ds("xss", "doctrine"))


def _fallback_params_for_url(url: str) -> list[str]:
    lower = url.lower()
    if any(token in lower for token in ("search", "product", "catalog", "filter")):
        return ["q", "search", "query", "term"]
    if any(token in lower for token in ("return", "redirect", "next", "continue", "callback")):
        return ["returnUrl", "redirect", "next", "callback"]
    if any(token in lower for token in ("message", "comment", "feedback", "review", "profile")):
        return ["message", "comment", "bio", "displayName"]
    return ["q", "search", "query", "returnUrl"]


def _xss_payloads_for_round(r: int) -> list[dict[str, str]]:
    """Select XSS payload set by rotation round.

    Payloads live in ``src/vxis/data/payloads/xss.json`` (ADR-007).
    """
    from ._payload_loader import load_skill_payloads

    return load_skill_payloads("xss", r)


def _select_target_params(
    url: str,
    param_name: str | None = None,
    *,
    limit: int = 4,
) -> tuple[list[str], dict[str, list[str]], Any]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if param_name:
        if param_name in params:
            return [param_name], params, parsed
        synthetic = {param_name: [""]}
        return [param_name], synthetic, parsed

    if params:
        hinted: list[str] = []
        fallback: list[str] = []
        for key in params.keys():
            lower = key.lower()
            if any(token in lower for token in _REFLECTIVE_PARAM_HINTS):
                hinted.append(key)
            else:
                fallback.append(key)
        ordered = hinted + fallback
        return ordered[:limit], params, parsed

    synthetic_order = _fallback_params_for_url(url)
    return synthetic_order[:limit], {}, parsed


def _doctrine_rows_for_param(url: str, param_name: str) -> list[dict[str, str]]:
    lower = f"{url} {param_name}".lower()
    if any(token in lower for token in _REFLECTIVE_PARAM_HINTS) or any(
        token in lower
        for token in ("hash", "fragment", "comment", "bio", "displayname", "preview", "render")
    ):
        return list(_XSS_DOCTRINE)
    return []


def _xss_validation_hint(context: str, payload: str) -> str:
    if context in {"href", "proto", "data_url", "srcdoc", "formaction", "xlink"}:
        return "Executable URL-like context; stronger than plain reflection."
    if context in {"attribute_break", "event", "svg", "svg_script", "svg_animate"}:
        return "HTML/event context with likely executable sink."
    if context in {"dom_hash", "dom_hash_img", "dom_js_proto"}:
        return "Likely DOM-driven sink; confirm in browser/JS context if available."
    if context in {"js_string", "template_literal"}:
        return "JavaScript string/literal context; verify quote-breaking/execution path."
    if (
        payload.lower().startswith("javascript:")
        or "onerror=" in payload.lower()
        or "onload=" in payload.lower()
    ):
        return "Executable event/protocol payload reflected."
    return "Reflection observed; confirm execution context before escalating."


async def execute(
    url: str, param_name: str | None = None, round: int = 1, **kwargs: Any
) -> dict[str, Any]:
    """Test XSS on a URL with query parameter.

    `round` (1|2|3) selects the payload set — scan_loop passes
    incrementing rounds when re-queueing the skill against the same
    URL so the second pass tests filter-bypass payloads instead of
    the same classic ones.

    Returns:
        {
            "vulnerable": bool,
            "findings": [...],
            "baseline": {"status": int, "size": int, "preview": str},
            "control_evidence": {"baseline": {...}, "interesting_responses": [...]},
            "tested": int,
            "url": str,
            "round": int,
        }
    """
    from vxis.interaction.hands import SessionManager
    from urllib.parse import urlparse as _urlparse

    _base = _urlparse(url)
    _base_url = f"{_base.scheme}://{_base.netloc}"

    _payloads = _xss_payloads_for_round(round)

    target_params, params, parsed = _select_target_params(url, param_name)

    findings: list[dict[str, Any]] = []
    control_evidence: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    _mgr = SessionManager()
    _session = await _mgr.get_session(_base_url)
    try:
        base_r = await _session.request("GET", url)
        baseline_status = base_r.status
        baseline_size = base_r.body_length
    except Exception as e:
        return {"vulnerable": False, "findings": [], "tested": 0, "url": url, "error": str(e)}

    async def test_payload(p: dict[str, str]) -> None:
        nonlocal tested
        async with sem:
            for target_param in target_params:
                tested += 1
                new_params = dict(params)
                existing = list(new_params.get(target_param, [""]))
                orig = existing[0] if existing else ""
                new_params[target_param] = [orig + p["payload"]]
                query = urlencode({k: v[0] for k, v in new_params.items()})
                test_url = urlunparse(parsed._replace(query=query))

                try:
                    r = await _session.request("GET", test_url)
                except Exception:
                    continue

                body = r.text
                doctrine_rows = _doctrine_rows_for_param(url, target_param)
                if p["payload"].lower() in body.lower():
                    findings.append(
                        {
                            "type": f"xss_{p['context']}",
                            "payload": p["payload"],
                            "param": target_param,
                            "evidence": (
                                f"Payload reflected unescaped in response (status {r.status}). "
                                f"{_xss_validation_hint(p['context'], p['payload'])}"
                            ),
                            "response_preview": body[:300],
                            "control": {
                                "baseline_status": baseline_status,
                                "baseline_size": baseline_size,
                                "payload_status": r.status,
                                "payload_size": r.body_length,
                                "baseline_preview": base_r.text[:180],
                                "payload_preview": body[:180],
                            },
                            "severity": "high",
                            "doctrine": doctrine_rows,
                        }
                    )
                    logger.info("XSS found: %s on param %s", p["context"], target_param)
                    return
                control_evidence.append(
                    {
                        "payload": p["payload"],
                        "context": p["context"],
                        "param": target_param,
                        "status": r.status,
                        "size": r.body_length,
                        "baseline_status": baseline_status,
                        "baseline_size": baseline_size,
                        "response_preview": body[:180],
                        "doctrine_families": [row.get("family", "") for row in doctrine_rows],
                    }
                )

    await asyncio.gather(*[test_payload(p) for p in _payloads])

    # Deduplicate by context
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f['type']}:{f['param']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {
        "vulnerable": len(unique) > 0,
        "findings": unique,
        "surface_hints": [
            {
                "param": param,
                "doctrine": _doctrine_rows_for_param(url, param),
            }
            for param in target_params
        ],
        "baseline": {
            "status": baseline_status,
            "size": baseline_size,
            "preview": base_r.text[:240],
        },
        "control_evidence": {
            "baseline": {
                "status": baseline_status,
                "size": baseline_size,
                "preview": base_r.text[:240],
            },
            "interesting_responses": control_evidence[:10],
        },
        "tested": tested,
        "url": url,
        "param": param_name or (target_params[0] if target_params else "q"),
        "tested_params": target_params,
        "round": round,
    }
