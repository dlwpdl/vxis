"""Skill: test_injection — SQLi/XSS/SSTI/CMDi on a URL+parameter."""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)


def _payloads_for_round(r: int) -> list[dict]:
    """Select payload set by rotation round.

    Round 1 (default): classic/error-based — highest signal, cheapest.
    Round 2: blind/time-based + filter bypass — used on second attempt.
    Round 3: WAF evasion + polyglots — last-resort.
    Round >=4 or <=0: union of all three (exhaustive).

    Payloads live in ``src/vxis/data/payloads/injection.json`` (ADR-007).
    """
    from vxis.agent.skills._payload_loader import load_skill_payloads
    return load_skill_payloads("injection", r)


async def execute(url: str, param_name: str | None = None, round: int = 1,
                  **kwargs: Any) -> dict[str, Any]:
    """Test injection on a URL with query parameter.

    If url contains ?param=value, tests on that param.
    If param_name given, injects into that specific param.

    `round` selects the payload set (1=classic, 2=blind/time/bypass,
    3=WAF evasion/polyglots, >=4 or <=0=all combined). Scan_loop passes
    an incrementing `round` when re-queueing the skill against the same
    endpoint so the second/third attempt isn't a no-op on a WAF-protected
    target.

    Returns:
        {
            "vulnerable": bool,
            "findings": [{"type": "sqli", "payload": "...", "evidence": "...", "severity": "..."}, ...],
            "baseline": {"status": int, "size": int, "preview": str},
            "control_evidence": {"baseline": {...}, "interesting_responses": [...]},
            "tested": int,
            "url": str,
            "round": int,
        }
    """
    import time
    from urllib.parse import urlparse as _urlparse
    from vxis.interaction.hands import SessionManager

    _base = _urlparse(url)
    _base_url = f"{_base.scheme}://{_base.netloc}"

    _payloads = _payloads_for_round(round)
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Find target parameter
    if param_name and param_name in params:
        target_param = param_name
    elif params:
        target_param = list(params.keys())[0]
    else:
        # No query param — try common ones
        target_param = "q"
        params = {"q": [""]}
        parsed = parsed._replace(query="q=")

    # Get baseline response
    _mgr = SessionManager()
    _session = await _mgr.get_session(_base_url)

    try:
        base_r = await _session.request("GET", url)
        baseline_status = base_r.status
        baseline_size = base_r.body_length
        baseline_body = base_r.text.lower()
    except Exception as e:
        return {"vulnerable": False, "findings": [], "tested": 0, "url": url, "error": str(e)}

    findings: list[dict] = []
    blind_sizes: dict[str, int] = {}
    control_evidence: list[dict[str, Any]] = []
    tested = 0

    sem = asyncio.Semaphore(10)

    async def test_payload(p: dict) -> None:
        nonlocal tested
        async with sem:
            tested += 1
            new_params = dict(params)
            original_val = new_params[target_param][0] if new_params[target_param] else ""
            new_params[target_param] = [original_val + p["payload"]]
            query = urlencode({k: v[0] for k, v in new_params.items()})
            test_url = urlunparse(parsed._replace(query=query))

            _t0 = time.monotonic()
            try:
                r = await _session.request("GET", test_url)
            except Exception:
                return
            _elapsed = time.monotonic() - _t0

            body = r.text.lower()
            size = r.body_length

            # Time-based blind SQLi — a consistent 3s+ delay with
            # a SLEEP/WAITFOR/pg_sleep payload is a strong signal.
            if p["type"] == "sqli_time" and _elapsed >= 2.5:
                findings.append({
                    "type": "sqli_time",
                    "payload": p["payload"],
                    "param": target_param,
                    "evidence": f"Request took {_elapsed:.2f}s (payload injected SLEEP/WAITFOR)",
                    "response_preview": r.text[:300],
                    "control": {
                        "baseline_status": baseline_status,
                        "baseline_size": baseline_size,
                        "payload_status": r.status,
                        "payload_size": size,
                        "baseline_preview": base_r.text[:180],
                        "payload_preview": r.text[:180],
                        "elapsed_seconds": round(_elapsed, 2),
                    },
                    "severity": "critical",
                })
                logger.info("time-based sqli: %s on %s (%.2fs)", p["payload"][:40], target_param, _elapsed)
                return

            # Track blind SQLi size differences
            if p["type"] == "sqli_blind":
                blind_sizes[p["payload"]] = size
                control_evidence.append({
                    "type": p["type"],
                    "payload": p["payload"],
                    "status": r.status,
                    "size": size,
                    "baseline_status": baseline_status,
                    "baseline_size": baseline_size,
                    "response_preview": r.text[:180],
                })
                return

            # Check for error-based detection
            for sig in p["detect"]:
                if sig.lower() in body:
                    severity = {
                        "sqli": "critical", "sqli_time": "critical",
                        "sqli_oob": "critical",
                        "xss": "high", "ssti": "critical",
                        "cmdi": "critical", "path_traversal": "high",
                        "ssrf": "high", "nosql": "high",
                        "crlf": "medium", "xxe": "critical", "ldap": "high",
                    }.get(p["type"], "medium")

                    findings.append({
                        "type": p["type"],
                        "payload": p["payload"],
                        "param": target_param,
                        "evidence": f"Status {r.status}, matched '{sig}' in response",
                        "response_preview": r.text[:300],
                        "control": {
                            "baseline_status": baseline_status,
                            "baseline_size": baseline_size,
                            "payload_status": r.status,
                            "payload_size": size,
                            "matched_signal": sig,
                            "baseline_preview": base_r.text[:180],
                            "payload_preview": r.text[:180],
                        },
                        "severity": severity,
                    })
                    logger.info("injection found: %s on %s with %s", p["type"], target_param, p["payload"][:30])
                    return

            # Check for interesting status code changes
            if r.status == 500 and baseline_status != 500:
                findings.append({
                    "type": p["type"],
                    "payload": p["payload"],
                    "param": target_param,
                    "evidence": f"Payload caused 500 error (baseline was {baseline_status})",
                    "response_preview": r.text[:300],
                    "control": {
                        "baseline_status": baseline_status,
                        "baseline_size": baseline_size,
                        "payload_status": r.status,
                        "payload_size": size,
                        "baseline_preview": base_r.text[:180],
                        "payload_preview": r.text[:180],
                    },
                    "severity": "medium",
                })

            # Check for XSS reflection
            if p["type"] == "xss" and p["payload"].lower() in body:
                findings.append({
                    "type": "xss_reflected",
                    "payload": p["payload"],
                    "param": target_param,
                    "evidence": "Payload reflected in response body",
                    "response_preview": r.text[:300],
                    "control": {
                        "baseline_status": baseline_status,
                        "baseline_size": baseline_size,
                        "payload_status": r.status,
                        "payload_size": size,
                        "baseline_preview": base_r.text[:180],
                        "payload_preview": r.text[:180],
                    },
                    "severity": "high",
                })

    await asyncio.gather(*[test_payload(p) for p in _payloads])

    # Analyze blind SQLi
    if len(blind_sizes) >= 2:
        sizes = list(blind_sizes.values())
        if max(sizes) - min(sizes) > 50:
            findings.append({
                "type": "sqli_blind",
                "payload": "boolean-based blind",
                "param": target_param,
                "evidence": f"Response size delta: {dict(blind_sizes)}",
                "control": {
                    "baseline_status": baseline_status,
                    "baseline_size": baseline_size,
                    "blind_sizes": dict(blind_sizes),
                    "baseline_preview": base_r.text[:180],
                },
                "severity": "critical",
            })

    # Deduplicate findings by type
    seen_types: set[str] = set()
    unique_findings: list[dict] = []
    for f in findings:
        key = f"{f['type']}:{f['param']}"
        if key not in seen_types:
            seen_types.add(key)
            unique_findings.append(f)

    return {
        "vulnerable": len(unique_findings) > 0,
        "findings": unique_findings,
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
        "param": target_param,
        "round": round,
    }
