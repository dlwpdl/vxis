"""Skill: test_ssrf — SSRF on URL-accepting parameters."""
from __future__ import annotations
import asyncio
import logging
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

SSRF_PAYLOADS = _load_ds("test_ssrf", "ssrf_payloads")  # ADR-007 Phase 3-9 — data in data/payloads/test_ssrf.json

URL_PARAMS = _load_ds("test_ssrf", "url_params")  # ADR-007 Phase 3-9 — data in data/payloads/test_ssrf.json
HIGH_SIGNAL_PARAMS = tuple(_load_ds("test_ssrf", "high_signal_params"))
_SSRF_DOCTRINE = list(_load_ds("test_ssrf", "doctrine"))

_SSRF_FALLBACK_PARAMS = ("url", "uri", "dest", "redirect", "next", "return", "callback")


def _ssrf_payloads_for_round(round_num: int) -> list[dict[str, str]]:
    if round_num <= 0 or round_num >= 4:
        return list(SSRF_PAYLOADS)
    if round_num == 1:
        return list(SSRF_PAYLOADS[:8])
    if round_num == 2:
        return list(SSRF_PAYLOADS[8:16])
    return list(SSRF_PAYLOADS[16:])


def _fallback_params_for_url(url: str) -> list[str]:
    lower = url.lower()
    if any(token in lower for token in ("redirect", "return", "next", "continue")):
        return ["redirect", "next", "return", "url"]
    if any(token in lower for token in ("image", "avatar", "fetch", "proxy", "import", "load")):
        return ["url", "uri", "src", "image"]
    if any(token in lower for token in ("webhook", "callback", "notify", "ping")):
        return ["callback", "webhook", "url", "dest"]
    return list(_SSRF_FALLBACK_PARAMS)


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

    target_params = [p for p in URL_PARAMS if p in params]
    if target_params:
        return target_params[:limit], params, parsed

    if params:
        hinted: list[str] = []
        fallback: list[str] = []
        for key in params.keys():
            lower = key.lower()
            if any(token in lower for token in HIGH_SIGNAL_PARAMS):
                hinted.append(key)
            else:
                fallback.append(key)
        ordered = hinted + fallback
        return ordered[:limit], params, parsed

    return _fallback_params_for_url(url)[:limit], {}, parsed


def _doctrine_rows_for_param(url: str, param_name: str) -> list[dict[str, str]]:
    lower = f"{url} {param_name}".lower()
    if any(token in lower for token in ("url", "uri", "src", "redirect", "next", "callback", "webhook", "proxy", "fetch", "load", "import", "file")):
        return list(_SSRF_DOCTRINE)
    return []


async def execute(url: str, param_name: str | None = None, round: int = 1, **kwargs: Any) -> dict[str, Any]:
    """Test SSRF on URL-accepting parameters.

    Returns:
        {
            "vulnerable": bool,
            "findings": [...],
            "baseline": {"status": int, "size": int, "preview": str},
            "control_evidence": {"baseline": {...}, "interesting_responses": [...]},
            "tested": int,
            "url": str,
        }
    """
    from urllib.parse import urlparse as _urlparse
    from vxis.interaction.hands import SessionManager

    _base = _urlparse(url)
    _base_url = f"{_base.scheme}://{_base.netloc}"
    payloads = _ssrf_payloads_for_round(round)

    parsed = urlparse(url)
    target_params, params, parsed = _select_target_params(url, param_name)

    findings: list[dict[str, Any]] = []
    control_evidence: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    _mgr = SessionManager()
    _session = await _mgr.get_session(_base_url)

    # Get baseline
    try:
        base_r = await _session.request("GET", url)
        baseline_size = base_r.body_length
        baseline_status = base_r.status
    except Exception as e:
        return {"vulnerable": False, "findings": [], "tested": 0, "url": url, "error": str(e)}

    async def test_payload(p: dict[str, str]) -> None:
        nonlocal tested
        async with sem:
            for target_param in target_params:
                tested += 1
                new_params = dict(params)
                new_params[target_param] = [p["payload"]]
                query = urlencode({k: v[0] for k, v in new_params.items()})
                test_url = urlunparse(parsed._replace(query=query))
                doctrine_rows = _doctrine_rows_for_param(url, target_param)

                try:
                    r = await _session.request("GET", test_url)
                except Exception:
                    continue

                body = r.text.lower()
                size = r.body_length

                if p["detect"] and p["detect"].lower() in body:
                    findings.append({
                        "type": "ssrf",
                        "payload": p["payload"],
                        "param": target_param,
                        "desc": p["desc"],
                        "evidence": f"Detected '{p['detect']}' in response (status {r.status})",
                        "response_preview": r.text[:300],
                        "control": {
                            "baseline_status": baseline_status,
                            "baseline_size": baseline_size,
                            "payload_status": r.status,
                            "payload_size": size,
                            "matched_signal": p["detect"],
                            "baseline_preview": base_r.text[:180],
                            "payload_preview": r.text[:180],
                        },
                        "severity": "critical",
                        "doctrine": doctrine_rows,
                    })
                    logger.info("SSRF found: %s via %s", p["desc"], target_param)
                    return

                if size > baseline_size + 200 and r.status == 200:
                    findings.append({
                        "type": "ssrf_possible",
                        "payload": p["payload"],
                        "param": target_param,
                        "desc": p["desc"],
                        "evidence": f"Response size {size} vs baseline {baseline_size} (status {r.status})",
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
                        "doctrine": doctrine_rows,
                    })
                control_evidence.append({
                    "payload": p["payload"],
                    "desc": p["desc"],
                    "param": target_param,
                    "status": r.status,
                    "size": size,
                    "baseline_status": baseline_status,
                    "baseline_size": baseline_size,
                    "response_preview": r.text[:180],
                    "doctrine_families": [row.get("family", "") for row in doctrine_rows],
                })

    await asyncio.gather(*[test_payload(p) for p in payloads])

    # Deduplicate
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f['type']}:{f['payload']}"
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
        "param": param_name or (target_params[0] if target_params else "url"),
        "tested_params": target_params,
        "round": round,
    }
