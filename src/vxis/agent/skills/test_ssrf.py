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


async def execute(url: str, param_name: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test SSRF on URL-accepting parameters.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int, "url": str}
    """
    import httpx

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Find URL-like parameter
    if param_name and param_name in params:
        target_param = param_name
    else:
        target_param = None
        for p in URL_PARAMS:
            if p in params:
                target_param = p
                break
        if not target_param:
            target_param = list(params.keys())[0] if params else "url"
            if not params:
                params = {"url": [""]}
                parsed = parsed._replace(query="url=")

    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        # Get baseline
        try:
            base_r = await client.get(url)
            baseline_size = len(base_r.content)
            baseline_status = base_r.status_code
        except Exception as e:
            return {"vulnerable": False, "findings": [], "tested": 0, "url": url, "error": str(e)}

        async def test_payload(p: dict[str, str]) -> None:
            nonlocal tested
            async with sem:
                tested += 1
                new_params = dict(params)
                new_params[target_param] = [p["payload"]]
                query = urlencode({k: v[0] for k, v in new_params.items()})
                test_url = urlunparse(parsed._replace(query=query))

                try:
                    r = await client.get(test_url, timeout=10)
                except Exception:
                    return

                body = r.text.lower()
                size = len(r.content)

                # Signature detection
                if p["detect"] and p["detect"].lower() in body:
                    findings.append({
                        "type": "ssrf",
                        "payload": p["payload"],
                        "param": target_param,
                        "desc": p["desc"],
                        "evidence": f"Detected '{p['detect']}' in response (status {r.status_code})",
                        "response_preview": r.text[:300],
                        "severity": "critical",
                    })
                    logger.info("SSRF found: %s via %s", p["desc"], target_param)
                    return

                # Size difference heuristic (might indicate internal response)
                if size > baseline_size + 200 and r.status_code == 200:
                    findings.append({
                        "type": "ssrf_possible",
                        "payload": p["payload"],
                        "param": target_param,
                        "desc": p["desc"],
                        "evidence": f"Response size {size} vs baseline {baseline_size} (status {r.status_code})",
                        "response_preview": r.text[:300],
                        "severity": "high",
                    })

        await asyncio.gather(*[test_payload(p) for p in SSRF_PAYLOADS])

    # Deduplicate
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f['type']}:{f['payload']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {"vulnerable": len(unique) > 0, "findings": unique, "tested": tested, "url": url, "param": target_param}
