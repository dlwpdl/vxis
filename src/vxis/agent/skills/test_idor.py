"""Skill: test_idor — test Insecure Direct Object Reference."""
from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def execute(url_pattern: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test IDOR by iterating IDs on an endpoint.

    url_pattern should contain {id}, e.g. http://target/api/Users/{id}

    Tests:
    1. Sequential ID access (1-20)
    2. With/without auth token comparison
    3. Cross-user data access detection

    Returns:
        {
            "vulnerable": bool,
            "accessible_ids": [int, ...],
            "auth_bypass_ids": [int, ...],  # accessible without token
            "data_samples": [{"id": int, "preview": str}, ...],
            "comparisons": [{"id": int, "status_auth": int, "status_noauth": int, ...}, ...],
            "control_evidence": {"positive_cases": [...], "negative_cases": [...]},
            "total_tested": int,
        }
    """
    from urllib.parse import urlparse as _urlparse
    from vxis.interaction.hands import SessionManager

    accessible_ids: list[int] = []
    auth_bypass_ids: list[int] = []
    data_samples: list[dict] = []
    comparisons: list[dict[str, Any]] = []
    max_id = int(kwargs.get("max_id", 20))

    headers_auth: dict[str, str] = {}
    if token:
        headers_auth = {"Authorization": f"Bearer {token}", "Cookie": f"token={token}"}

    # Derive base URL from the url_pattern (strip path+{id} placeholder)
    _sample_url = url_pattern.replace("{id}", "1")
    _parsed = _urlparse(_sample_url)
    _base_url = f"{_parsed.scheme}://{_parsed.netloc}"

    _mgr = SessionManager()
    _session = await _mgr.get_session(_base_url)
    sem = asyncio.Semaphore(15)

    async def check(uid: int) -> None:
        async with sem:
            url = url_pattern.replace("{id}", str(uid))
            try:
                entry: dict[str, Any] = {"id": uid, "url": url}
                # With auth
                if headers_auth:
                    r_auth = await _session.request("GET", url, headers=headers_auth)
                    entry["status_auth"] = r_auth.status
                    entry["size_auth"] = r_auth.body_length
                    entry["preview_auth"] = r_auth.text[:240]
                    if r_auth.status == 200:
                        accessible_ids.append(uid)
                        if uid <= 5:
                            data_samples.append({
                                "id": uid, "preview": r_auth.text[:300],
                            })

                # Without auth
                r_noauth = await _session.request("GET", url)
                entry["status_noauth"] = r_noauth.status
                entry["size_noauth"] = r_noauth.body_length
                entry["preview_noauth"] = r_noauth.text[:240]
                if r_noauth.status == 200 and r_noauth.body_length > 50:
                    auth_bypass_ids.append(uid)
                comparisons.append(entry)
            except Exception:
                pass

    await asyncio.gather(*[check(i) for i in range(1, max_id + 1)])

    accessible_ids.sort()
    auth_bypass_ids.sort()
    comparisons.sort(key=lambda item: item.get("id", 0))

    vulnerable = len(accessible_ids) > 1 or len(auth_bypass_ids) > 0
    positive_cases = [
        c for c in comparisons
        if c.get("status_auth") == 200 or c.get("status_noauth") == 200
    ][:5]
    negative_cases = [
        c for c in comparisons
        if c.get("status_noauth") in (401, 403, 404) or c.get("status_auth") in (401, 403, 404)
    ][:5]

    logger.info("test_idor: %d accessible, %d without auth, vulnerable=%s",
                len(accessible_ids), len(auth_bypass_ids), vulnerable)

    return {
        "vulnerable": vulnerable,
        "accessible_ids": accessible_ids,
        "auth_bypass_ids": auth_bypass_ids,
        "data_samples": data_samples,
        "comparisons": comparisons[:10],
        "control_evidence": {
            "positive_cases": positive_cases,
            "negative_cases": negative_cases,
        },
        "total_tested": max_id,
        "url_pattern": url_pattern,
    }
