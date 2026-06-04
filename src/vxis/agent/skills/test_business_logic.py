"""Skill: test_business_logic — negative quantities, price manipulation, state skipping."""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

LOGIC_TESTS = _load_ds("test_business_logic", "logic_tests")  # ADR-007 Phase 3-9 — data in data/payloads/test_business_logic.json

_BUSINESS_KEYWORDS = (
    "cart",
    "basket",
    "order",
    "checkout",
    "coupon",
    "promo",
    "discount",
    "transfer",
    "payment",
    "account",
    "verify",
    "subscription",
)


def _endpoint_path(target: str, endpoint: Any) -> str:
    raw = ""
    if isinstance(endpoint, dict):
        raw = str(endpoint.get("path") or endpoint.get("url") or endpoint.get("action") or "")
    else:
        raw = str(endpoint or "")
    if not raw:
        return ""
    absolute = urljoin(target.rstrip("/") + "/", raw)
    parsed = urlparse(absolute)
    target_host = urlparse(target).netloc
    if parsed.netloc and target_host and parsed.netloc != target_host:
        return ""
    return parsed.path or "/"


def _extract_business_paths(target: str, html: str) -> list[str]:
    candidates: list[Any] = []
    for pattern in (
        r"""(?:fetch|axios(?:\.(?:get|post|put|patch))?|\$\.post|\$\.ajax)\s*\(\s*['"]([^'"]+)['"]""",
        r"""<form[^>]+action=['"]([^'"]+)['"]""",
        r"""<a[^>]+href=['"]([^'"]+)['"]""",
    ):
        candidates.extend(re.findall(pattern, html or "", flags=re.IGNORECASE))
    paths: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        path = _endpoint_path(target, item)
        if not path or path in seen:
            continue
        if any(keyword in path.lower() for keyword in _BUSINESS_KEYWORDS):
            seen.add(path)
            paths.append(path)
    return paths[:20]


def _dynamic_tests_for_path(path: str) -> list[dict[str, Any]]:
    lower = path.lower()
    tests: list[dict[str, Any]] = []
    if any(token in lower for token in ("cart", "basket")):
        tests.extend(
            [
                {
                    "path": path,
                    "method": "POST",
                    "body": {"product_id": 1, "quantity": -1},
                    "control_body": {"product_id": 1, "quantity": 1},
                    "desc": f"Discovered cart negative quantity on {path}",
                    "severity": "high",
                    "origin": "discovered_flow",
                },
                {
                    "path": path,
                    "method": "POST",
                    "body": {"product_id": 1, "quantity": 1, "price": 0},
                    "control_body": {"product_id": 1, "quantity": 1},
                    "desc": f"Discovered cart price override on {path}",
                    "severity": "critical",
                    "origin": "discovered_flow",
                },
            ]
        )
    if "order" in lower or "checkout" in lower:
        tests.extend(
            [
                {
                    "path": path,
                    "method": "POST",
                    "body": {"items": [{"id": 1, "qty": -100, "price": 0.01}]},
                    "control_body": {"items": [{"id": 1, "qty": 1}]},
                    "desc": f"Discovered order negative quantity/price mutation on {path}",
                    "severity": "critical",
                    "origin": "discovered_flow",
                },
                {
                    "path": path,
                    "method": "POST",
                    "body": {"order_id": 1, "step": 999, "paid": False},
                    "control_body": {"order_id": 1, "step": 1},
                    "desc": f"Discovered checkout state-skip mutation on {path}",
                    "severity": "high",
                    "origin": "discovered_flow",
                },
            ]
        )
    if any(token in lower for token in ("coupon", "promo", "discount")):
        tests.append(
            {
                "path": path,
                "method": "POST",
                "body": {"code": "DISCOUNT50", "apply_count": 10},
                "control_body": {"code": "DISCOUNT50"},
                "desc": f"Discovered coupon multi-apply mutation on {path}",
                "severity": "medium",
                "origin": "discovered_flow",
                "race": True,
            }
        )
    if "transfer" in lower or "payment" in lower:
        tests.append(
            {
                "path": path,
                "method": "POST",
                "body": {"amount": -1000, "to": "attacker"},
                "control_body": {"amount": 1, "to": "recipient"},
                "desc": f"Discovered transfer negative amount on {path}",
                "severity": "critical",
                "origin": "discovered_flow",
            }
        )
    if "verify" in lower or "account" in lower:
        tests.append(
            {
                "path": path,
                "method": "POST",
                "body": {"verified": True, "role": "admin"},
                "control_body": {"verified": False},
                "desc": f"Discovered self-service account state mutation on {path}",
                "severity": "high",
                "origin": "discovered_flow",
            }
        )
    return tests


def _flow_body(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        for key in ("json", "json_data", "body_json"):
            if isinstance(raw.get(key), dict):
                return dict(raw[key])
        body = raw.get("body") or raw.get("request_body") or raw.get("body_preview") or ""
    else:
        body = raw
    if isinstance(body, dict):
        return dict(body)
    text = str(body or "").strip()
    if not text:
        return {}
    try:
        import json

        value = json.loads(text)
        return dict(value) if isinstance(value, dict) else {}
    except Exception:
        parsed = parse_qs(text, keep_blank_values=True)
        return {key: values[0] if values else "" for key, values in parsed.items()}


def _mutate_business_value(value: Any) -> list[tuple[str, Any]]:
    mutations: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            lower = str(key).lower()
            if lower in {"price", "unit_price", "amount", "total", "subtotal"}:
                mutated = dict(value)
                mutated[key] = -1 if lower == "amount" else 0
                mutations.append((f"{key}=negative_or_zero", mutated))
            if lower in {"quantity", "qty", "count", "units"}:
                mutated = dict(value)
                mutated[key] = -1
                mutations.append((f"{key}=negative", mutated))
            if lower in {"step", "state", "status"}:
                mutated = dict(value)
                mutated[key] = 999 if lower == "step" else "paid"
                mutations.append((f"{key}=state_skip", mutated))
            for label, child in _mutate_business_value(nested)[:3]:
                mutated = dict(value)
                mutated[key] = child
                mutations.append((f"{key}.{label}", mutated))
    elif isinstance(value, list):
        for index, nested in enumerate(value[:5]):
            for label, child in _mutate_business_value(nested)[:3]:
                mutated = list(value)
                mutated[index] = child
                mutations.append((f"{index}.{label}", mutated))
    return mutations[:8]


def _tests_from_captured_flows(target: str, flows: Any) -> list[dict[str, Any]]:
    raw_flows = flows if isinstance(flows, list) else []
    tests: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for flow in raw_flows[:30]:
        if not isinstance(flow, dict):
            continue
        method = str(flow.get("method") or "GET").upper()
        if method not in {"POST", "PUT", "PATCH"}:
            continue
        path = _endpoint_path(target, flow.get("path") or flow.get("url") or "")
        if not path or not any(keyword in path.lower() for keyword in _BUSINESS_KEYWORDS):
            continue
        control_body = _flow_body(flow)
        if not control_body:
            continue
        for label, mutated_body in _mutate_business_value(control_body):
            key = (path, str(mutated_body))
            if key in seen:
                continue
            seen.add(key)
            tests.append(
                {
                    "path": path,
                    "method": method,
                    "body": mutated_body,
                    "control_body": control_body,
                    "desc": f"Captured flow mutation {label} on {path}",
                    "severity": "critical"
                    if any(token in label for token in ("price", "amount", "total"))
                    else "high",
                    "origin": "captured_flow",
                    "source_request_id": flow.get("id") or flow.get("request_id") or "",
                }
            )
    return tests[:20]


def _merge_logic_tests(
    target: str,
    endpoints: Any,
    html: str = "",
    captured_flows: Any = None,
) -> list[dict[str, Any]]:
    paths: list[str] = []
    seen_paths: set[str] = set()
    raw_endpoints = endpoints if isinstance(endpoints, list) else []
    for endpoint in raw_endpoints:
        path = _endpoint_path(target, endpoint)
        if path and path not in seen_paths and any(k in path.lower() for k in _BUSINESS_KEYWORDS):
            seen_paths.add(path)
            paths.append(path)
    for path in _extract_business_paths(target, html):
        if path not in seen_paths:
            seen_paths.add(path)
            paths.append(path)

    merged = [dict(item) for item in LOGIC_TESTS]
    seen_tests = {(item.get("path"), str(item.get("body"))) for item in merged}
    for path in paths:
        for test in _dynamic_tests_for_path(path):
            key = (test.get("path"), str(test.get("body")))
            if key in seen_tests:
                continue
            seen_tests.add(key)
            merged.append(test)
    for test in _tests_from_captured_flows(target, captured_flows):
        key = (test.get("path"), str(test.get("body")))
        if key in seen_tests:
            continue
        seen_tests.add(key)
        merged.append(test)
    return merged


async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test business logic vulnerabilities.

    Returns:
        {
            "vulnerable": bool,
            "findings": [...],
            "control_evidence": {"accepted": [...], "rejected": [...]},
            "tested": int,
        }
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    findings: list[dict[str, Any]] = []
    accepted_controls: list[dict[str, Any]] = []
    rejected_controls: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    auth_headers: dict[str, str] = {}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)
    discovered_html = ""
    try:
        root_r = await _session.request("GET", target)
        discovered_html = root_r.text
    except Exception:
        discovered_html = ""
    logic_tests = _merge_logic_tests(
        target,
        kwargs.get("endpoints") or kwargs.get("api_endpoints") or kwargs.get("surface_hints"),
        discovered_html,
        kwargs.get("captured_flows")
        or kwargs.get("request_flows")
        or kwargs.get("captured_requests"),
    )

    async def run_test(t: dict[str, Any]) -> None:
        nonlocal tested
        async with sem:
            tested += 1
            url = f"{target}{t['path']}"
            try:
                control_result: dict[str, Any] | None = None
                if t.get("control_body") and t["method"] in ("POST", "PUT"):
                    control_r = await _session.request(
                        t["method"], url, json_data=t["control_body"], headers=auth_headers
                    )
                    control_result = {
                        "status": control_r.status,
                        "size": control_r.body_length,
                        "preview": control_r.text[:180],
                        "body": t["control_body"],
                    }
                if t["method"] in ("POST", "PUT"):
                    r = await _session.request(
                        t["method"], url, json_data=t["body"], headers=auth_headers
                    )
                else:
                    return

                # Logic flaw indicators: accepted when it shouldn't be
                if r.status in (200, 201, 202):
                    body = r.text.lower()
                    # Check for negative/zero amounts being accepted
                    error_indicators = ["invalid", "cannot", "negative", "not allowed", "error"]
                    if not any(ind in body for ind in error_indicators):
                        control_accepted = (
                            control_result is None
                            or control_result.get("status") in (200, 201, 202, 204)
                        )
                        if t.get("origin") in {"discovered_flow", "captured_flow"} and not control_accepted:
                            rejected_controls.append({
                                "desc": t["desc"],
                                "path": t["path"],
                                "status": r.status,
                                "size": r.body_length,
                                "preview": r.text[:180],
                                "control": control_result,
                            })
                            return
                        findings.append({
                            "type": "business_logic",
                            "payload": f"{t['method']} {t['path']} body={t['body']}",
                            "evidence": f"{t['desc']}: accepted (status {r.status})",
                            "response_preview": r.text[:300],
                            "control": {
                                "status": r.status,
                                "size": r.body_length,
                                "preview": r.text[:180],
                                "test": t,
                                "paired_control": control_result,
                            },
                            "severity": t["severity"],
                        })
                        logger.info("Business logic: %s", t["desc"])
                        accepted_controls.append({
                            "desc": t["desc"],
                            "path": t["path"],
                            "status": r.status,
                            "size": r.body_length,
                            "preview": r.text[:180],
                            "paired_control": control_result,
                        })
                    else:
                        rejected_controls.append({
                            "desc": t["desc"],
                            "path": t["path"],
                            "status": r.status,
                            "size": r.body_length,
                            "preview": r.text[:180],
                            "paired_control": control_result,
                        })
            except Exception:
                pass

    await asyncio.gather(*[run_test(t) for t in logic_tests])

    # --- Race condition: double-spend ---
    tested += 1
    async with sem:
        try:
            tasks = [
                _session.request(
                    "POST", f"{target}/api/coupon/apply",
                    json_data={"code": "RACE_TEST"}, headers=auth_headers,
                )
                for _ in range(5)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            successes = [r for r in results if not isinstance(r, Exception) and hasattr(r, "status") and r.status in (200, 201)]
            if len(successes) > 1:
                findings.append({
                    "type": "race_condition",
                    "payload": "5 concurrent coupon applies",
                    "evidence": f"{len(successes)} of 5 succeeded (possible double-spend)",
                    "response_preview": str([getattr(r, "status", "?") for r in successes])[:300],
                    "control": {
                        "success_count": len(successes),
                        "attempt_count": 5,
                        "statuses": [getattr(r, "status", "?") for r in results if not isinstance(r, Exception)],
                    },
                    "severity": "high",
                })
            else:
                rejected_controls.append({
                    "desc": "concurrent coupon apply",
                    "path": "/api/coupon/apply",
                    "status": "no_race",
                    "size": 0,
                    "preview": str([getattr(r, "status", "?") for r in results if not isinstance(r, Exception)])[:180],
                })
        except Exception:
            pass

    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "control_evidence": {
            "accepted": accepted_controls[:8],
            "rejected": rejected_controls[:8],
            "discovered_tests": [
                {"path": t.get("path"), "desc": t.get("desc"), "severity": t.get("severity")}
                for t in logic_tests
                if t.get("origin") == "discovered_flow"
            ][:12],
            "captured_flow_tests": [
                {
                    "path": t.get("path"),
                    "desc": t.get("desc"),
                    "severity": t.get("severity"),
                    "source_request_id": t.get("source_request_id", ""),
                }
                for t in logic_tests
                if t.get("origin") == "captured_flow"
            ][:12],
        },
        "tested": tested,
    }
