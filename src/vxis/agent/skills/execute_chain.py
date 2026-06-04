"""Skill: execute_chain — run a declared multi-step skill chain."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_AUTO_CONTEXT_KEYS = (
    "token",
    "identities",
    "owner_map",
    "object_ids",
    "url_pattern",
    "max_id",
    "cloud_credentials",
    "cloud_metadata",
    "credential_evidence",
    "loot",
    "secrets",
    "urls",
    "internal_urls",
)


def _get_path(data: Any, path: str) -> Any:
    cur = data
    for part in str(path or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)]
        else:
            return None
    return cur


def _resolve_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("{{") and stripped.endswith("}}") and stripped.count("{{") == 1:
            resolved = context.get(stripped[2:-2].strip())
            if isinstance(resolved, (dict, list)):
                return _resolve_value(resolved, context)
            return resolved
        for key, ctx_value in context.items():
            value = value.replace(f"{{{{{key}}}}}", str(ctx_value))
        return value
    if isinstance(value, dict):
        return {
            key: resolved
            for key, raw in value.items()
            if (resolved := _resolve_value(raw, context)) is not None
        }
    if isinstance(value, list):
        return [_resolve_value(item, context) for item in value]
    return value


def _resolve_params(params: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    resolved = _resolve_value(params, context)
    return dict(resolved or {}) if isinstance(resolved, dict) else {}


def _default_steps(template: str) -> list[dict[str, Any]]:
    if template == "auth_to_crown":
        return [
            {
                "skill": "attempt_auth",
                "extract": {
                    "token": "token",
                    "auth_method": "method",
                    "identities": "identities",
                    "owner_map": "owner_map",
                },
            },
            *_default_steps("post_auth_crown"),
        ]
    if template == "ssrf_cloud_context":
        return [
            {"skill": "test_ssrf", "params": {"url": "{{url}}"}},
        ]
    return [
        {
            "skill": "post_auth_enum",
            "requires": ["token"],
            "params": {"token": "{{token}}"},
        },
        {
            "skill": "test_idor",
            "params": {
                "token": "{{token}}",
                "url_pattern": "{{url_pattern}}",
                "identities": "{{identities}}",
                "object_ids": "{{object_ids}}",
                "owner_map": "{{owner_map}}",
                "max_id": "{{max_id}}",
            },
        },
        {
            "skill": "test_auth_deep",
            "requires": ["token"],
            "params": {"token": "{{token}}"},
        },
    ]


async def _dispatch_skill(skill_name: str, target_url: str, params: dict[str, Any]) -> dict[str, Any]:
    from vxis.agent.skills import SKILL_REGISTRY

    if skill_name == "execute_chain":
        raise ValueError("execute_chain cannot call itself")
    if skill_name not in SKILL_REGISTRY:
        raise KeyError(f"unknown chain skill: {skill_name}")
    fn = SKILL_REGISTRY[skill_name]["fn"]
    params = dict(params or {})
    if skill_name == "test_idor":
        url_pattern = params.pop("url_pattern", f"{target_url.rstrip('/')}/api/Users/{{id}}")
        token = params.pop("token", None)
        return await fn(url_pattern=url_pattern, token=token, **params)
    if skill_name == "post_auth_enum":
        token = params.pop("token", "")
        return await fn(target_url=target_url, token=token, **params)
    if skill_name in {"test_injection", "test_xss", "test_ssrf"}:
        effective_url = params.pop("url", target_url)
        return await fn(url=effective_url, **params)
    if skill_name in {"test_auth_deep", "test_csrf", "test_api_security", "test_business_logic"}:
        token = params.pop("token", None)
        return await fn(target_url=target_url, token=token, **params)
    return await fn(target_url=target_url, **params)


def _summarize_child(skill: str, data: dict[str, Any]) -> str:
    if skill == "post_auth_enum":
        return (
            f"{len(data.get('accessible', []))} accessible, "
            f"{len(data.get('user_data_exposed', []))} data-bearing"
        )
    if skill == "test_idor":
        return (
            f"{'vulnerable' if data.get('vulnerable') else 'clean'}, "
            f"{len(data.get('cross_identity_access', []))} cross-identity, "
            f"{len(data.get('auth_bypass_ids', []))} no-auth"
        )
    if skill == "test_auth_deep":
        return f"{len(data.get('findings', []))} auth-depth finding(s)"
    if skill == "attempt_auth":
        return (
            f"{'authenticated' if data.get('authenticated') else 'not authenticated'}, "
            f"{len(data.get('identities') or [])} identity(s)"
        )
    if skill == "test_ssrf":
        creds = data.get("cloud_credentials") or []
        return (
            f"{'vulnerable' if data.get('vulnerable') else 'clean'}, "
            f"{len(data.get('findings', []))} finding(s), "
            f"{len(creds) if isinstance(creds, list) else 1 if creds else 0} cloud credential signal(s)"
        )
    return "completed"


def _auto_context_updates(skill: str, data: dict[str, Any]) -> dict[str, Any]:
    updates: dict[str, Any] = {}
    for key in _AUTO_CONTEXT_KEYS:
        value = data.get(key)
        if value not in (None, "", [], {}):
            updates[key] = value

    cloud_credentials: list[Any] = []
    cloud_metadata: list[Any] = []
    credential_evidence: list[Any] = []
    for finding in list(data.get("findings") or []):
        if not isinstance(finding, dict):
            continue
        if finding.get("cloud_credentials"):
            cloud_credentials.append(finding["cloud_credentials"])
        if finding.get("cloud_metadata"):
            cloud_metadata.append(finding["cloud_metadata"])
        if finding.get("credential_evidence"):
            credential_evidence.append(finding["credential_evidence"])
    if cloud_credentials and "cloud_credentials" not in updates:
        updates["cloud_credentials"] = cloud_credentials
    if cloud_metadata and "cloud_metadata" not in updates:
        updates["cloud_metadata"] = cloud_metadata
    if credential_evidence and "credential_evidence" not in updates:
        updates["credential_evidence"] = credential_evidence
    if skill == "attempt_auth" and data.get("authenticated") and data.get("token"):
        updates.setdefault("token", data["token"])
    return updates


def _merge_context(context: dict[str, Any], updates: dict[str, Any]) -> None:
    for key, value in updates.items():
        if value in (None, "", [], {}):
            continue
        if key not in context or context.get(key) in (None, "", [], {}):
            context[key] = value
            continue
        if isinstance(context[key], list) and isinstance(value, list):
            existing = list(context[key])
            for item in value:
                if item not in existing:
                    existing.append(item)
            context[key] = existing
        elif isinstance(context[key], dict) and isinstance(value, dict):
            context[key] = {**context[key], **value}


def _normalized_findings(skill: str, data: dict[str, Any], target_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if skill == "test_idor" and data.get("vulnerable"):
        cross = list(data.get("cross_identity_access") or [])
        role = list(data.get("role_matrix_findings") or [])
        finding_type = "bola" if cross else "idor"
        title = "Broken object authorization across identities" if cross else "IDOR on object pattern"
        component = data.get("url_pattern") or target_url
        findings.append(
            {
                "title": f"{title}: {component}",
                "severity": "high",
                "finding_type": finding_type,
                "affected_component": component,
                "description": "Object access controls allowed an unexpected principal to retrieve protected object data.",
                "impact": "A low-privilege or sibling account can access another user's records or privileged objects.",
                "technical_analysis": (
                    f"cross_identity_access={cross[:5]} role_matrix_findings={role[:5]} "
                    f"control_evidence={data.get('control_evidence', {})}"
                ),
                "poc_description": "Replay the same object URL with the requester identity and compare it against the expected owner/control identity.",
                "poc_script_code": str(data.get("identity_comparisons", [])[:5]),
                "remediation_steps": "Enforce server-side object ownership and role checks before returning every object reference.",
                "endpoint": component,
                "method": "GET",
                "cwe": "CWE-639",
            }
        )
    elif skill == "post_auth_enum" and data.get("user_data_exposed"):
        exposed = list(data.get("user_data_exposed") or [])
        paths = [item.get("path", "") for item in exposed[:5]]
        findings.append(
            {
                "title": f"Sensitive authenticated data exposed on {len(exposed)} endpoint(s)",
                "severity": "high",
                "finding_type": "broken_access_control",
                "affected_component": target_url,
                "description": f"Authenticated endpoints returned sensitive user data: {paths}",
                "impact": "A foothold session can enumerate data-bearing endpoints and expand into account or tenant data exposure.",
                "technical_analysis": f"control_evidence={data.get('control_evidence', {})}",
                "poc_description": "Access the listed endpoints with the foothold session and compare unauthenticated controls.",
                "poc_script_code": str(exposed[:5]),
                "remediation_steps": "Apply least-privilege and field-level authorization checks to authenticated data endpoints.",
                "endpoint": target_url,
                "method": "GET",
                "cwe": "CWE-863",
            }
        )
    elif skill == "test_ssrf" and (
        data.get("cloud_credentials")
        or any(
            isinstance(item, dict) and item.get("cloud_credentials")
            for item in list(data.get("findings") or [])
        )
    ):
        creds = data.get("cloud_credentials") or [
            item.get("cloud_credentials")
            for item in list(data.get("findings") or [])
            if isinstance(item, dict) and item.get("cloud_credentials")
        ]
        metadata = data.get("cloud_metadata") or [
            item.get("cloud_metadata")
            for item in list(data.get("findings") or [])
            if isinstance(item, dict) and item.get("cloud_metadata")
        ]
        findings.append(
            {
                "title": "SSRF exposed cloud metadata credential material",
                "severity": "critical",
                "finding_type": "ssrf_cloud_metadata",
                "affected_component": data.get("url") or target_url,
                "description": "The SSRF probe returned cloud metadata credential fields through an attacker-controlled URL fetch path.",
                "impact": "Cloud instance role credentials can enable lateral movement into cloud APIs if the metadata response is usable.",
                "technical_analysis": (
                    f"cloud_credentials={creds[:3] if isinstance(creds, list) else creds} "
                    f"cloud_metadata={metadata[:3] if isinstance(metadata, list) else metadata}"
                ),
                "poc_description": "Replay the SSRF payload against the same URL parameter and confirm that cloud metadata credential markers are returned.",
                "poc_script_code": str(data.get("control_evidence", {}))[:1500],
                "remediation_steps": "Block link-local metadata targets in server-side fetchers, enforce egress allowlists, and require IMDSv2 or equivalent metadata protections.",
                "endpoint": data.get("url") or target_url,
                "method": "GET",
                "cwe": "CWE-918",
            }
        )
    else:
        for finding in list(data.get("findings") or [])[:5]:
            if not isinstance(finding, dict):
                continue
            copied = dict(finding)
            copied.setdefault("affected_component", target_url)
            copied.setdefault("endpoint", copied["affected_component"])
            copied.setdefault("method", "GET")
            findings.append(copied)
    return findings


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Execute a multi-step chain and pass extracted context between steps."""

    template = str(kwargs.get("template") or kwargs.get("chain") or "post_auth_crown")
    target = target_url.rstrip("/")
    context: dict[str, Any] = dict(kwargs.get("context") or {})
    for key in _AUTO_CONTEXT_KEYS:
        if key in kwargs and kwargs.get(key) is not None:
            context[key] = kwargs[key]
    context.setdefault("url_pattern", f"{target}/api/Users/{{id}}")
    steps = list(kwargs.get("steps") or _default_steps(template))

    executed: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for index, step in enumerate(steps):
        skill = str(step.get("skill") or "").strip()
        if not skill:
            continue
        missing = [key for key in step.get("requires", []) if not context.get(str(key))]
        if missing:
            executed.append(
                {
                    "index": index,
                    "skill": skill,
                    "ok": False,
                    "skipped": True,
                    "summary": f"missing context: {', '.join(missing)}",
                }
            )
            continue
        params = _resolve_params(dict(step.get("params") or {}), context)
        try:
            data = await _dispatch_skill(skill, target, params)
        except Exception as exc:
            logger.exception("execute_chain step failed: %s", skill)
            executed.append(
                {
                    "index": index,
                    "skill": skill,
                    "ok": False,
                    "skipped": False,
                    "summary": f"{type(exc).__name__}: {exc}",
                    "error": str(exc),
                }
            )
            if step.get("stop_on_error", True):
                break
            continue

        for ctx_key, result_path in dict(step.get("extract") or {}).items():
            extracted = _get_path(data, str(result_path))
            if extracted not in (None, ""):
                context[str(ctx_key)] = extracted
        _merge_context(context, _auto_context_updates(skill, data))
        child_findings = _normalized_findings(skill, data, target)
        findings.extend(child_findings)
        executed.append(
            {
                "index": index,
                "skill": skill,
                "ok": True,
                "skipped": False,
                "summary": _summarize_child(skill, data),
                "data": data,
                "findings": child_findings,
            }
        )

    ok = all(step.get("ok") or step.get("skipped") for step in executed)
    return {
        "ok": ok,
        "template": template,
        "steps": executed,
        "findings": findings,
        "finding_count": len(findings),
        "context_keys": sorted(context.keys()),
    }
