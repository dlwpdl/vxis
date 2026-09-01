"""Skill: execute_chain — run a declared multi-step skill chain."""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

_AUTO_CONTEXT_KEYS = (
    "token",
    "identities",
    "credentials",
    "owner_map",
    "object_ids",
    "url_pattern",
    "max_id",
    "cloud_credentials",
    "cloud_metadata",
    "credential_evidence",
    "loot",
    "secrets",
    "seed_paths",
    "urls",
    "internal_urls",
    "object_patterns",
    "cloud_impact",
    "allow_cloud_api_probe",
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
                "skill": "test_sensitive_files",
                "extract": {
                    "credentials": "credentials",
                    "loot": "loot",
                    "secrets": "secrets",
                    "seed_paths": "seed_paths",
                    "urls": "urls",
                    "internal_urls": "internal_urls",
                },
            },
            {
                "skill": "attempt_auth",
                "params": {"credentials": "{{credentials}}"},
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
    if template == "ssrf_to_cloud_impact":
        return [
            {
                "skill": "test_ssrf",
                "params": {
                    "url": "{{url}}",
                    "retain_secret_material": "{{allow_cloud_api_probe}}",
                },
            },
            {
                "skill": "prove_cloud_impact",
                "requires": ["cloud_credentials"],
                "params": {
                    "cloud_credentials": "{{cloud_credentials}}",
                    "allow_probe": "{{allow_cloud_api_probe}}",
                },
            },
        ]
    return [
        {
            "skill": "post_auth_enum",
            "requires": ["token"],
            "params": {"token": "{{token}}", "identities": "{{identities}}"},
            "extract": {
                "post_auth_result": "",
                "discovered_endpoints": "accessible",
                "discovered_auth_only_endpoints": "new_endpoints",
                "discovered_paths": "discovered_paths",
            },
        },
        {
            "skill": "test_api_security",
            "requires": ["token"],
            "params": {
                "token": "{{token}}",
                "identities": "{{identities}}",
                "discovered_endpoints": "{{discovered_endpoints}}",
                "discovered_auth_only_endpoints": "{{discovered_auth_only_endpoints}}",
                "discovered_paths": "{{discovered_paths}}",
            },
            "extract": {"api_security_result": ""},
        },
        {
            "skill": "test_idor",
            "params": {
                "token": "{{token}}",
                "url_pattern": "{{url_pattern}}",
                "identities": "{{identities}}",
                "object_ids": "{{object_ids}}",
                "owner_map": "{{owner_map}}",
                "object_patterns": "{{object_patterns}}",
                "max_id": "{{max_id}}",
            },
            "extract": {"idor_result": ""},
        },
        {
            "skill": "prove_post_auth_crown",
            "requires": ["post_auth_result", "idor_result"],
            "params": {
                "post_auth_result": "{{post_auth_result}}",
                "api_security_result": "{{api_security_result}}",
                "idor_result": "{{idor_result}}",
            },
        },
        {
            "skill": "test_auth_deep",
            "requires": ["token"],
            "params": {"token": "{{token}}"},
        },
    ]


async def _dispatch_skill(
    skill_name: str, target_url: str, params: dict[str, Any]
) -> dict[str, Any]:
    from vxis.agent.skills import SKILL_REGISTRY

    if skill_name == "prove_cloud_impact":
        return _prove_cloud_impact(params)
    if skill_name == "prove_post_auth_crown":
        return _prove_post_auth_crown(params)
    if skill_name == "execute_chain":
        raise ValueError("execute_chain cannot call itself")
    if skill_name not in SKILL_REGISTRY:
        raise KeyError(f"unknown chain skill: {skill_name}")
    fn = SKILL_REGISTRY[skill_name]["fn"]
    params = dict(params or {})
    if skill_name == "test_idor":
        object_patterns = params.pop("object_patterns", None)
        if isinstance(object_patterns, list) and object_patterns:
            return await _dispatch_idor_object_patterns(
                fn=fn,
                target_url=target_url,
                base_params=params,
                object_patterns=object_patterns,
            )
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


async def _dispatch_idor_object_patterns(
    *,
    fn: Any,
    target_url: str,
    base_params: dict[str, Any],
    object_patterns: list[Any],
) -> dict[str, Any]:
    pattern_results: list[dict[str, Any]] = []
    for item in object_patterns[:8]:
        if not isinstance(item, dict):
            continue
        url_pattern = str(item.get("url_pattern") or "").strip()
        if not url_pattern:
            continue
        params = dict(base_params)
        params.pop("url_pattern", None)
        params["object_ids"] = item.get("object_ids") or params.get("object_ids")
        params["owner_map"] = item.get("owner_map") or params.get("owner_map")
        token = params.pop("token", None)
        result = await fn(url_pattern=url_pattern, token=token, **params)
        if isinstance(result, dict):
            result = {**result, "url_pattern": result.get("url_pattern") or url_pattern}
            pattern_results.append(result)
    aggregate: dict[str, Any] = {
        "vulnerable": any(item.get("vulnerable") for item in pattern_results),
        "url_pattern": "multiple object patterns"
        if len(pattern_results) > 1
        else pattern_results[0].get("url_pattern", target_url)
        if pattern_results
        else target_url,
        "pattern_results": pattern_results,
        "accessible_ids": [],
        "auth_bypass_ids": [],
        "cross_identity_access": [],
        "role_matrix_findings": [],
        "data_samples": [],
        "comparisons": [],
        "identity_comparisons": [],
        "control_evidence": {
            "pattern_count": len(pattern_results),
            "cross_identity_access": [],
            "role_matrix_findings": [],
        },
        "total_tested": sum(int(item.get("total_tested", 0) or 0) for item in pattern_results),
    }
    for result in pattern_results:
        for key in (
            "accessible_ids",
            "auth_bypass_ids",
            "data_samples",
            "comparisons",
            "identity_comparisons",
        ):
            aggregate[key].extend(list(result.get(key) or [])[:20])
        for key in ("cross_identity_access", "role_matrix_findings"):
            values = list(result.get(key) or [])
            aggregate[key].extend(values[:20])
            aggregate["control_evidence"][key].extend(values[:5])
    return aggregate


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "allow"}


def _privileged_mass_assignment_candidates(api_security_result: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for finding in list(api_security_result.get("findings") or []):
        if not isinstance(finding, dict):
            continue
        if str(finding.get("type") or "").strip().lower() != "mass_assignment":
            continue
        blob = " ".join(
            str(finding.get(key) or "")
            for key in ("payload", "evidence", "response_preview", "endpoint")
        ).lower()
        if any(token in blob for token in ("role", "admin", "isadmin", "is_admin", "privilege")):
            candidates.append(finding)
    return candidates


def _candidate_endpoint(candidate: dict[str, Any]) -> str:
    endpoint = str(candidate.get("endpoint") or "").strip()
    if endpoint:
        return endpoint
    payload = str(candidate.get("payload") or "").strip()
    if " on " in payload:
        tail = payload.rsplit(" on ", 1)[-1].strip()
        if tail.startswith("/"):
            return tail
    return ""


def _first_aws_credentials(raw: Any) -> dict[str, Any]:
    candidates = raw if isinstance(raw, list) else [raw]
    for item in candidates:
        if isinstance(item, list):
            nested = _first_aws_credentials(item)
            if nested:
                return nested
        if not isinstance(item, dict):
            continue
        provider = str(item.get("provider") or "").lower()
        if provider and provider != "aws":
            continue
        if item.get("cloud_credentials") and isinstance(item["cloud_credentials"], dict):
            item = item["cloud_credentials"]
        fields = {str(v).lower() for v in item.get("fields") or []}
        if provider == "aws" or "accesskeyid" in fields or item.get("access_key_id"):
            return item
    return {}


def _prove_cloud_impact(params: dict[str, Any]) -> dict[str, Any]:
    creds = _first_aws_credentials(params.get("cloud_credentials"))
    allow_probe = (
        _boolish(params.get("allow_probe")) or os.environ.get("VXIS_ALLOW_CLOUD_API_PROBE") == "1"
    )
    planned = [
        "aws sts get-caller-identity",
        "aws s3api list-buckets --max-items 10",
    ]
    proof: dict[str, Any] = {
        "provider": "aws" if creds else "",
        "planned_probes": planned,
        "verified": False,
        "allow_probe": allow_probe,
        "credential_fields": list(creds.get("fields") or []),
    }
    raw_access_key = str(creds.get("access_key_id_raw") or creds.get("AccessKeyId") or "")
    raw_secret = str(creds.get("secret_access_key") or creds.get("SecretAccessKey") or "")
    if not creds:
        proof["reason"] = "no_aws_credentials_in_context"
    elif not allow_probe:
        proof["reason"] = "cloud_api_probe_disabled"
    elif not (raw_access_key and raw_secret):
        proof["reason"] = "raw_secret_material_not_retained"
    else:
        proof["raw_material_available"] = True
        from vxis.agent.cloud_probe import probe_aws_identity_and_storage

        probe_results = probe_aws_identity_and_storage(
            {
                "access_key_id": raw_access_key,
                "secret_access_key": raw_secret,
                "session_token": str(creds.get("session_token") or creds.get("Token") or ""),
            }
        )
        proof.update(probe_results)
        proof["verified"] = bool(probe_results.get("sts", {}).get("ok"))
        proof["reason"] = "verified_with_sts" if proof["verified"] else "probe_failed"
    finding = {
        "title": "SSRF cloud credential impact proof plan",
        "severity": "critical" if creds else "medium",
        "finding_type": "ssrf_cloud_impact",
        "affected_component": "cloud metadata credentials",
        "description": "Cloud credential material from SSRF can be validated with STS identity and storage enumeration probes.",
        "impact": "If the credential material is accepted by STS, the SSRF becomes cloud account or workload-role compromise.",
        "technical_analysis": str(proof),
        "poc_description": "Use the captured temporary credentials only within authorized scope to call STS GetCallerIdentity, then list low-risk storage metadata.",
        "poc_script_code": "\n".join(planned),
        "remediation_steps": "Block metadata egress, require IMDSv2 or equivalent, and scope instance roles to least privilege.",
        "endpoint": "cloud metadata",
        "method": "STS/S3",
        "cwe": "CWE-918",
    }
    return {
        "ok": bool(creds),
        "cloud_impact": proof,
        "findings": [finding] if creds else [],
    }


def _prove_post_auth_crown(params: dict[str, Any]) -> dict[str, Any]:
    post_auth = (
        params.get("post_auth_result") if isinstance(params.get("post_auth_result"), dict) else {}
    )
    api_security = (
        params.get("api_security_result")
        if isinstance(params.get("api_security_result"), dict)
        else {}
    )
    idor = params.get("idor_result") if isinstance(params.get("idor_result"), dict) else {}
    cross = list(idor.get("cross_identity_access") or [])
    auth_bypass = list(idor.get("auth_bypass_ids") or [])
    role = list(idor.get("role_matrix_findings") or [])
    privileged_mass_assignment = _privileged_mass_assignment_candidates(api_security)
    if privileged_mass_assignment:
        candidate = privileged_mass_assignment[0]
        component = _candidate_endpoint(candidate) or "post-auth API surface"
        credential_evidence = candidate.get("credential_evidence") or {}
        observed = {
            "payload": candidate.get("payload", ""),
            "evidence": candidate.get("evidence", ""),
            "response_preview": candidate.get("response_preview", ""),
            "credential_evidence": credential_evidence,
        }
        artifact = {
            "source_output": (
                f"foothold token unlocked {len(post_auth.get('accessible') or [])} authenticated "
                f"endpoint(s); /api coverage included {component}."
            )[:1200],
            "pivot_action": (
                f"Reuse the foothold session against {component} and submit privileged account "
                "attributes such as role=admin."
            )[:1200],
            "control_result": str(
                candidate.get("control")
                or candidate.get("negative_result")
                or post_auth.get("control_evidence", {})
                or []
            )[:1200],
            "observed_result": str(observed)[:1500],
            "crown_jewel_evidence": str(
                credential_evidence
                or candidate.get("response_preview")
                or candidate.get("evidence")
                or candidate.get("payload")
                or ""
            )[:1800],
            "source_output_used_in_pivot": True,
            "verification_method": "live_chain_replay",
            "hops": [
                {
                    "source_skill": "post_auth_enum",
                    "target_skill": "test_api_security",
                    "source_output": list(post_auth.get("accessible") or [])[:3],
                    "pivot_action": f"Replay privileged field assignment on {component}",
                    "observed_result": observed,
                    "control_result": (
                        candidate.get("control")
                        or candidate.get("negative_result")
                        or post_auth.get("control_evidence", {})
                        or []
                    ),
                    "source_output_used_in_pivot": True,
                    "repeat_count": 2 if credential_evidence else 1,
                    "negative_result": candidate.get("negative_result")
                    or candidate.get("control")
                    or "Privileged fields should be rejected or ignored.",
                }
            ],
            "repeat_count": 2 if credential_evidence else 1,
            "negative_result": candidate.get("negative_result")
            or candidate.get("control")
            or "Privileged fields should be rejected or ignored.",
        }
        finding = {
            "title": f"Validated post-auth crown replay on {component}",
            "severity": "critical" if credential_evidence else "medium",
            "finding_type": "attack_chain",
            "affected_component": component,
            "description": (
                "A live post-auth chain reused the foothold session to submit privileged account "
                "attributes on an authenticated API surface."
            ),
            "impact": (
                "An attacker can turn an authenticated foothold into privileged account creation "
                "or admin takeover."
            ),
            "technical_analysis": (
                f"post_auth_control={post_auth.get('control_evidence', {})} "
                f"api_security_mass_assignment={privileged_mass_assignment[:3]}"
            ),
            "poc_description": (
                "Authenticate, replay the privileged field assignment on the authenticated API, "
                "and confirm that the privileged attribute is accepted or persists after login."
            ),
            "poc_script_code": str(artifact),
            "remediation_steps": (
                "Apply strict server-side allowlists for user-controlled fields and reject "
                "privileged attributes on self-service account creation or update flows."
            ),
            "endpoint": component,
            "method": "POST",
            "cwe": "CWE-915",
            "verification_method": "live_chain_replay",
            "evidence_artifact": artifact,
        }
        return {
            "ok": True,
            "verified": True,
            "reason": "live_chain_replay",
            "evidence_artifact": artifact,
            "findings": [finding],
        }
    if not (cross or auth_bypass or role):
        return {
            "ok": False,
            "verified": False,
            "reason": "no_post_auth_crown_signal",
            "findings": [],
        }

    object_patterns = list(post_auth.get("object_patterns") or [])
    component = str(idor.get("url_pattern") or "")
    if not component and object_patterns:
        component = str((object_patterns[0] or {}).get("url_pattern") or "")
    if not component:
        component = "post-auth object surface"
    crown_target = cross[:3] or role[:3] or auth_bypass[:5]
    post_auth_paths = [
        str(item.get("path") or "")
        for item in list(post_auth.get("user_data_exposed") or post_auth.get("accessible") or [])[
            :5
        ]
        if isinstance(item, dict) and item.get("path")
    ]
    auth_controls = dict(post_auth.get("control_evidence") or {})
    idor_controls = dict(idor.get("control_evidence") or {})
    artifact = {
        "source_output": (
            f"foothold token unlocked {len(post_auth.get('accessible') or [])} endpoint(s), "
            f"{len(post_auth.get('user_data_exposed') or [])} data-bearing; "
            f"paths={post_auth_paths[:3]}"
        )[:1200],
        "pivot_action": (
            f"Reuse the foothold session against {component} and replay non-owner object IDs "
            f"derived from post-auth enumeration ({post_auth_paths[:3]})."
        )[:1200],
        "control_result": str(
            idor_controls.get("negative_cases")
            or auth_controls.get("auth_only")
            or auth_controls.get("same_data_without_auth")
            or []
        )[:1200],
        "observed_result": str(crown_target)[:1500],
        "crown_jewel_evidence": str(
            idor.get("identity_comparisons")
            or idor.get("data_samples")
            or post_auth.get("user_data_exposed")
            or []
        )[:1800],
        "source_output_used_in_pivot": True,
        "verification_method": "live_chain_replay",
        "hops": [
            {
                "source_skill": "post_auth_enum",
                "target_skill": "test_idor",
                "source_output": post_auth_paths[:3],
                "pivot_action": f"Replay non-owner IDs on {component}",
                "observed_result": crown_target[:3],
                "control_result": (
                    idor_controls.get("negative_cases") or auth_controls.get("auth_only") or []
                )[:3],
                "source_output_used_in_pivot": True,
            }
        ],
    }
    severity = "critical" if cross and post_auth.get("user_data_exposed") else "high"
    finding = {
        "title": f"Validated post-auth crown replay on {component}",
        "severity": severity,
        "finding_type": "attack_chain",
        "affected_component": component,
        "description": "A live post-auth chain reused foothold output to reach another user's object data.",
        "impact": "A low-privilege foothold can be chained into cross-account data access and repeatable exfiltration.",
        "technical_analysis": (
            f"post_auth_control={auth_controls} "
            f"idor_control={idor_controls} "
            f"cross_identity_access={cross[:5]} role_matrix_findings={role[:5]} "
            f"auth_bypass_ids={auth_bypass[:5]}"
        ),
        "poc_description": "Authenticate, enumerate the unlocked data-bearing surface, then replay a non-owner object ID against the discovered pattern and compare it with the control cases.",
        "poc_script_code": str(artifact),
        "remediation_steps": "Apply object-level authorization on every authenticated object route and constrain post-auth enumeration to least privilege.",
        "endpoint": component,
        "method": "GET",
        "cwe": "CWE-639",
        "verification_method": "live_chain_replay",
        "evidence_artifact": artifact,
    }
    return {
        "ok": True,
        "verified": True,
        "reason": "live_chain_replay",
        "evidence_artifact": artifact,
        "findings": [finding],
    }


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
    if skill == "test_api_security":
        return f"{len(data.get('findings', []))} api-security finding(s)"
    if skill == "test_auth_deep":
        return f"{len(data.get('findings', []))} auth-depth finding(s)"
    if skill == "attempt_auth":
        return (
            f"{'authenticated' if data.get('authenticated') else 'not authenticated'}, "
            f"{len(data.get('identities') or [])} identity(s)"
        )
    if skill == "test_sensitive_files":
        return (
            f"{len(data.get('exposed') or [])} exposed path(s), "
            f"{len(data.get('credentials') or [])} credential pivot(s), "
            f"{len(data.get('loot') or [])} loot item(s)"
        )
    if skill == "test_ssrf":
        creds = data.get("cloud_credentials") or []
        return (
            f"{'vulnerable' if data.get('vulnerable') else 'clean'}, "
            f"{len(data.get('findings', []))} finding(s), "
            f"{len(creds) if isinstance(creds, list) else 1 if creds else 0} cloud credential signal(s)"
        )
    if skill == "prove_cloud_impact":
        impact = data.get("cloud_impact") or {}
        return f"cloud impact {'ready' if impact else 'unavailable'} ({impact.get('reason', 'no_reason')})"
    if skill == "prove_post_auth_crown":
        return (
            "post-auth crown replay verified"
            if data.get("verified")
            else f"post-auth crown replay unavailable ({data.get('reason', 'no_reason')})"
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
            if key == "identities":
                merged: dict[str, dict[str, Any]] = {}
                for item in [*context[key], *value]:
                    if not isinstance(item, dict):
                        continue
                    name = str(item.get("name") or item.get("identity") or item.get("token") or "")
                    if not name:
                        continue
                    existing = merged.get(name, {})
                    next_item = {**existing, **item}
                    if existing.get("owned_ids") or item.get("owned_ids"):
                        next_item["owned_ids"] = sorted(
                            {
                                str(v)
                                for v in [
                                    *list(existing.get("owned_ids") or []),
                                    *list(item.get("owned_ids") or []),
                                ]
                            },
                            key=str,
                        )
                    merged[name] = next_item
                context[key] = list(merged.values())
                continue
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
        title = (
            "Broken object authorization across identities" if cross else "IDOR on object pattern"
        )
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
            copied.setdefault("finding_type", str(copied.get("type") or "generic_finding"))
            copied.setdefault("title", str(copied.get("type") or "finding"))
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
    resolved_template = template
    if not kwargs.get("steps") and template == "post_auth_crown" and not context.get("token"):
        resolved_template = "auth_to_crown"
    steps = list(kwargs.get("steps") or _default_steps(resolved_template))

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
        "resolved_template": resolved_template,
        "steps": executed,
        "findings": findings,
        "finding_count": len(findings),
        "context_keys": sorted(context.keys()),
    }
