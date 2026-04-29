"""Skill: test_infra — exposed .git, .env, cloud metadata, subdomain enumeration."""
from __future__ import annotations
import asyncio
import logging
import re
import socket
from typing import Any
from urllib.parse import urlparse
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

GIT_PATHS = [tuple(_c) for _c in _load_ds("test_infra", "git_paths")]  # ADR-007 Phase 3-9 — data in data/payloads/test_infra.json

ENV_PATHS = _load_ds("test_infra", "env_paths")  # ADR-007 Phase 3-9 — data in data/payloads/test_infra.json

CLOUD_ENDPOINTS = _load_ds("test_infra", "cloud_endpoints")  # ADR-007 Phase 3-9 — data in data/payloads/test_infra.json

SUBDOMAIN_PREFIXES = _load_ds("test_infra", "subdomain_prefixes")  # ADR-007 Phase 3-9 — data in data/payloads/test_infra.json


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Test infrastructure: exposed repos, env files, cloud metadata, subdomains.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    parsed = urlparse(target)
    hostname = parsed.hostname or "localhost"
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    # --- Git exposure ---
    async def check_git(path: str, signature: str) -> None:
        nonlocal tested
        async with sem:
            tested += 1
            try:
                r = await _session.request("GET", f"{target}{path}")
                if r.status == 200 and r.body_length > 20:
                    if not signature or signature in r.text:
                        findings.append({
                            "type": "git_exposed",
                            "payload": path,
                            "evidence": f"Git file accessible (status {r.status}, {r.body_length}B)",
                            "response_preview": r.text[:300],
                            "severity": "critical",
                        })
                        logger.info("Git exposed: %s", path)
            except Exception:
                pass

    await asyncio.gather(*[check_git(p, s) for p, s in GIT_PATHS])

    # --- Env file exposure ---
    async def check_env(path: str) -> None:
        nonlocal tested
        async with sem:
            tested += 1
            try:
                r = await _session.request("GET", f"{target}{path}")
                if r.status == 200 and r.body_length > 10:
                    body = r.text
                    # Env files typically have KEY=VALUE lines
                    if re.search(r"^[A-Z_]+=.+", body, re.MULTILINE):
                        findings.append({
                            "type": "env_exposed",
                            "payload": path,
                            "evidence": "Environment file accessible with KEY=VALUE pairs",
                            "response_preview": body[:300],
                            "severity": "critical",
                        })
            except Exception:
                pass

    await asyncio.gather(*[check_env(p) for p in ENV_PATHS])

    # --- Cloud metadata (direct from server via SSRF-style) ---
    for ep in CLOUD_ENDPOINTS:
        tested += 1
        async with sem:
            try:
                ep_url: str = ep["url"]
                ep_headers: dict[str, str] = ep.get("headers", {})
                # Cloud metadata endpoints may be on different hosts — use a fresh session
                _cloud_mgr = SessionManager()
                _cloud_session = await _cloud_mgr.get_session(ep_url)
                r = await _cloud_session.request("GET", ep_url, headers=ep_headers)
                if r.status == 200:
                    if not ep["detect"] or ep["detect"] in r.text:
                        findings.append({
                            "type": "cloud_metadata",
                            "payload": ep_url,
                            "evidence": f"{ep['desc']} accessible (status {r.status})",
                            "response_preview": r.text[:300],
                            "severity": "critical",
                        })
            except Exception:
                pass

    # --- Subdomain enumeration via DNS ---
    # Only if target is a domain (not IP)
    if not re.match(r"\d+\.\d+\.\d+\.\d+", hostname) and hostname != "localhost":
        parts = hostname.split(".")
        if len(parts) >= 2:
            base_domain = ".".join(parts[-2:])

            async def check_subdomain(prefix: str) -> None:
                nonlocal tested
                async with sem:
                    tested += 1
                    fqdn = f"{prefix}.{base_domain}"
                    try:
                        loop = asyncio.get_event_loop()
                        dns_result = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                        if dns_result:
                            findings.append({
                                "type": "subdomain_found",
                                "payload": fqdn,
                                "evidence": f"Resolves to {dns_result}",
                                "severity": "informational",
                            })
                    except (socket.gaierror, OSError):
                        pass

            await asyncio.gather(*[check_subdomain(p) for p in SUBDOMAIN_PREFIXES])

    # --- Firebase check ---
    tested += 1
    async with sem:
        if not re.match(r"\d+\.\d+\.\d+\.\d+", hostname):
            firebase_name = hostname.split(".")[0]
            try:
                _fb_url = f"https://{firebase_name}.firebaseio.com"
                _fb_mgr = SessionManager()
                _fb_session = await _fb_mgr.get_session(_fb_url)
                r = await _fb_session.request("GET", f"{_fb_url}/.json")
                if r.status == 200 and r.text != "null":
                    findings.append({
                        "type": "firebase_open",
                        "payload": f"{firebase_name}.firebaseio.com",
                        "evidence": "Firebase database publicly readable",
                        "response_preview": r.text[:300],
                        "severity": "critical",
                    })
            except Exception:
                pass

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
