"""Skill: test_infra — exposed .git, .env, cloud metadata, subdomain enumeration."""
from __future__ import annotations
import asyncio
import os
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

_CLOUD_METADATA_TIMEOUT_SECONDS = 4.0
_FIREBASE_TIMEOUT_SECONDS = 5.0


def _normalize_seed_paths(seed_paths: Any) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in seed_paths or []:
        path = str(raw or "").strip()
        if not path:
            continue
        if "://" in path:
            path = urlparse(path).path or "/"
        if not path.startswith("/"):
            path = f"/{path}"
        if len(path) > 1:
            path = path.rstrip("/")
        if path not in seen:
            seen.add(path)
            normalized.append(path)
    return normalized[:20]


def _seeded_git_env_paths(seed_paths: Any) -> list[tuple[str, str | None]]:
    candidates: list[tuple[str, str | None]] = []
    seen: set[str] = set()

    def _add(path: str, signature: str | None = None) -> None:
        normalized = path.strip()
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        if normalized in seen:
            return
        seen.add(normalized)
        candidates.append((normalized, signature))

    for seed in _normalize_seed_paths(seed_paths):
        lowered = seed.lower()
        parent = os.path.dirname(seed) or "/"
        if parent != "/":
            _add(f"{parent}/.git/config", "[core]")
            _add(f"{parent}/.git/HEAD", "ref:")
            _add(f"{parent}/.env")
            _add(f"{parent}/.env.bak")
        if "/.git/" in lowered or lowered.endswith("/.git"):
            _add(seed if "/.git/" in lowered else f"{seed}/HEAD", "ref:")
        if lowered.endswith(".env") or lowered.endswith(".env.bak"):
            _add(seed)
        if any(token in lowered for token in ("backup", "dump", "config", "env", "git")):
            _add(seed)
    return candidates[:16]


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
    allow_direct_cloud_metadata_probe = bool(kwargs.get("allow_direct_cloud_metadata_probe", False))
    seeded_paths = _seeded_git_env_paths(kwargs.get("seed_paths"))

    _mgr = SessionManager()
    _cloud_mgr = SessionManager()
    _firebase_mgr = SessionManager()
    _session = await _mgr.get_session(target)

    try:
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
                                "path": path,
                                "payload": path,
                                "evidence": f"Git file accessible (status {r.status}, {r.body_length}B)",
                                "response_preview": r.text[:300],
                                "status": r.status,
                                "size": r.body_length,
                                "severity": "critical",
                            })
                            logger.info("Git exposed: %s", path)
                except Exception:
                    pass

        git_targets = list(GIT_PATHS)
        for path, signature in seeded_paths:
            if "/.git" in path:
                git_targets.append((path, signature or ""))
        await asyncio.gather(*[check_git(p, s) for p, s in git_targets])

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
                                "path": path,
                                "payload": path,
                                "evidence": "Environment file accessible with KEY=VALUE pairs",
                                "response_preview": body[:300],
                                "status": r.status,
                                "size": r.body_length,
                                "severity": "critical",
                            })
                except Exception:
                    pass

        env_targets = list(ENV_PATHS)
        for path, _signature in seeded_paths:
            if path.endswith(".env") or path.endswith(".env.bak"):
                env_targets.append(path)
        await asyncio.gather(*[check_env(p) for p in env_targets])

        # --- Cloud metadata ---
        # Do not probe metadata endpoints directly from the scanner host by
        # default. That tests our environment, not the target. SSRF-style
        # metadata reachability belongs in test_ssrf or an explicit opt-in.
        if allow_direct_cloud_metadata_probe:
            async def check_cloud_endpoint(ep: dict[str, Any]) -> None:
                nonlocal tested
                async with sem:
                    tested += 1
                    try:
                        ep_url: str = ep["url"]
                        ep_headers: dict[str, str] = ep.get("headers", {})
                        _cloud_session = await _cloud_mgr.get_session(
                            ep_url,
                            timeout=_CLOUD_METADATA_TIMEOUT_SECONDS,
                        )
                        r = await _cloud_session.request("GET", ep_url, headers=ep_headers)
                        if r.status == 200 and (not ep["detect"] or ep["detect"] in r.text):
                            findings.append({
                                "type": "cloud_metadata",
                                "path": ep_url,
                                "payload": ep_url,
                                "evidence": f"{ep['desc']} accessible (status {r.status})",
                                "response_preview": r.text[:300],
                                "status": r.status,
                                "size": r.body_length,
                                "severity": "critical",
                            })
                    except Exception:
                        pass

            await asyncio.gather(*[check_cloud_endpoint(ep) for ep in CLOUD_ENDPOINTS])

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
                    _fb_session = await _firebase_mgr.get_session(
                        _fb_url,
                        timeout=_FIREBASE_TIMEOUT_SECONDS,
                    )
                    r = await _fb_session.request("GET", f"{_fb_url}/.json")
                    if r.status == 200 and r.text != "null":
                        findings.append({
                            "type": "firebase_open",
                            "path": f"{firebase_name}.firebaseio.com/.json",
                            "payload": f"{firebase_name}.firebaseio.com",
                            "evidence": "Firebase database publicly readable",
                            "response_preview": r.text[:300],
                            "status": r.status,
                            "size": r.body_length,
                            "severity": "critical",
                        })
                except Exception:
                    pass
    finally:
        await _mgr.close_all()
        await _cloud_mgr.close_all()
        await _firebase_mgr.close_all()

    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "tested": tested,
        "seed_paths": [path for path, _ in seeded_paths],
    }
