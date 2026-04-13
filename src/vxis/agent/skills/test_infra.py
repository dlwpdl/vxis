"""Skill: test_infra — exposed .git, .env, cloud metadata, subdomain enumeration."""
from __future__ import annotations
import asyncio
import logging
import re
import socket
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

GIT_PATHS = [
    ("/.git/HEAD", "ref: refs/heads/"),
    ("/.git/config", "[core]"),
    ("/.git/index", "DIRC"),
    ("/.git/COMMIT_EDITMSG", ""),
    ("/.git/description", ""),
    ("/.git/packed-refs", "# pack-refs"),
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]

ENV_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.staging",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/env.js",
    "/config.env",
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]

CLOUD_ENDPOINTS = [
    {"url": "http://169.254.169.254/latest/meta-data/", "detect": "ami-", "desc": "AWS metadata"},
    {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "detect": "AccessKeyId", "desc": "AWS IAM creds"},
    {"url": "http://metadata.google.internal/computeMetadata/v1/project/project-id",
     "headers": {"Metadata-Flavor": "Google"}, "detect": "", "desc": "GCP metadata"},
    {"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "headers": {"Metadata": "true"}, "detect": "", "desc": "Azure metadata"},
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]

SUBDOMAIN_PREFIXES = [
    "admin", "api", "dev", "staging", "test", "beta", "internal",
    "mail", "vpn", "git", "ci", "jenkins", "grafana", "monitor",
    "db", "mysql", "redis", "elastic", "kibana", "prometheus",
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Test infrastructure: exposed repos, env files, cloud metadata, subdomains.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    import httpx

    target = target_url.rstrip("/")
    parsed = urlparse(target)
    hostname = parsed.hostname or "localhost"
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        # --- Git exposure ---
        async def check_git(path: str, signature: str) -> None:
            nonlocal tested
            async with sem:
                tested += 1
                try:
                    r = await client.get(f"{target}{path}")
                    if r.status_code == 200 and len(r.content) > 20:
                        if not signature or signature in r.text:
                            findings.append({
                                "type": "git_exposed",
                                "payload": path,
                                "evidence": f"Git file accessible (status {r.status_code}, {len(r.content)}B)",
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
                    r = await client.get(f"{target}{path}")
                    if r.status_code == 200 and len(r.content) > 10:
                        body = r.text
                        # Env files typically have KEY=VALUE lines
                        if re.search(r"^[A-Z_]+=.+", body, re.MULTILINE):
                            findings.append({
                                "type": "env_exposed",
                                "payload": path,
                                "evidence": f"Environment file accessible with KEY=VALUE pairs",
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
                    headers = ep.get("headers", {})
                    r = await client.get(ep["url"], headers=headers, timeout=3)
                    if r.status_code == 200:
                        if not ep["detect"] or ep["detect"] in r.text:
                            findings.append({
                                "type": "cloud_metadata",
                                "payload": ep["url"],
                                "evidence": f"{ep['desc']} accessible (status {r.status_code})",
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
                            result = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                            if result:
                                findings.append({
                                    "type": "subdomain_found",
                                    "payload": fqdn,
                                    "evidence": f"Resolves to {result}",
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
                    r = await client.get(f"https://{firebase_name}.firebaseio.com/.json", timeout=5)
                    if r.status_code == 200 and r.text != "null":
                        findings.append({
                            "type": "firebase_open",
                            "payload": f"{firebase_name}.firebaseio.com",
                            "evidence": f"Firebase database publicly readable",
                            "response_preview": r.text[:300],
                            "severity": "critical",
                        })
                except Exception:
                    pass

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
