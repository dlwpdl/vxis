"""Skill: test_crypto — TLS weaknesses, weak hashes, hardcoded secrets in JS."""
from __future__ import annotations
import asyncio
import logging
import re
import ssl
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

SECRET_PATTERNS = _load_ds("test_crypto", "secret_patterns")  # ADR-007 Phase 3-9 — data in data/payloads/test_crypto.json

JS_PATHS = _load_ds("test_crypto", "js_paths")  # ADR-007 Phase 3-9 — data in data/payloads/test_crypto.json


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Test cryptographic weaknesses: TLS, hashes, secrets in JS.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    from urllib.parse import urlparse
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    parsed = urlparse(target)
    hostname = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    # --- TLS version check ---
    if parsed.scheme == "https":
        weak_protocols = [
            ("SSLv3", ssl.PROTOCOL_TLS),
            ("TLSv1.0", ssl.PROTOCOL_TLS),
            ("TLSv1.1", ssl.PROTOCOL_TLS),
        ]
        for proto_name, proto in weak_protocols:
            tested += 1
            try:
                ctx = ssl.SSLContext(proto)
                if proto_name == "SSLv3":
                    ctx.options &= ~ssl.OP_NO_SSLv3
                    ctx.maximum_version = ssl.TLSVersion.SSLv3
                elif proto_name == "TLSv1.0":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1
                elif proto_name == "TLSv1.1":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=ctx), timeout=5
                )
                writer.close()
                await writer.wait_closed()
                findings.append({
                    "type": f"weak_tls_{proto_name.lower().replace('.', '')}",
                    "payload": proto_name,
                    "evidence": f"Server accepts {proto_name} connections",
                    "severity": "high" if proto_name == "SSLv3" else "medium",
                })
            except Exception:
                pass  # Expected: server rejects weak protocol

    # --- Scan JS bundles for secrets ---
    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    # First get the main page to find JS links
    js_urls: list[str] = list(JS_PATHS)
    try:
        r = await _session.request("GET", target)
        body = r.text
        # Extract JS file paths from HTML
        for match in re.finditer(r'src=["\']([^"\']*\.js[^"\']*)["\']', body):
            js_path = match.group(1)
            if js_path.startswith("http"):
                continue  # Skip external CDNs
            if not js_path.startswith("/"):
                js_path = "/" + js_path
            js_urls.append(js_path)
    except Exception:
        pass

    async def scan_js(path: str) -> None:
        nonlocal tested
        async with sem:
            tested += 1
            try:
                r = await _session.request("GET", f"{target}{path}")
                if r.status != 200 or r.body_length < 50:
                    return
                content = r.text
                for sp in SECRET_PATTERNS:
                    matches = re.findall(sp["pattern"], content, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "type": "hardcoded_secret",
                            "payload": f"{sp['desc']} in {path}",
                            "evidence": f"Found {len(matches)} match(es): {matches[0][:60]}...",
                            "severity": "critical",
                        })
                        logger.info("Secret found: %s in %s", sp["desc"], path)
                        break  # One finding per JS file
            except Exception:
                pass

    await asyncio.gather(*[scan_js(p) for p in js_urls])

    # --- Check for weak hashes in API responses ---
    hash_endpoints = ["/api/users", "/api/profile", "/api/account"]
    for ep in hash_endpoints:
        tested += 1
        async with sem:
            try:
                r = await _session.request("GET", f"{target}{ep}")
                body = r.text
                # MD5 hash pattern (32 hex)
                if re.search(r'"(?:password|hash|passwd)":\s*"[a-f0-9]{32}"', body, re.IGNORECASE):
                    findings.append({
                        "type": "weak_hash_md5",
                        "payload": f"MD5 hash in {ep}",
                        "evidence": "API response contains MD5-length hash for password field",
                        "response_preview": body[:300],
                        "severity": "high",
                    })
                # SHA1 hash pattern (40 hex)
                if re.search(r'"(?:password|hash|passwd)":\s*"[a-f0-9]{40}"', body, re.IGNORECASE):
                    findings.append({
                        "type": "weak_hash_sha1",
                        "payload": f"SHA1 hash in {ep}",
                        "evidence": "API response contains SHA1-length hash for password field",
                        "response_preview": body[:300],
                        "severity": "high",
                    })
            except Exception:
                pass

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
