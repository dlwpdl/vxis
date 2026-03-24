"""L7 CDNEdgeAgent — Cache poisoning, Cache Deception, Origin IP exposure."""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class CDNEdgeAgent(BaseAgent):
    agent_id = "cdn_edge"
    description = "Cache poisoning, Cache Deception, Origin IP exposure analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: CDN detection
        cdn_info = await self._detect_cdn(target)
        if cdn_info:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"CDN detected: {cdn_info['provider']} for {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"CDN provider: {cdn_info['provider']}. Headers: {cdn_info.get('headers', '')}",
                response=json.dumps(cdn_info, indent=2),
                tags=["cdn", cdn_info["provider"].lower()],
            ))

        # Phase 2: Cache Poisoning tests
        poison_results = await self._test_cache_poisoning(target)
        for pr in poison_results:
            if pr.get("vulnerable"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Cache Poisoning vector: {pr['vector']} on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        f"Web cache poisoning possible via {pr['vector']}. "
                        f"Unkeyed header/parameter reflected in cached response."
                    ),
                    request=pr.get("request", ""),
                    response=pr.get("response", "")[:4096],
                    tags=["cdn", "cache-poisoning", pr["vector"]],
                ))
                hypotheses.append(Hypothesis(
                    title=f"XSS via cache poisoning on {target}",
                    rationale=f"Cache poisoning via {pr['vector']} confirmed",
                    probability=0.7, impact=0.85,
                    suggested_agent="web",
                ))

        # Phase 3: Web Cache Deception
        deception_results = await self._test_cache_deception(target)
        for dr in deception_results:
            if dr.get("vulnerable"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Web Cache Deception: {dr['path']} on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        f"Web cache deception detected. Dynamic content cached at "
                        f"{dr['path']}. User-specific data may be leaked."
                    ),
                    request=dr.get("request", ""),
                    response=dr.get("response", "")[:4096],
                    tags=["cdn", "cache-deception"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Account takeover via cache deception on {target}",
                    rationale="Cache deception can expose authenticated user data",
                    probability=0.6, impact=0.9,
                    suggested_agent="web",
                ))

        # Phase 4: Origin IP exposure
        origin_results = await self._find_origin_ip(target)
        for ori in origin_results:
            if ori.get("ip"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Origin IP exposed: {ori['ip']} for {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"Origin server IP {ori['ip']} discovered via {ori['method']}. "
                        f"This bypasses CDN/WAF protections."
                    ),
                    response=json.dumps(ori, indent=2),
                    tags=["cdn", "origin-ip", ori["method"]],
                ))
                hypotheses.append(Hypothesis(
                    title=f"WAF bypass via direct origin access at {ori['ip']}",
                    rationale=f"Origin IP discovered: {ori['ip']}",
                    probability=0.85, impact=0.8,
                    suggested_agent="web",
                ))

        # Phase 5: Cache header analysis
        cache_headers = await self._analyze_cache_headers(target)
        for ch in cache_headers:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ch["title"],
                severity=ch["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=ch["description"],
                tags=["cdn", "cache-headers"],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "cdn_provider": cdn_info.get("provider") if cdn_info else None,
                "cache_poison_vectors": len([p for p in poison_results if p.get("vulnerable")]),
            },
        )

    async def _detect_cdn(self, target: str) -> dict[str, Any] | None:
        if not shutil.which("curl"):
            return None
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-I", target, "--max-time", "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            headers = stdout.decode(errors="replace").lower()
            cdn_signatures = {
                "cloudflare": ("cf-ray", "cloudflare"),
                "cloudfront": ("x-amz-cf", "cloudfront"),
                "akamai": ("x-akamai", "akamai"),
                "fastly": ("x-fastly", "fastly"),
                "varnish": ("x-varnish", "varnish"),
                "cdn77": ("cdn77", "x-cdn77"),
                "stackpath": ("x-sp", "stackpath"),
                "incapsula": ("x-iinfo", "incapsula"),
                "sucuri": ("x-sucuri", "sucuri"),
            }
            for provider, signatures in cdn_signatures.items():
                for sig in signatures:
                    if sig in headers:
                        return {"provider": provider, "headers": headers[:1024]}
        except asyncio.TimeoutError:
            pass
        return None

    async def _test_cache_poisoning(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        unkeyed_headers = [
            ("X-Forwarded-Host", "evil.com", "x-forwarded-host"),
            ("X-Host", "evil.com", "x-host"),
            ("X-Original-URL", "/admin", "x-original-url"),
            ("X-Rewrite-URL", "/admin", "x-rewrite-url"),
            ("X-Forwarded-Scheme", "nothttps", "x-forwarded-scheme"),
        ]
        for header, value, vector in unkeyed_headers:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", target,
                "-H", f"{header}: {value}",
                "-w", "\n%{http_code}", "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                vulnerable = value in body and status in ("200", "301", "302")
                results.append({
                    "vector": vector,
                    "vulnerable": vulnerable,
                    "request": f"GET {target} -H '{header}: {value}'",
                    "response": f"HTTP {status}\n{body[:2048]}",
                })
            except asyncio.TimeoutError:
                results.append({"vector": vector, "vulnerable": False})
        return results

    async def _test_cache_deception(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        deception_paths = [
            "/account/nonexistent.css",
            "/profile/random.js",
            "/api/user/image.png",
            "/dashboard/test.svg",
        ]
        for path in deception_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-D", "-", f"{target}{path}", "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                has_cache = any(
                    indicator in output.lower()
                    for indicator in ("x-cache: hit", "cf-cache-status: hit", "age:", "x-cache-status")
                )
                has_content = "200" in output[:100] and len(output) > 500
                vulnerable = has_cache and has_content
                results.append({
                    "path": path,
                    "vulnerable": vulnerable,
                    "request": f"GET {target}{path}",
                    "response": output[:2048],
                })
            except asyncio.TimeoutError:
                results.append({"path": path, "vulnerable": False})
        return results

    async def _find_origin_ip(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        domain = target.lstrip("https://").lstrip("http://").split("/")[0]

        if shutil.which("dig"):
            origin_subs = [
                f"direct.{domain}", f"origin.{domain}", f"direct-connect.{domain}",
                f"mail.{domain}", f"ftp.{domain}", f"staging.{domain}",
                f"dev.{domain}", f"cpanel.{domain}",
            ]
            for sub in origin_subs:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", "A", sub,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                    ip = stdout.decode().strip()
                    if ip and not ip.startswith(";"):
                        results.append({
                            "ip": ip.split("\n")[0],
                            "method": f"subdomain-{sub}",
                        })
                except asyncio.TimeoutError:
                    continue
        return results

    async def _analyze_cache_headers(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-I", target, "--max-time", "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            headers = stdout.decode(errors="replace")
            header_lower = headers.lower()

            if "cache-control" not in header_lower:
                results.append({
                    "title": f"Missing Cache-Control header on {target}",
                    "severity": Severity.LOW,
                    "description": "No Cache-Control header; browser caching behavior undefined",
                })
            if "vary" not in header_lower:
                results.append({
                    "title": f"Missing Vary header on {target}",
                    "severity": Severity.LOW,
                    "description": "No Vary header; increases cache poisoning attack surface",
                })
            if "private" not in header_lower and "no-store" not in header_lower:
                if "set-cookie" in header_lower:
                    results.append({
                        "title": f"Cacheable response with Set-Cookie on {target}",
                        "severity": Severity.MEDIUM,
                        "description": "Response sets cookies but may be cached (no private/no-store)",
                    })
        except asyncio.TimeoutError:
            pass
        return results
