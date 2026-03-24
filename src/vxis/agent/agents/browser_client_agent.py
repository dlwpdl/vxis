"""L7 BrowserClientAgent — Service Worker, WASM, postMessage, Prototype Pollution."""

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
class BrowserClientAgent(BaseAgent):
    agent_id = "browser_client"
    description = "Service Worker abuse, WASM analysis, postMessage, Prototype Pollution"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Check for service worker registration
        sw_results = await self._check_service_workers(target)
        for sw in sw_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Service Worker detected: {sw['url']}",
                severity=Severity.LOW,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"Service Worker found at {sw['url']}. Service workers can intercept "
                    f"network requests, cache data, and persist across sessions."
                ),
                response=sw.get("content", "")[:4096],
                tags=["browser-client", "service-worker"],
            ))
            if sw.get("has_fetch_handler"):
                hypotheses.append(Hypothesis(
                    title=f"Service Worker cache poisoning on {target}",
                    rationale="Service Worker with fetch handler can be exploited for cache poisoning",
                    probability=0.4, impact=0.7,
                    suggested_agent="cdn_edge",
                ))

        # Phase 2: Check for postMessage vulnerabilities
        postmsg_results = await self._check_postmessage(target)
        for pm in postmsg_results:
            if pm.get("vulnerable"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Insecure postMessage handler on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.CODE_FINDING,
                    description=(
                        f"postMessage event listener found without origin validation. "
                        f"This may allow cross-origin message injection. "
                        f"Pattern: {pm.get('pattern', '')}"
                    ),
                    response=pm.get("code", "")[:4096],
                    tags=["browser-client", "postmessage", "xss"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"DOM XSS via postMessage on {target}",
                    rationale="postMessage handler lacks origin check",
                    probability=0.7, impact=0.85,
                    suggested_agent="web",
                ))

        # Phase 3: Check for Prototype Pollution vectors
        proto_results = await self._check_prototype_pollution(target)
        for pr in proto_results:
            if pr.get("vulnerable"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Prototype Pollution vector: {pr['vector']} on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=(
                        f"Prototype Pollution detected via {pr['vector']}. "
                        f"This may lead to XSS, auth bypass, or RCE."
                    ),
                    request=pr.get("request", ""),
                    response=pr.get("response", "")[:4096],
                    tags=["browser-client", "prototype-pollution"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"RCE via Prototype Pollution gadget on {target}",
                    rationale="Prototype Pollution confirmed; gadget chains may exist",
                    probability=0.5, impact=0.95,
                    suggested_agent="web",
                ))

        # Phase 4: WASM module detection
        wasm_results = await self._check_wasm(target)
        for wr in wasm_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"WebAssembly module found: {wr['url']}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.CODE_FINDING,
                description=(
                    f"WASM module at {wr['url']} ({wr.get('size', 'unknown')} bytes). "
                    f"May contain business logic, crypto operations, or obfuscated code."
                ),
                tags=["browser-client", "wasm", "webassembly"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Business logic bypass via WASM reverse engineering on {target}",
                rationale="WASM module detected; client-side validation may be bypassable",
                probability=0.5, impact=0.7,
                suggested_agent="browser_client",
            ))

        # Phase 5: Nuclei client-side templates
        nuclei_results = await self._run_nuclei_client(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            matched = nf.get("matched-at", target)
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["browser-client", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "service_workers": len(sw_results),
                "postmessage_vulns": len([p for p in postmsg_results if p.get("vulnerable")]),
                "proto_pollution": len([p for p in proto_results if p.get("vulnerable")]),
            },
        )

    async def _check_service_workers(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        sw_paths = ["/sw.js", "/service-worker.js", "/serviceworker.js", "/ngsw-worker.js"]
        for path in sw_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"{target}{path}", "-w", "\n%{http_code}",
                "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status == "200" and ("addEventListener" in body or "self." in body):
                    results.append({
                        "url": f"{target}{path}",
                        "content": body[:4096],
                        "has_fetch_handler": "fetch" in body.lower(),
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_postmessage(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", target, "--max-time", "15",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            body = stdout.decode(errors="replace")
            # Search for postMessage listeners without origin checks
            if "addEventListener" in body and "message" in body:
                has_origin_check = "origin" in body.lower() and (
                    "event.origin" in body or "e.origin" in body
                )
                if not has_origin_check:
                    results.append({
                        "vulnerable": True,
                        "pattern": "addEventListener('message') without origin check",
                        "code": body[body.find("addEventListener"):body.find("addEventListener") + 500],
                    })
                else:
                    results.append({"vulnerable": False, "pattern": "origin check present"})
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_prototype_pollution(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Test URL parameter-based prototype pollution
        payloads = [
            ("?__proto__[polluted]=true", "query-proto"),
            ("?constructor[prototype][polluted]=true", "query-constructor"),
            ("#__proto__[polluted]=true", "hash-proto"),
        ]
        for payload, vector in payloads:
            url = f"{target}/{payload}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", url, "-w", "\n%{http_code}", "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                # Check for signs of pollution (reflected in response, error changes)
                vulnerable = (
                    status == "200"
                    and ("polluted" in body or "true" in body[:500])
                )
                results.append({
                    "vector": vector,
                    "vulnerable": vulnerable,
                    "request": f"GET {url}",
                    "response": f"HTTP {status}\n{body[:2048]}",
                })
            except asyncio.TimeoutError:
                results.append({"vector": vector, "vulnerable": False})
        return results

    async def _check_wasm(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Fetch main page and look for .wasm references
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", target, "--max-time", "15",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            body = stdout.decode(errors="replace")
            # Find .wasm references
            import re
            wasm_refs = re.findall(r'["\']([^"\']*\.wasm)["\']', body)
            for ref in set(wasm_refs[:5]):
                url = ref if ref.startswith("http") else f"{target}/{ref.lstrip('/')}"
                results.append({"url": url, "size": "unknown"})
        except asyncio.TimeoutError:
            pass
        return results

    async def _run_nuclei_client(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "xss,dom,cors,postmessage,prototype-pollution",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
        results: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
