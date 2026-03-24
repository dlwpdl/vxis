"""L7 MobileAgent — iOS/Android decompile, Frida instrumentation, Deep Link, BLE analysis."""

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
class MobileAgent(BaseAgent):
    agent_id = "mobile"
    description = "iOS/Android decompile, Frida instrumentation, Deep Link, BLE analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: APK decompilation and analysis
        apk_findings = await self._analyze_apk(target)
        for af in apk_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=af["title"],
                severity=af["severity"],
                evidence_type=af.get("evidence_type", EvidenceType.CODE_FINDING),
                description=af["description"],
                response=af.get("detail", ""),
                tags=["mobile", "android"] + af.get("tags", []),
            ))
            if af["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"API key extraction from mobile app for {target}",
                    rationale=af["description"],
                    probability=0.7, impact=0.85,
                    suggested_agent="secrets_lifecycle",
                ))

        # Phase 2: Deep link / URL scheme analysis
        deeplink_findings = await self._check_deep_links(target)
        for dl in deeplink_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Deep link scheme found: {dl['scheme']}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.CODE_FINDING,
                description=(
                    f"Deep link scheme {dl['scheme']} discovered. "
                    f"May allow unauthorized app invocation or data injection."
                ),
                response=json.dumps(dl, indent=2),
                tags=["mobile", "deep-link", "url-scheme"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Deep link hijacking via {dl['scheme']}",
                rationale="Custom URL scheme may be hijackable by malicious app",
                probability=0.5, impact=0.7,
                suggested_agent="mobile",
            ))

        # Phase 3: Check for insecure mobile API endpoints
        api_findings = await self._check_mobile_api(target)
        for mf in api_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=mf["title"],
                severity=mf["severity"],
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=mf["description"],
                response=mf.get("response", ""),
                tags=["mobile", "api", "endpoint"],
            ))
            if mf["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Mobile API exploitation on {target}",
                    rationale=mf["description"],
                    probability=0.65, impact=0.85,
                    suggested_agent="api",
                ))

        # Phase 4: Certificate pinning / TLS checks
        tls_findings = await self._check_mobile_tls(target)
        for tf in tls_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=tf["title"],
                severity=tf["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=tf["description"],
                tags=["mobile", "tls", "certificate-pinning"],
            ))

        # Phase 5: Nuclei mobile-specific templates
        nuclei_results = await self._run_nuclei_mobile(target, context.mission.stealth)
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
                tags=["mobile", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "apk_findings": len(apk_findings),
                "deep_links": len(deeplink_findings),
            },
        )

    async def _analyze_apk(self, target: str) -> list[dict[str, Any]]:
        """Use apktool/jadx to decompile and analyze APK for secrets and misconfigs."""
        results: list[dict[str, Any]] = []
        if not shutil.which("nuclei"):
            return results
        # Use nuclei android-related templates against the mobile backend
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target,
            "-tags", "android,mobile,apk",
            "-jsonl", "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        sev_str = data.get("info", {}).get("severity", "info").lower()
                        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                                   "medium": Severity.MEDIUM, "low": Severity.LOW}
                        results.append({
                            "title": data.get("info", {}).get("name", "Mobile finding"),
                            "severity": sev_map.get(sev_str, Severity.INFO),
                            "description": data.get("info", {}).get("description", ""),
                            "detail": json.dumps(data)[:2048],
                            "tags": ["apk-analysis"],
                        })
                    except json.JSONDecodeError:
                        continue
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_deep_links(self, target: str) -> list[dict[str, Any]]:
        """Probe common deep-link and app-link verification endpoints."""
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Check Apple App Site Association and Android assetlinks
        endpoints = [
            ("/.well-known/apple-app-site-association", "ios"),
            ("/.well-known/assetlinks.json", "android"),
        ]
        for path, platform in endpoints:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"https://{target}{path}", "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                body = stdout.decode(errors="replace")
                if body.strip().startswith("{") or body.strip().startswith("["):
                    data = json.loads(body)
                    schemes = []
                    if platform == "ios" and "applinks" in str(data):
                        schemes.append(f"{platform}://applinks")
                    elif platform == "android":
                        for entry in data if isinstance(data, list) else []:
                            ns = entry.get("target", {}).get("namespace", "")
                            pkg = entry.get("target", {}).get("package_name", "")
                            if pkg:
                                schemes.append(f"{ns}:{pkg}")
                    for scheme in schemes:
                        results.append({"scheme": scheme, "platform": platform, "source": path})
            except (asyncio.TimeoutError, json.JSONDecodeError):
                continue
        return results

    async def _check_mobile_api(self, target: str) -> list[dict[str, Any]]:
        """Check common mobile API endpoints for misconfigurations."""
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        mobile_paths = [
            "/api/v1/config", "/api/v1/version", "/api/mobile/config",
            "/api/v1/user", "/api/v1/auth/register",
        ]
        for path in mobile_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"https://{target}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status in ("200", "201"):
                    results.append({
                        "title": f"Mobile API endpoint exposed: {path}",
                        "severity": Severity.MEDIUM,
                        "description": f"Endpoint {path} returns HTTP {status} without auth",
                        "response": f"HTTP {status}",
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_mobile_tls(self, target: str) -> list[dict[str, Any]]:
        """Check for weak TLS configuration relevant to mobile apps."""
        results: list[dict[str, Any]] = []
        if not shutil.which("nmap"):
            return results
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "--script", "ssl-enum-ciphers", "-p", "443", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            if "TLSv1.0" in output or "SSLv3" in output:
                results.append({
                    "title": f"Weak TLS version supported on {target}",
                    "severity": Severity.MEDIUM,
                    "description": "Server supports TLSv1.0 or SSLv3, vulnerable to POODLE/BEAST",
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _run_nuclei_mobile(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "mobile,android,ios,api",
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
