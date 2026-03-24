"""CRT-P10 CryptoTLSAgent — SSL/TLS analysis, certificates, JWT, encryption strength."""

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

# testssl.sh severity mapping
_TESTSSL_SEV: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "OK": Severity.INFO,
    "INFO": Severity.INFO,
}


@register
class CryptoTLSAgent(BaseAgent):
    agent_id = "crypto_tls"
    description = "SSL/TLS protocol analysis, certificate audit, JWT weaknesses, cipher strength"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        stealth = context.mission.stealth

        # 1. testssl.sh comprehensive scan
        testssl_results = await self._run_testssl(target)
        for item in testssl_results:
            severity_str = item.get("severity", "INFO").upper()
            severity = _TESTSSL_SEV.get(severity_str, Severity.INFO)
            if severity == Severity.INFO and severity_str == "OK":
                continue  # Skip OK results

            finding_text = item.get("finding", "")
            test_id = item.get("id", "")

            if severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"TLS: {test_id} — {finding_text[:80]}",
                    severity=severity,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=finding_text,
                    response=json.dumps(item, indent=2),
                    tags=["tls", "testssl", test_id],
                ))

                # Chain hypotheses for critical TLS issues
                if severity == Severity.CRITICAL:
                    hypotheses.append(Hypothesis(
                        title=f"MITM via TLS vulnerability on {target}",
                        rationale=f"Critical TLS issue: {test_id} — {finding_text[:60]}",
                        probability=0.7, impact=0.9,
                        suggested_agent="l2_network",
                    ))

        # 2. Certificate analysis
        cert_findings = await self._run_cert_analysis(target)
        findings.extend(cert_findings)
        for cf in cert_findings:
            if cf.severity in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Certificate impersonation for {target}",
                    rationale=f"Certificate issue: {cf.title}",
                    probability=0.5, impact=0.8,
                    suggested_agent="web",
                ))

        # 3. Nuclei TLS/crypto templates
        nuclei_results = await self._run_nuclei_crypto(target, stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            template_id = nf.get("template-id", "")
            matched = nf.get("matched-at", target)

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["tls", "nuclei", template_id],
            ))

            # JWT-specific hypothesis chaining
            if "jwt" in template_id.lower() or "jwt" in name.lower():
                hypotheses.append(Hypothesis(
                    title=f"JWT algorithm confusion / none attack on {target}",
                    rationale=f"JWT vulnerability found: {name}",
                    probability=0.75, impact=0.9,
                    suggested_agent="api",
                    suggested_tool="jwt_tool",
                ))

        # 4. Check for weak cipher suites and protocols
        weak_crypto = [f for f in findings if any(
            kw in f.description.lower() for kw in
            ("rc4", "des", "null", "export", "sslv2", "sslv3", "sweet32", "beast", "poodle")
        )]
        if weak_crypto:
            hypotheses.append(Hypothesis(
                title=f"Traffic decryption via weak cipher on {target}",
                rationale=f"{len(weak_crypto)} weak cipher/protocol issues found",
                probability=0.5, impact=0.85,
                suggested_agent="l2_network",
            ))

        # 5. HSTS / certificate transparency check
        hsts_finding = await self._check_hsts(target)
        if hsts_finding:
            findings.append(hsts_finding)

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "testssl_findings": len(testssl_results),
                "nuclei_findings": len(nuclei_results),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_testssl(self, target: str) -> list[dict[str, Any]]:
        """Run testssl.sh and parse JSON output."""
        testssl_bin = shutil.which("testssl.sh") or shutil.which("testssl")
        if not testssl_bin:
            return []
        domain = target.lstrip("*.").split("/")[0]
        if ":" not in domain:
            domain = f"{domain}:443"

        proc = await asyncio.create_subprocess_exec(
            testssl_bin, "--jsonfile", "/dev/stdout",
            "--warnings", "off", "--quiet",
            "--sneaky",  # Minimal fingerprinting
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            output = stdout.decode()
            # testssl.sh outputs JSON array
            try:
                results = json.loads(output)
                if isinstance(results, list):
                    return results
            except json.JSONDecodeError:
                # Try line-by-line JSON
                results = []
                for line in output.splitlines():
                    if line.strip():
                        try:
                            results.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
                return results
        except asyncio.TimeoutError:
            return []
        return []

    async def _run_cert_analysis(self, target: str) -> list[Evidence]:
        """Analyse TLS certificate using openssl."""
        if not shutil.which("openssl"):
            return []
        domain = target.lstrip("*.").split("/")[0].split(":")[0]
        proc = await asyncio.create_subprocess_exec(
            "openssl", "s_client", "-connect", f"{domain}:443",
            "-servername", domain, "-showcerts",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=b""), timeout=15,
            )
            output = stdout.decode()
            findings: list[Evidence] = []

            # Parse certificate details
            cert_proc = await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-connect", f"{domain}:443",
                "-servername", domain,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            cert_stdout, _ = await asyncio.wait_for(
                cert_proc.communicate(input=b""), timeout=15,
            )
            cert_output = cert_stdout.decode()

            # Check for self-signed certificates
            if "self signed" in cert_output.lower() or "self-signed" in cert_output.lower():
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Self-signed certificate on {domain}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description="Self-signed TLS certificate detected. "
                                "Users may be trained to bypass warnings.",
                    response=cert_output[:4096],
                    tags=["tls", "certificate", "self-signed"],
                ))

            # Check for expired certificate
            if "certificate has expired" in cert_output.lower():
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Expired certificate on {domain}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description="TLS certificate has expired. "
                                "Indicates poor certificate management.",
                    response=cert_output[:4096],
                    tags=["tls", "certificate", "expired"],
                ))

            # Check for wildcard certificate
            if "*.%s" % domain.split(".", 1)[-1] in cert_output if "." in domain else False:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Wildcard certificate on {domain}",
                    severity=Severity.LOW,
                    evidence_type=EvidenceType.NETWORK,
                    description="Wildcard TLS certificate. If private key is compromised, "
                                "all subdomains are affected.",
                    response=cert_output[:2048],
                    tags=["tls", "certificate", "wildcard"],
                ))

            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_nuclei_crypto(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "80"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "ssl,tls,jwt,crypto,certificate,heartbleed",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
            results = []
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        except asyncio.TimeoutError:
            return []

    async def _check_hsts(self, target: str) -> Evidence | None:
        """Check for HSTS header."""
        if not shutil.which("curl"):
            return None
        domain = target.lstrip("*.").split("/")[0].split(":")[0]
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-I", "-m", "10", f"https://{domain}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            headers = stdout.decode().lower()
            if "strict-transport-security" not in headers:
                return Evidence(
                    agent_id=self.agent_id,
                    title=f"Missing HSTS header on {domain}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "HTTP Strict-Transport-Security header not set. "
                        "Users can be downgraded to HTTP via SSL-stripping."
                    ),
                    response=stdout.decode()[:2048],
                    tags=["tls", "hsts", "missing-header"],
                )
        except asyncio.TimeoutError:
            pass
        return None
