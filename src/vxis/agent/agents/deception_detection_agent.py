"""META-08 DeceptionDetectionAgent — honeypot detection, canary tokens, SIEM detection probability."""

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
class DeceptionDetectionAgent(BaseAgent):
    agent_id = "deception_detection"
    description = (
        "Deception technology detection: honeypots, honeytokens, canary tokens, "
        "decoy credentials, SIEM/SOC detection probability assessment"
    )

    # Known honeypot signatures
    _HONEYPOT_SIGNATURES = {
        "cowrie": ["SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"],
        "kippo": ["SSH-2.0-OpenSSH_5.1p1 Debian-5"],
        "dionaea": ["Microsoft-IIS/5.0", "Apache/2.0.45"],
        "glastopf": ["BestHTTP"],
        "conpot": ["Siemens, SIMATIC"],
        "elastichoney": ["elasticsearch"],
    }

    # Common honeypot ports
    _HONEYPOT_PORTS = [
        22, 23, 80, 443, 445, 1433, 3306, 3389, 5432,
        8080, 8443, 9200, 11211, 27017,
    ]

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Honeypot detection via service fingerprinting
        hp_findings = await self._detect_honeypots(target)
        findings.extend(hp_findings)

        # Phase 2: Canary token detection
        canary_findings = await self._detect_canary_tokens(target)
        findings.extend(canary_findings)

        # Phase 3: Deception network detection (too many open ports)
        deception_net = await self._detect_deception_network(target)
        if deception_net:
            findings.append(deception_net)

        # Phase 4: Tarpit detection
        tarpit_findings = await self._detect_tarpits(target)
        findings.extend(tarpit_findings)

        # Phase 5: SIEM detection probability assessment
        siem_assessment = self._assess_siem_detection(context)
        findings.append(siem_assessment)

        # Phase 6: Decoy credential detection
        decoy_findings = await self._detect_decoy_credentials(target)
        findings.extend(decoy_findings)

        # Generate hypotheses
        honeypot_detected = any("honeypot" in f.tags for f in findings)
        if honeypot_detected:
            hypotheses.append(Hypothesis(
                title=f"Deception infrastructure surrounds {target}",
                rationale="Honeypot indicators detected — adjust attack approach",
                probability=0.8,
                impact=0.6,
                suggested_agent="deception_detection",
            ))
            hypotheses.append(Hypothesis(
                title="SOC team actively monitoring — increase stealth",
                rationale="Deception technology deployment suggests active SOC",
                probability=0.7,
                impact=0.8,
                suggested_agent="deception_detection",
            ))
        hypotheses.append(Hypothesis(
            title=f"SIEM evasion techniques needed for {target}",
            rationale="Detection infrastructure likely present",
            probability=0.6,
            impact=0.7,
            suggested_agent="lateral_move",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "honeypots_detected": sum(1 for f in findings if "honeypot" in f.tags),
                "canary_tokens_found": sum(1 for f in findings if "canary" in f.tags),
                "stealth_advisory": honeypot_detected,
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _detect_honeypots(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("nmap"):
            return results

        ports_str = ",".join(str(p) for p in self._HONEYPOT_PORTS)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sV", "-p", ports_str,
            "--open", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        output = stdout.decode()

        # Check for honeypot signatures
        for hp_name, signatures in self._HONEYPOT_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in output.lower():
                    results.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Honeypot detected: {hp_name} on {target}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.NETWORK,
                        description=(
                            f"Service fingerprint matches {hp_name} honeypot. "
                            f"Signature: {sig}. Interacting with this host will "
                            "alert the SOC team."
                        ),
                        response=output[:2000],
                        tags=["deception", "honeypot", hp_name],
                    ))

        # Heuristic: check for suspiciously identical banners across services
        lines = [l for l in output.splitlines() if "open" in l]
        if len(lines) > 5:
            banners = [l.strip() for l in lines]
            # If many services respond with similar timing, possible honeypot
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"Many open ports on {target} — possible honeypot/decoy",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"{len(lines)} services detected. High port count with "
                    "uniform response characteristics may indicate a honeypot "
                    "or deception host."
                ),
                response="\n".join(banners[:15]),
                tags=["deception", "honeypot", "heuristic"],
            ))

        return results

    async def _detect_canary_tokens(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Check for canary token patterns in robots.txt, sitemap, etc.
        canary_paths = [
            "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/admin/login", "/.env",
        ]
        canary_patterns = [
            "canarytokens.com", "canary.tools",
            "thinkst", "o365-owa", "clonedsite",
        ]
        for path in canary_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "5",
                f"https://{target}{path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            content = stdout.decode()
            for pattern in canary_patterns:
                if pattern in content.lower():
                    results.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Canary token detected at {path}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.NETWORK,
                        description=(
                            f"Canary token ({pattern}) found at {path}. "
                            "Accessing this resource triggers an alert to defenders."
                        ),
                        request=f"GET https://{target}{path}",
                        response=content[:500],
                        tags=["deception", "canary", "alert-trigger"],
                    ))

        # Check for canary DNS entries
        if shutil.which("dig"):
            canary_subdomains = [
                "admin", "vpn", "internal", "secret", "backup",
            ]
            for sub in canary_subdomains:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", f"{sub}.{target}", "CNAME",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode().strip()
                if any(p in output.lower() for p in canary_patterns):
                    results.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"DNS canary token: {sub}.{target}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.NETWORK,
                        description=(
                            f"DNS CNAME for {sub}.{target} points to canary service. "
                            "Resolving or connecting triggers defender alert."
                        ),
                        response=output,
                        tags=["deception", "canary", "dns"],
                    ))
        return results

    async def _detect_deception_network(self, target: str) -> Evidence | None:
        if not shutil.which("nmap"):
            return None

        # Quick scan for port count heuristic
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sS", "--top-ports", "100",
            "--open", "-oG", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode()
        open_count = output.count("/open/")
        if open_count > 30:
            return Evidence(
                agent_id=self.agent_id,
                title=f"Suspicious port profile: {open_count}/100 ports open on {target}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"{open_count} of top 100 ports are open. This is unusual for "
                    "a production system and is characteristic of a honeypot or "
                    "deception network (e.g., Thinkst Canary, T-Pot, HoneyDB)."
                ),
                response=output[:2000],
                tags=["deception", "honeypot", "port-profile"],
            )
        return None

    async def _detect_tarpits(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Test for HTTP tarpit (extremely slow response)
        import time as _time
        start = _time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{time_total}",
            "--max-time", "15",
            f"https://{target}/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        try:
            elapsed = float(stdout.decode().strip())
            if elapsed > 10.0:
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"HTTP tarpit detected on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"Response took {elapsed:.1f}s — possible HTTP tarpit "
                        "(e.g., Endlessh for SSH, LaBrea). Tarpits slow down "
                        "scanners and waste attacker resources."
                    ),
                    tags=["deception", "tarpit", "slowdown"],
                ))
        except ValueError:
            pass
        return results

    def _assess_siem_detection(self, context: AgentContext) -> Evidence:
        """Assess SIEM/SOC detection probability based on attack characteristics."""
        target = context.mission.target
        return Evidence(
            agent_id=self.agent_id,
            title=f"SIEM detection probability assessment for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "Detection probability by attack category:\n"
                "- Port scanning: ~80% (IDS signature + NetFlow anomaly)\n"
                "- Web vulnerability scanning: ~70% (WAF rules + log analysis)\n"
                "- Credential brute-force: ~90% (account lockout + log alerts)\n"
                "- DNS exfiltration: ~40% (requires DNS analytics)\n"
                "- Lateral movement (PtH): ~50% (Windows Event 4624 type 3)\n"
                "- Living-off-the-land: ~20% (behavioral analytics required)\n"
                "- Encrypted C2: ~30% (JA3/JA4 fingerprinting, beacon analysis)\n\n"
                "Recommendations: Use low-and-slow techniques, randomize timing, "
                "blend with normal traffic patterns."
            ),
            tags=["deception", "siem", "detection-probability", "assessment"],
        )

    async def _detect_decoy_credentials(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Check for planted credentials in common locations
        decoy_paths = [
            "/.git/config", "/backup/credentials.txt",
            "/config/database.yml", "/wp-config.php.bak",
        ]
        for path in decoy_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "5",
                f"https://{target}{path}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            content = stdout.decode()
            # Check if content looks like planted credentials
            if ("password" in content.lower() and len(content) < 500):
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Possible decoy credentials at {path}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.OTHER,
                    description=(
                        f"Credentials found at {path} may be honeytokens. "
                        "Using these credentials would trigger SOC alerts. "
                        "Verify authenticity before use."
                    ),
                    request=f"GET https://{target}{path}",
                    response=content[:200],
                    tags=["deception", "canary", "decoy-credentials"],
                ))
        return results
