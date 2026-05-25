"""META-10 QuantumRiskAgent — RSA/ECC status, PQC readiness, harvest-now-decrypt-later risk."""

from __future__ import annotations

import asyncio
import json
import re
import shutil

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


# Quantum vulnerability classification for algorithms
_ALGO_QUANTUM_STATUS = {
    # Asymmetric — vulnerable to Shor's algorithm
    "RSA": {"vulnerable": True, "type": "asymmetric", "attack": "Shor's algorithm"},
    "ECDSA": {"vulnerable": True, "type": "asymmetric", "attack": "Shor's algorithm"},
    "ECDH": {"vulnerable": True, "type": "asymmetric", "attack": "Shor's algorithm"},
    "EdDSA": {"vulnerable": True, "type": "asymmetric", "attack": "Shor's algorithm"},
    "DH": {"vulnerable": True, "type": "asymmetric", "attack": "Shor's algorithm"},
    "DSA": {"vulnerable": True, "type": "asymmetric", "attack": "Shor's algorithm"},
    # Symmetric — reduced security (Grover's algorithm halves effective key length)
    "AES-128": {"vulnerable": False, "type": "symmetric", "note": "Grover reduces to 64-bit"},
    "AES-256": {
        "vulnerable": False,
        "type": "symmetric",
        "note": "Grover reduces to 128-bit (safe)",
    },
    "ChaCha20": {
        "vulnerable": False,
        "type": "symmetric",
        "note": "256-bit key, post-quantum safe",
    },
    # Post-quantum candidates (NIST PQC)
    "ML-KEM": {"vulnerable": False, "type": "pqc", "note": "NIST FIPS 203 (Kyber)"},
    "ML-DSA": {"vulnerable": False, "type": "pqc", "note": "NIST FIPS 204 (Dilithium)"},
    "SLH-DSA": {"vulnerable": False, "type": "pqc", "note": "NIST FIPS 205 (SPHINCS+)"},
}


@register
class QuantumRiskAgent(BaseAgent):
    agent_id = "quantum_risk"
    description = (
        "Quantum computing risk assessment: RSA/ECC vulnerability analysis, "
        "post-quantum cryptography readiness, harvest-now-decrypt-later risk"
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: TLS cipher suite analysis for quantum vulnerability
        tls_findings = await self._analyze_tls_quantum_risk(target)
        findings.extend(tls_findings)

        # Phase 2: Certificate key analysis
        cert_findings = await self._analyze_certificate_keys(target)
        findings.extend(cert_findings)

        # Phase 3: SSH key exchange quantum risk
        ssh_findings = await self._analyze_ssh_quantum_risk(target)
        findings.extend(ssh_findings)

        # Phase 4: PQC readiness assessment
        pqc_assessment = self._assess_pqc_readiness(findings)
        findings.append(pqc_assessment)

        # Phase 5: Harvest-now-decrypt-later risk
        hndl_risk = self._assess_hndl_risk(target, findings)
        findings.append(hndl_risk)

        # Phase 6: Quantum timeline assessment
        findings.append(
            Evidence(
                agent_id=self.agent_id,
                title="Quantum threat timeline assessment",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OTHER,
                description=(
                    "Quantum Computing Threat Timeline:\n"
                    "- 2025-2028: NIST PQC standards finalized and adopted\n"
                    "- 2028-2032: Early cryptographically-relevant quantum computers\n"
                    "- 2030-2035: Estimated RSA-2048 break timeline (optimistic)\n"
                    "- NOW: Harvest-now-decrypt-later attacks already occurring\n\n"
                    "Recommended Actions:\n"
                    "1. Inventory all cryptographic assets\n"
                    "2. Prioritize hybrid key exchange (classical + PQC)\n"
                    "3. Migrate to ML-KEM (Kyber) for key encapsulation\n"
                    "4. Migrate to ML-DSA (Dilithium) for digital signatures\n"
                    "5. Increase symmetric key sizes to 256-bit minimum"
                ),
                tags=["quantum", "timeline", "assessment"],
            )
        )

        # Generate hypotheses
        vulnerable_algos = [
            f.title for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        if vulnerable_algos:
            hypotheses.append(
                Hypothesis(
                    title=f"Harvest-now-decrypt-later attack on {target} data",
                    rationale="Quantum-vulnerable cryptography in use",
                    probability=0.6,
                    impact=0.9,
                    suggested_agent="crypto_tls",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"Long-term data confidentiality risk for {target}",
                    rationale="RSA/ECC will be broken by quantum computers",
                    probability=0.7,
                    impact=0.85,
                    suggested_agent="quantum_risk",
                )
            )
        hypotheses.append(
            Hypothesis(
                title=f"PQC migration planning needed for {target}",
                rationale="All organizations need quantum-safe crypto migration",
                probability=0.9,
                impact=0.7,
                suggested_agent="compliance",
            )
        )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "quantum_vulnerable_services": sum(
                    1
                    for f in findings
                    if f.severity in (Severity.HIGH, Severity.CRITICAL) and "quantum" in f.tags
                ),
                "pqc_ready": any("pqc-detected" in f.tags for f in findings),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _analyze_tls_quantum_risk(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("nmap"):
            return results

        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-Pn",
            "--script",
            "ssl-enum-ciphers",
            "-p",
            "443",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode()

        vulnerable_ciphers: list[str] = []
        safe_ciphers: list[str] = []
        pqc_ciphers: list[str] = []

        for line in output.splitlines():
            line = line.strip()
            if "TLS_" in line or "SSL_" in line:
                cipher = line.split()[0] if line.split() else line
                # Check for quantum-vulnerable key exchange
                if any(kw in cipher.upper() for kw in ("RSA", "ECDH", "DHE", "ECDSA")):
                    vulnerable_ciphers.append(cipher)
                elif any(kw in cipher.upper() for kw in ("KYBER", "ML_KEM")):
                    pqc_ciphers.append(cipher)
                else:
                    safe_ciphers.append(cipher)

        if vulnerable_ciphers:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Quantum-vulnerable TLS ciphers on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"{len(vulnerable_ciphers)} TLS cipher suites use RSA/ECC "
                        "key exchange, which will be broken by quantum computers "
                        "using Shor's algorithm. Captured TLS sessions can be "
                        "decrypted retroactively."
                    ),
                    response=json.dumps(
                        {
                            "vulnerable": vulnerable_ciphers[:15],
                            "safe": safe_ciphers[:10],
                            "pqc": pqc_ciphers,
                        },
                        indent=2,
                    ),
                    tags=["quantum", "tls", "cipher-suite", "shor-algorithm"],
                )
            )

        if pqc_ciphers:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Post-quantum cipher suites detected on {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"PQC cipher suites: {', '.join(pqc_ciphers)}",
                    tags=["quantum", "pqc-detected", "tls"],
                )
            )

        return results

    async def _analyze_certificate_keys(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("openssl"):
            return results

        proc = await asyncio.create_subprocess_exec(
            "openssl",
            "s_client",
            "-connect",
            f"{target}:443",
            "-servername",
            target,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=b"Q\n"),
            timeout=15,
        )
        output = stdout.decode()

        # Extract key type and size
        key_info = {}
        if "Server public key is" in output:
            match = re.search(r"Server public key is (\d+) bit", output)
            if match:
                key_info["bits"] = int(match.group(1))

        # Determine key type from certificate
        if "rsaEncryption" in output:
            key_info["algorithm"] = "RSA"
        elif "id-ecPublicKey" in output or "ecdsa" in output.lower():
            key_info["algorithm"] = "ECDSA"
        elif "ED25519" in output.upper():
            key_info["algorithm"] = "EdDSA"

        if key_info.get("algorithm"):
            algo = key_info["algorithm"]
            algo_status = _ALGO_QUANTUM_STATUS.get(algo, {})
            severity = Severity.HIGH if algo_status.get("vulnerable") else Severity.INFO
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Certificate uses {algo} ({key_info.get('bits', '?')}-bit) on {target}",
                    severity=severity,
                    evidence_type=EvidenceType.MISCONFIGURATION
                    if severity == Severity.HIGH
                    else EvidenceType.NETWORK,
                    description=(
                        f"Certificate algorithm: {algo} ({key_info.get('bits', 'unknown')}-bit)\n"
                        f"Quantum vulnerable: {'YES' if algo_status.get('vulnerable') else 'No'}\n"
                        f"Attack: {algo_status.get('attack', 'N/A')}\n"
                        f"Recommendation: Migrate to ML-DSA (Dilithium) or hybrid certificates"
                    ),
                    response=json.dumps(key_info, indent=2),
                    tags=["quantum", "certificate", algo.lower()],
                )
            )
        return results

    async def _analyze_ssh_quantum_risk(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("ssh-keyscan"):
            return results

        proc = await asyncio.create_subprocess_exec(
            "ssh-keyscan",
            "-T",
            "5",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode()

        key_types: list[str] = []
        vulnerable_types: list[str] = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                key_type = parts[1]
                key_types.append(key_type)
                if any(kw in key_type.lower() for kw in ("rsa", "ecdsa", "ed25519")):
                    vulnerable_types.append(key_type)

        if vulnerable_types:
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Quantum-vulnerable SSH host keys on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"SSH host key types: {', '.join(vulnerable_types)}. "
                        "All current SSH key types (RSA, ECDSA, Ed25519) are vulnerable "
                        "to quantum attack. OpenSSH 9.0+ supports hybrid sntrup761x25519."
                    ),
                    response="\n".join(key_types),
                    tags=["quantum", "ssh", "host-key"],
                )
            )
        return results

    def _assess_pqc_readiness(self, findings: list[Evidence]) -> Evidence:
        pqc_detected = any("pqc-detected" in f.tags for f in findings)
        quantum_vulns = sum(
            1 for f in findings if "quantum" in f.tags and f.severity == Severity.HIGH
        )
        if pqc_detected:
            readiness = "PARTIAL"
            sev = Severity.MEDIUM
            desc = (
                "Post-quantum cryptography partially deployed. Continue migration "
                "to ensure all services use PQC or hybrid algorithms."
            )
        elif quantum_vulns > 0:
            readiness = "NOT READY"
            sev = Severity.HIGH
            desc = (
                f"{quantum_vulns} quantum-vulnerable services found. No PQC "
                "deployment detected. Immediate migration planning recommended."
            )
        else:
            readiness = "UNKNOWN"
            sev = Severity.INFO
            desc = "Unable to fully assess PQC readiness from external scan."

        return Evidence(
            agent_id=self.agent_id,
            title=f"Post-Quantum Cryptography readiness: {readiness}",
            severity=sev,
            evidence_type=EvidenceType.OTHER,
            description=desc,
            tags=["quantum", "pqc", "readiness"],
        )

    def _assess_hndl_risk(self, target: str, findings: list[Evidence]) -> Evidence:
        """Assess Harvest Now, Decrypt Later risk."""
        quantum_vulns = [
            f
            for f in findings
            if "quantum" in f.tags and f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        if quantum_vulns:
            return Evidence(
                agent_id=self.agent_id,
                title=f"Harvest-Now-Decrypt-Later risk: HIGH for {target}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.OTHER,
                description=(
                    "HNDL Risk Assessment: HIGH\n\n"
                    "Nation-state actors are currently intercepting and storing "
                    "encrypted traffic for future decryption with quantum computers. "
                    f"Target {target} uses quantum-vulnerable cryptography.\n\n"
                    "Risk factors:\n"
                    "- Data sensitivity: confidential/regulatory data at risk\n"
                    "- Data shelf life: secrets valid for years are high-value targets\n"
                    "- Adversary capability: state-level actors actively harvesting\n"
                    "- Timeline: quantum decryption estimated within 10-15 years\n\n"
                    "Immediate action: deploy hybrid key exchange (e.g., X25519Kyber768)"
                ),
                tags=["quantum", "hndl", "harvest-now-decrypt-later"],
            )
        return Evidence(
            agent_id=self.agent_id,
            title=f"Harvest-Now-Decrypt-Later risk assessment for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "HNDL risk could not be fully assessed from external scanning. "
                "Recommend internal cryptographic inventory review."
            ),
            tags=["quantum", "hndl"],
        )
