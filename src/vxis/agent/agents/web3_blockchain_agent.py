"""L7 Web3BlockchainAgent — Smart contract, private key exposure, DeFi analysis."""

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
class Web3BlockchainAgent(BaseAgent):
    agent_id = "web3_blockchain"
    description = "Smart contract analysis, private key exposure, DeFi vulnerability scanning"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Scan for exposed Web3 endpoints and wallets
        web3_endpoints = await self._check_web3_endpoints(target)
        for ep in web3_endpoints:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Web3 endpoint exposed: {ep['path']}",
                severity=ep.get("severity", Severity.MEDIUM),
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=ep["description"],
                response=ep.get("response", ""),
                tags=["web3", "blockchain", ep.get("tag", "endpoint")],
            ))
            if ep.get("severity") in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Wallet drain via exposed Web3 endpoint on {target}",
                    rationale=ep["description"],
                    probability=0.6, impact=0.95,
                    suggested_agent="web3_blockchain",
                ))

        # Phase 2: Check for leaked private keys and mnemonics
        key_findings = await self._scan_for_keys(target)
        for kf in key_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Blockchain key material exposed: {kf['type']}",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.SECRET,
                description=kf["description"],
                response=kf.get("evidence", "")[:2048],
                tags=["web3", "private-key", "secret"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Fund theft via exposed {kf['type']} on {target}",
                rationale=f"Blockchain private key material found: {kf['type']}",
                probability=0.9, impact=1.0,
                suggested_agent="secrets_lifecycle",
            ))

        # Phase 3: Smart contract interaction endpoints
        contract_findings = await self._check_smart_contracts(target)
        for cf in contract_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=cf["title"],
                severity=cf["severity"],
                evidence_type=EvidenceType.CODE_FINDING,
                description=cf["description"],
                response=cf.get("detail", ""),
                tags=["web3", "smart-contract"] + cf.get("tags", []),
            ))

        # Phase 4: DeFi-specific checks
        defi_findings = await self._check_defi_exposure(target)
        for df in defi_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=df["title"],
                severity=df["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=df["description"],
                tags=["web3", "defi"],
            ))

        # Phase 5: Nuclei Web3 templates
        nuclei_results = await self._run_nuclei_web3(target, context.mission.stealth)
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
                tags=["web3", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "web3_endpoints": len(web3_endpoints),
                "keys_found": len(key_findings),
            },
        )

    async def _check_web3_endpoints(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        endpoints = [
            ("/api/wallet", "wallet-api", "Wallet API endpoint"),
            ("/api/v1/blockchain", "blockchain-api", "Blockchain API"),
            ("/web3/provider", "web3-provider", "Web3 provider endpoint"),
            ("/api/contract", "contract-api", "Smart contract API"),
            ("/etherscan", "etherscan-proxy", "Etherscan proxy"),
        ]
        for path, tag, desc in endpoints:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"{target}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status in ("200", "201", "301", "302"):
                    results.append({
                        "path": path, "tag": tag,
                        "description": f"{desc} at {path} is accessible (HTTP {status})",
                        "severity": Severity.MEDIUM,
                        "response": f"HTTP {status}",
                    })
            except asyncio.TimeoutError:
                continue

        # Check JSON-RPC endpoint
        rpc_result = await self._check_json_rpc(target)
        if rpc_result:
            results.append(rpc_result)
        return results

    async def _check_json_rpc(self, target: str) -> dict[str, Any] | None:
        if not shutil.which("curl"):
            return None
        rpc_payload = json.dumps({
            "jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1,
        })
        for path in ["/", "/rpc", "/api/eth"]:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-X", "POST", f"{target}{path}",
                "-H", "Content-Type: application/json",
                "-d", rpc_payload, "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                data = json.loads(stdout.decode())
                if "result" in data:
                    return {
                        "path": path, "tag": "json-rpc",
                        "description": f"Ethereum JSON-RPC endpoint exposed at {path}",
                        "severity": Severity.HIGH,
                        "response": json.dumps(data)[:1024],
                    }
            except (asyncio.TimeoutError, json.JSONDecodeError):
                continue
        return None

    async def _scan_for_keys(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        # Fetch JS bundles and check for key patterns
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", target, "--max-time", "15",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            body = stdout.decode(errors="replace")
            import re
            # Check for Ethereum private keys
            eth_keys = re.findall(r'["\']?(0x[a-fA-F0-9]{64})["\']?', body)
            for key in set(eth_keys[:3]):
                results.append({
                    "type": "Ethereum private key",
                    "description": f"Possible Ethereum private key found in page source",
                    "evidence": f"Key pattern: {key[:10]}...{key[-6:]}",
                })
            # Check for mnemonic phrases
            mnemonic_pattern = re.findall(
                r'["\']([a-z]+(?: [a-z]+){11,23})["\']', body
            )
            for phrase in mnemonic_pattern[:2]:
                words = phrase.split()
                if len(words) in (12, 24):
                    results.append({
                        "type": "BIP39 mnemonic phrase",
                        "description": "Possible BIP39 mnemonic seed phrase found in source",
                        "evidence": f"Mnemonic: {words[0]} {words[1]} ... ({len(words)} words)",
                    })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_smart_contracts(self, target: str) -> list[dict[str, Any]]:
        """Check for exposed smart contract ABIs and deployment artifacts."""
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        abi_paths = [
            "/contracts/abi.json", "/build/contracts/",
            "/artifacts/contracts/", "/deployments/",
        ]
        for path in abi_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"{target}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status == "200":
                    results.append({
                        "title": f"Smart contract artifact exposed: {path}",
                        "severity": Severity.MEDIUM,
                        "description": f"Contract ABI/deployment data at {path} is publicly accessible",
                        "tags": ["abi", "deployment"],
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_defi_exposure(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        defi_paths = [
            "/api/v1/pools", "/api/v1/pairs", "/api/v1/swap",
            "/api/liquidity", "/api/staking",
        ]
        for path in defi_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"{target}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status == "200":
                    results.append({
                        "title": f"DeFi API endpoint exposed: {path}",
                        "severity": Severity.MEDIUM,
                        "description": f"DeFi endpoint at {path} is accessible without auth",
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _run_nuclei_web3(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "web3,blockchain,ethereum,crypto,defi",
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
