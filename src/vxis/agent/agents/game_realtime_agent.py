"""L7-30 GameRealtimeAgent — WebSocket manipulation, UDP packet manipulation, client validation bypass."""

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
class GameRealtimeAgent(BaseAgent):
    agent_id = "game_realtime"
    description = "WebSocket manipulation, UDP packet manipulation, client-side validation bypass"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. WebSocket endpoint discovery
        ws_findings = await self._probe_websocket(target)
        findings.extend(ws_findings)
        if ws_findings:
            hypotheses.append(Hypothesis(
                title=f"WebSocket injection/hijacking on {target}",
                rationale="WebSocket endpoints discovered — may lack origin validation",
                probability=0.6, impact=0.8,
                suggested_agent="api",
            ))

        # 2. Nuclei WebSocket/realtime templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{nf.get('info', {}).get('name', '')} — {nf.get('matched-at', target)}",
                severity=sev_map.get(sev_str, Severity.INFO),
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                tags=["game", "realtime", "nuclei"],
            ))

        # 3. Check for common real-time service ports (game servers, TURN/STUN)
        realtime_ports = await self._check_realtime_ports(target)
        findings.extend(realtime_ports)

        return AgentResult(
            agent_id=self.agent_id, findings=findings, hypotheses=hypotheses,
            status="completed", metadata={"total_findings": len(findings)},
        )

    async def _probe_websocket(self, target: str) -> list[Evidence]:
        if not shutil.which("curl"):
            return []
        ws_paths = ["/ws", "/websocket", "/socket.io/", "/sockjs", "/cable"]
        findings: list[Evidence] = []
        for path in ws_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-I", f"{target}{path}",
                "-H", "Upgrade: websocket",
                "-H", "Connection: Upgrade",
                "--max-time", "5",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                headers = stdout.decode().lower()
                if "101" in headers or "upgrade" in headers or "websocket" in headers:
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"WebSocket endpoint found: {target}{path}",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.HTTP_EXCHANGE,
                        description=f"WebSocket upgrade accepted at {path}",
                        response=stdout.decode()[:2048],
                        tags=["game", "websocket", "realtime"],
                    ))
            except asyncio.TimeoutError:
                continue
        return findings

    async def _check_realtime_ports(self, target: str) -> list[Evidence]:
        if not shutil.which("nmap"):
            return []
        # Common realtime/game ports: STUN(3478), TURN(3479), game(7777-7778, 27015)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-sV", "--top-ports", "20", "-p", "3478,3479,7777,7778,27015",
            target, "-oX", "-",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            findings: list[Evidence] = []
            if "open" in output:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Realtime/game service ports open on {target}",
                    severity=Severity.LOW,
                    evidence_type=EvidenceType.NETWORK,
                    description="UDP-based realtime service ports detected",
                    response=output[:4096],
                    tags=["game", "realtime", "udp"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_nuclei(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target, "-tags", "websocket,socketio,realtime",
            "-severity", "critical,high,medium", "-rate-limit", rate, "-jsonl", "-silent",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
        results = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
