"""L7 GameRealtimeAgent — WebSocket manipulation, UDP packet manipulation, client validation bypass."""

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

        # Phase 1: WebSocket endpoint discovery
        ws_findings = await self._discover_websockets(target)
        for ws in ws_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"WebSocket endpoint found: {ws['url']}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=f"WebSocket upgrade accepted at {ws['url']}",
                response=ws.get("headers", "")[:2048],
                tags=["game", "websocket", "realtime"],
            ))

        if ws_findings:
            hypotheses.append(Hypothesis(
                title=f"WebSocket injection/hijacking on {target}",
                rationale="WebSocket endpoints discovered; may lack origin validation",
                probability=0.6, impact=0.8,
                suggested_agent="game_realtime",
            ))

        # Phase 2: WebSocket origin bypass (CSWSH)
        origin_results = await self._test_ws_origin_bypass(target, ws_findings)
        for or_ in origin_results:
            if or_.get("vulnerable"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"WebSocket CSWSH: cross-origin accepted at {or_['url']}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"WebSocket at {or_['url']} accepts connections from arbitrary origins. "
                        f"Cross-Site WebSocket Hijacking possible."
                    ),
                    request=or_.get("request", ""),
                    response=or_.get("response", ""),
                    tags=["game", "websocket", "cswsh"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Data theft via CSWSH on {target}",
                    rationale="WebSocket allows cross-origin connections",
                    probability=0.7, impact=0.85,
                    suggested_agent="web",
                ))

        # Phase 3: UDP game server scanning
        udp_results = await self._scan_udp_game_ports(target)
        for ur in udp_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ur["title"],
                severity=ur["severity"],
                evidence_type=EvidenceType.NETWORK,
                description=ur["description"],
                response=ur.get("detail", ""),
                tags=["game", "udp"] + ur.get("tags", []),
            ))

        # Phase 4: Client-side validation detection
        client_results = await self._check_client_validation(target)
        for cr in client_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=cr["title"],
                severity=cr["severity"],
                evidence_type=EvidenceType.CODE_FINDING,
                description=cr["description"],
                tags=["game", "client-validation"],
            ))
            if cr["severity"] in (Severity.MEDIUM, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"Game logic bypass via client validation on {target}",
                    rationale=cr["description"],
                    probability=0.7, impact=0.75,
                    suggested_agent="browser_client",
                ))

        # Phase 5: Rate limiting check
        rate_results = await self._check_rate_limits(target)
        for rr in rate_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=rr["title"],
                severity=rr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=rr["description"],
                tags=["game", "rate-limit"],
            ))

        # Phase 6: Nuclei WebSocket/realtime templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{nf.get('info', {}).get('name', '')} — {nf.get('matched-at', target)}",
                severity=sev_map.get(sev_str, Severity.INFO),
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["game", "realtime", "nuclei", nf.get("template-id", "")],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "websocket_endpoints": len(ws_findings),
                "udp_services": len(udp_results),
            },
        )

    async def _discover_websockets(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        domain = target.lstrip("https://").lstrip("http://").split("/")[0]
        ws_paths = ["/ws", "/websocket", "/socket.io/", "/sockjs", "/cable", "/live", "/signalr"]
        for path in ws_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-I",
                "-H", "Connection: Upgrade",
                "-H", "Upgrade: websocket",
                "-H", "Sec-WebSocket-Version: 13",
                "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                f"https://{domain}{path}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                headers = stdout.decode(errors="replace").lower()
                if "101" in headers or "upgrade" in headers or "websocket" in headers:
                    results.append({
                        "url": f"wss://{domain}{path}",
                        "headers": headers[:512],
                    })
            except asyncio.TimeoutError:
                continue

        # Also check page source for ws:// URLs
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", target, "--max-time", "15",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            body = stdout.decode(errors="replace")
            import re
            ws_urls = re.findall(r'wss?://[^\s"\'<>]+', body)
            for url in set(ws_urls[:5]):
                if not any(url == r["url"] for r in results):
                    results.append({"url": url, "headers": ""})
        except asyncio.TimeoutError:
            pass
        return results

    async def _test_ws_origin_bypass(
        self, target: str, endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for ep in endpoints:
            url = ep["url"].replace("wss://", "https://").replace("ws://", "http://")
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-I",
                "-H", "Connection: Upgrade",
                "-H", "Upgrade: websocket",
                "-H", "Sec-WebSocket-Version: 13",
                "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                "-H", "Origin: https://evil.com",
                url, "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                headers = stdout.decode(errors="replace").lower()
                vulnerable = "101" in headers or "websocket" in headers
                results.append({
                    "url": ep["url"],
                    "vulnerable": vulnerable,
                    "request": "WebSocket upgrade with Origin: https://evil.com",
                    "response": headers[:1024],
                })
            except asyncio.TimeoutError:
                continue
        return results

    async def _scan_udp_game_ports(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        domain = target.lstrip("https://").lstrip("http://").split("/")[0]
        game_ports = "3478,3479,7777,7778,27015,27016,25565,19132,30120,64738,9987"
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-Pn", "--open", "-p", game_ports,
            "-oX", "-", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            import xml.etree.ElementTree as ET
            root = ET.fromstring(stdout.decode())
            game_names = {
                3478: "STUN", 3479: "TURN", 27015: "Source Engine",
                7777: "Unreal/ARK", 25565: "Minecraft",
                19132: "Bedrock", 30120: "FiveM/GTA",
                64738: "Mumble", 9987: "TeamSpeak",
            }
            for port_elem in root.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") in ("open", "open|filtered"):
                    port_id = int(port_elem.get("portid", 0))
                    name = game_names.get(port_id, "unknown")
                    results.append({
                        "title": f"Game/realtime server: {name} on UDP/{port_id}",
                        "severity": Severity.MEDIUM,
                        "description": f"Game/realtime server ({name}) on UDP port {port_id}",
                        "detail": f"Port {port_id}/udp open",
                        "tags": [name.lower().replace(" ", "-")],
                    })
        except (asyncio.TimeoutError, Exception):
            pass
        return results

    async def _check_client_validation(self, target: str) -> list[dict[str, Any]]:
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
            patterns = [
                ("localStorage.setItem", "Client-side state in localStorage"),
                ("sessionStorage.setItem", "Client-side state in sessionStorage"),
                ("score", "Client-side score tracking"),
                (".health", "Client-side health management"),
                ("inventory", "Client-side inventory management"),
            ]
            for pattern, desc in patterns:
                if pattern.lower() in body.lower():
                    results.append({
                        "title": f"Client-side validation: {desc} on {target}",
                        "severity": Severity.MEDIUM,
                        "description": f"{desc} found in page source; may be manipulable",
                    })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_rate_limits(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        has_rate_limit = False
        for _ in range(5):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-I", target, "--max-time", "3",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                headers = stdout.decode(errors="replace").lower()
                if any(h in headers for h in ("x-ratelimit", "retry-after", "x-rate-limit", "429")):
                    has_rate_limit = True
                    break
            except asyncio.TimeoutError:
                break
        if not has_rate_limit:
            results.append({
                "title": f"No rate limiting detected on {target}",
                "severity": Severity.MEDIUM,
                "description": "No rate limiting headers found; may be vulnerable to abuse/DoS",
            })
        return results

    async def _run_nuclei(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target,
            "-tags", "websocket,socketio,realtime,cors",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
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
