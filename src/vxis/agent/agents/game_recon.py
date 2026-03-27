"""GameReconAgent — 게임 특화 정찰 에이전트.

게임 서버 인프라, 백엔드 API, WebSocket 엔드포인트,
CDN 구조, 게임 버전 관리 시스템을 탐색.

게임 특화 정찰 항목:
    - 게임 서버 지역별 분산 (멀티 리전)
    - 게임 클라이언트 업데이트 서버
    - 경기 서버 (게임플레이 세션)
    - 매치메이킹 서버
    - 채팅/소셜 서버
    - 결제/상점 서버
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any
from urllib.parse import urlparse

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class GameReconAgent(BaseAgent):
    agent_id = "game_recon"
    description = (
        "Game-specific reconnaissance: server infrastructure, WebSocket endpoints, "
        "game version systems, CDN structure, multiplayer backend discovery"
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: 게임 서버 타입별 엔드포인트 탐색
        server_endpoints = await self._discover_game_endpoints(target)
        for ep in server_endpoints:
            severity = Severity.HIGH if ep.get("is_admin") else Severity.MEDIUM
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Game endpoint discovered: {ep['path']} [{ep.get('type', 'unknown')}]",
                severity=severity,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"Game server endpoint {ep['path']} is accessible. "
                    f"Type: {ep.get('type', 'unknown')}, Status: {ep.get('status', 0)}"
                ),
                response=ep.get("response_preview", ""),
                tags=["game", "recon", ep.get("type", "unknown")],
            ))

            if ep.get("is_admin"):
                hypotheses.append(Hypothesis(
                    title=f"Admin panel accessible at {ep['path']} on {target}",
                    rationale=f"Admin endpoint found without authentication: {ep['path']}",
                    probability=0.7, impact=0.95,
                    suggested_agent="game_recon",
                ))

        # Phase 2: WebSocket 서버 탐색
        ws_findings = await self._discover_websocket_servers(target)
        for ws in ws_findings:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"WebSocket game server: {ws['url']}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"WebSocket endpoint discovered: {ws['url']}. "
                    f"Subprotocol: {ws.get('subprotocol', 'unknown')}"
                ),
                tags=["game", "websocket", "realtime"],
            ))
            hypotheses.append(Hypothesis(
                title=f"WebSocket protocol manipulation on {ws['url']}",
                rationale="WebSocket game server accessible — protocol injection and state manipulation possible",
                probability=0.6, impact=0.8,
                suggested_agent="game_protocol",
            ))

        # Phase 3: 게임 버전/업데이트 서버 탐색
        version_info = await self._check_version_endpoints(target)
        if version_info.get("found"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Game version endpoint exposed: {version_info.get('endpoint')}",
                severity=Severity.LOW,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"Version info at {version_info.get('endpoint')}: "
                    f"v{version_info.get('version', 'unknown')}"
                ),
                response=json.dumps(version_info.get("data", {}))[:500],
                tags=["game", "version", "update-server"],
            ))

        # Phase 4: CDN + 에셋 서버 구조 탐색
        cdn_info = await self._discover_cdn_structure(target)
        for cdn_ep in cdn_info:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Game CDN/asset server: {cdn_ep['url']}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=f"Game CDN endpoint: {cdn_ep['url']} ({cdn_ep.get('type', 'assets')})",
                tags=["game", "cdn", "assets"],
            ))

        # Phase 5: 개발자 디버그 엔드포인트 탐색
        debug_eps = await self._find_debug_endpoints(target)
        for dbg in debug_eps:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Debug endpoint exposed: {dbg['path']}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Development/debug endpoint accessible: {dbg['path']}. "
                    f"Status: {dbg.get('status')}. "
                    f"May expose game internals, debug commands, or admin functions."
                ),
                response=dbg.get("preview", ""),
                tags=["game", "debug", "misconfiguration"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Debug command execution via {dbg['path']}",
                rationale=f"Debug endpoint {dbg['path']} accessible — may allow arbitrary game state modification",
                probability=0.65, impact=0.85,
                suggested_agent="game_economy",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "endpoints_found": len(server_endpoints),
                "ws_servers": len(ws_findings),
                "debug_endpoints": len(debug_eps),
            },
        )

    async def _discover_game_endpoints(self, target: str) -> list[dict[str, Any]]:
        """게임 특화 엔드포인트 탐색."""
        if not shutil.which("curl"):
            return []

        game_paths = [
            # 플레이어 API
            ("/api/v1/player", "player"),
            ("/api/v1/profile", "player"),
            ("/api/v1/account", "player"),
            # 경제
            ("/api/v1/shop", "economy"),
            ("/api/v1/store", "economy"),
            ("/api/v1/inventory", "economy"),
            ("/api/v1/currency", "economy"),
            # 매치메이킹
            ("/api/v1/match", "matchmaking"),
            ("/api/v1/matchmaking", "matchmaking"),
            ("/api/v1/lobby", "matchmaking"),
            # 리더보드
            ("/api/v1/leaderboard", "leaderboard"),
            ("/api/v1/rankings", "leaderboard"),
            ("/api/v1/scores", "leaderboard"),
            # 관리자 (중요)
            ("/api/admin", "admin"),
            ("/admin", "admin"),
            ("/api/internal", "admin"),
            ("/debug", "debug"),
            ("/api/v1/admin", "admin"),
            # 소셜
            ("/api/v1/guild", "social"),
            ("/api/v1/friends", "social"),
            ("/api/v1/chat", "social"),
        ]

        results: list[dict[str, Any]] = []

        async def probe(path: str, path_type: str) -> dict[str, Any] | None:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w",
                "%{http_code}|%{content_type}",
                f"{target}{path}", "--max-time", "5",
                "-L", "--insecure",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                parts = stdout.decode().strip().split("|")
                status_code = int(parts[0]) if parts[0].isdigit() else 0
                if 0 < status_code < 404:
                    return {
                        "path": path,
                        "type": path_type,
                        "status": status_code,
                        "content_type": parts[1] if len(parts) > 1 else "",
                        "is_admin": path_type in ("admin", "debug"),
                    }
            except (asyncio.TimeoutError, ValueError):
                pass
            return None

        tasks = [probe(path, ptype) for path, ptype in game_paths]
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in probe_results:
            if isinstance(result, dict) and result is not None:
                results.append(result)

        return results

    async def _discover_websocket_servers(self, target: str) -> list[dict[str, Any]]:
        """WebSocket 게임 서버 탐색."""
        if not shutil.which("curl"):
            return []

        ws_paths = ["/ws", "/game-ws", "/socket", "/realtime", "/live", "/game", "/socket.io/"]
        results: list[dict[str, Any]] = []

        for path in ws_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS",
                "-H", "Connection: Upgrade",
                "-H", "Upgrade: websocket",
                "-H", "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==",
                "-H", "Sec-WebSocket-Version: 13",
                "-w", "\\nHTTP_STATUS:%{http_code}",
                f"{target}{path}", "--max-time", "5", "--insecure",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode()
                if "HTTP_STATUS:" in output:
                    status = int(output.split("HTTP_STATUS:")[-1].strip())
                    if status in (101, 400, 426):  # 101=WebSocket OK, 400/426=needs WS upgrade
                        ws_url = target.replace("https://", "wss://").replace("http://", "ws://") + path
                        results.append({
                            "url": ws_url,
                            "http_status": status,
                            "subprotocol": "unknown",
                        })
            except (asyncio.TimeoutError, ValueError):
                pass

        return results

    async def _check_version_endpoints(self, target: str) -> dict[str, Any]:
        """게임 버전/업데이트 서버 엔드포인트 확인."""
        if not shutil.which("curl"):
            return {"found": False}

        version_paths = [
            "/api/v1/version", "/version", "/api/version",
            "/api/v1/config", "/config.json", "/manifest.json",
            "/api/v1/build", "/build-info",
        ]

        for path in version_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"{target}{path}",
                "--max-time", "5", "--insecure",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                body = stdout.decode(errors="replace")
                try:
                    data = json.loads(body)
                    version_keys = ["version", "build", "client_version", "app_version"]
                    for key in version_keys:
                        if key in data:
                            return {
                                "found": True,
                                "endpoint": path,
                                "version": str(data[key])[:20],
                                "data": {k: str(v)[:50] for k, v in data.items() if isinstance(v, (str, int, float))},
                            }
                except json.JSONDecodeError:
                    # 버전 번호 패턴 탐색
                    ver_match = re.search(r"(\d+\.\d+\.\d+[\.\d]*)", body)
                    if ver_match:
                        return {
                            "found": True,
                            "endpoint": path,
                            "version": ver_match.group(1),
                            "data": {},
                        }
            except asyncio.TimeoutError:
                pass

        return {"found": False}

    async def _discover_cdn_structure(self, target: str) -> list[dict[str, Any]]:
        """게임 CDN + 에셋 서버 구조 탐색."""
        if not shutil.which("curl"):
            return []

        parsed = urlparse(target)
        base_domain = parsed.netloc
        root_domain = ".".join(base_domain.split(".")[-2:])

        cdn_subdomains = [
            f"cdn.{root_domain}", f"assets.{root_domain}",
            f"static.{root_domain}", f"dl.{root_domain}",
            f"download.{root_domain}", f"patch.{root_domain}",
            f"update.{root_domain}",
        ]

        results: list[dict[str, Any]] = []
        for cdn_url in cdn_subdomains:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"https://{cdn_url}", "--max-time", "5", "--insecure",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status.isdigit() and int(status) < 404:
                    results.append({
                        "url": f"https://{cdn_url}",
                        "status": int(status),
                        "type": "cdn_assets",
                    })
            except asyncio.TimeoutError:
                pass

        return results

    async def _find_debug_endpoints(self, target: str) -> list[dict[str, Any]]:
        """개발자 디버그 엔드포인트 탐색."""
        if not shutil.which("curl"):
            return []

        debug_paths = [
            "/debug", "/dev", "/test", "/api/debug",
            "/api/test", "/api/internal/debug",
            "/metrics", "/healthz", "/health", "/status",
            "/actuator", "/actuator/env", "/actuator/beans",
            "/.env", "/config.yaml", "/config.yml",
            "/server-status", "/phpinfo.php",
        ]

        results: list[dict[str, Any]] = []
        for path in debug_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS",
                f"{target}{path}",
                "--max-time", "5", "--insecure",
                "-w", "\\nHTTP_STATUS:%{http_code}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                if "HTTP_STATUS:" in output:
                    parts = output.rsplit("HTTP_STATUS:", 1)
                    body = parts[0]
                    status = int(parts[1].strip()) if parts[1].strip().isdigit() else 0
                    if 200 <= status < 400:
                        results.append({
                            "path": path,
                            "status": status,
                            "preview": body[:300],
                        })
            except (asyncio.TimeoutError, ValueError):
                pass

        return results
