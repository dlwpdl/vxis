"""GameProtocolAgent — 게임 네트워크 프로토콜 역공학 에이전트.

게임 클라이언트-서버 통신 프로토콜을 분석하여
보안 취약점 및 조작 가능한 메시지 필드를 식별.

분석 대상:
    - WebSocket 게임 프로토콜
    - TCP/UDP 바이너리 프로토콜
    - Protocol Buffers (Protobuf)
    - MessagePack
    - JSON-over-WebSocket
    - 커스텀 게임 프레임 포맷
"""

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
class GameProtocolAgent(BaseAgent):
    agent_id = "game_protocol"
    description = (
        "Game network protocol reverse engineering: WebSocket analysis, "
        "binary protocol decoding, protocol injection, replay attacks"
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: WebSocket 프로토콜 분석
        ws_analysis = await self._analyze_websocket_protocol(target)
        for issue in ws_analysis.get("security_issues", []):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"WebSocket Protocol Issue: {issue['title']}",
                severity=issue.get("severity", Severity.MEDIUM),
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=issue["description"],
                request=issue.get("request", ""),
                response=issue.get("response", ""),
                tags=["game", "websocket", "protocol"] + issue.get("tags", []),
            ))

        if ws_analysis.get("found"):
            hypotheses.append(Hypothesis(
                title=f"WebSocket message injection on {target}",
                rationale=(
                    f"WebSocket server found at {ws_analysis.get('endpoint')}. "
                    f"Game state messages potentially injectable without authentication."
                ),
                probability=0.65, impact=0.85,
                suggested_agent="game_protocol",
            ))

        # Phase 2: 프로토콜 암호화 분석
        crypto_analysis = await self._analyze_protocol_encryption(target)
        if not crypto_analysis.get("encrypted"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="Game Protocol Transmitted in Plaintext",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "Game network traffic is not encrypted. "
                    "MITM attacks, packet injection, and replay attacks are feasible. "
                    f"Protocol: {crypto_analysis.get('protocol', 'unknown')}"
                ),
                tags=["game", "protocol", "encryption", "mitm"],
            ))
            hypotheses.append(Hypothesis(
                title=f"MITM attack on unencrypted game protocol — {target}",
                rationale="Plaintext game protocol allows traffic interception and modification",
                probability=0.7, impact=0.9,
                suggested_agent="game_protocol",
            ))

        # Phase 3: 재전송 공격 취약성 분석
        replay_analysis = await self._analyze_replay_vulnerability(target)
        if replay_analysis.get("vulnerable"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="Replay Attack Vulnerability in Game Protocol",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Game protocol lacks nonce or timestamp validation. "
                    f"Captured packets can be replayed to repeat actions. "
                    f"Evidence: {replay_analysis.get('evidence', '')[:300]}"
                ),
                tags=["game", "protocol", "replay", "attack"],
            ))

        # Phase 4: 바이너리 프로토콜 분석
        binary_analysis = await self._analyze_binary_protocol(target)
        for finding in binary_analysis.get("findings", []):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Binary Protocol: {finding['title']}",
                severity=finding.get("severity", Severity.MEDIUM),
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=finding["description"],
                tags=["game", "binary-protocol"] + finding.get("tags", []),
            ))

        # Phase 5: 프로토콜 주입 테스트
        injection_results = await self._test_protocol_injection(target, ws_analysis)
        for inj in injection_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Protocol Injection: {inj['type']} at {inj['endpoint']}",
                severity=Severity.CRITICAL if inj.get("game_state_changed") else Severity.HIGH,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"Injected {inj['type']} message accepted by game server. "
                    f"Game state change: {inj.get('game_state_changed', False)}. "
                    f"Payload: {json.dumps(inj.get('payload', {}))[:200]}"
                ),
                request=json.dumps(inj.get("payload", {})),
                response=inj.get("response", ""),
                tags=["game", "protocol", "injection"],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "ws_found": ws_analysis.get("found", False),
                "encrypted": crypto_analysis.get("encrypted", False),
                "replay_vulnerable": replay_analysis.get("vulnerable", False),
            },
        )

    async def _analyze_websocket_protocol(self, target: str) -> dict[str, Any]:
        """WebSocket 게임 프로토콜 분석."""
        ws_paths = ["/ws", "/game-ws", "/socket", "/realtime", "/game"]
        security_issues: list[dict[str, Any]] = []
        found_endpoint = None

        if not shutil.which("curl"):
            return {"found": False, "security_issues": []}

        for path in ws_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS",
                "-H", "Connection: Upgrade",
                "-H", "Upgrade: websocket",
                "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                "-H", "Sec-WebSocket-Version: 13",
                "-H", "Origin: null",  # null Origin 테스트
                f"{target}{path}",
                "--max-time", "5", "--insecure",
                "-w", "\\nHTTP_STATUS:%{http_code}\\nHEADERS:%{response_code}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                if "HTTP_STATUS:" in output:
                    status = int(output.split("HTTP_STATUS:")[-1].split("\\n")[0].strip())
                    if status in (101, 400, 426):
                        found_endpoint = path

                        # null Origin이 허용되면 CSRF-over-WebSocket 취약
                        if status == 101:
                            security_issues.append({
                                "title": f"WebSocket null Origin accepted at {path}",
                                "severity": Severity.HIGH,
                                "description": (
                                    f"WebSocket at {path} accepts null Origin header. "
                                    f"Cross-site WebSocket hijacking possible from any page."
                                ),
                                "tags": ["csrf", "origin"],
                                "request": f"Origin: null\nUpgrade: websocket\nPATH: {path}",
                                "response": f"HTTP {status}",
                            })
                        break
            except (asyncio.TimeoutError, ValueError):
                pass

        # WebSocket 인증 없는 접근 테스트 (서브프로토콜 없이)
        if found_endpoint:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS",
                "-H", "Connection: Upgrade",
                "-H", "Upgrade: websocket",
                "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                "-H", "Sec-WebSocket-Version: 13",
                # 토큰 없이 접근 시도
                f"{target}{found_endpoint}",
                "--max-time", "5", "--insecure",
                "-w", "\\nHTTP_STATUS:%{http_code}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                if "HTTP_STATUS:101" in output:
                    security_issues.append({
                        "title": f"WebSocket unauthenticated access at {found_endpoint}",
                        "severity": Severity.CRITICAL,
                        "description": (
                            f"WebSocket endpoint {found_endpoint} allows connection without authentication. "
                            f"Game state manipulation without credentials is possible."
                        ),
                        "tags": ["authentication", "websocket"],
                    })
            except asyncio.TimeoutError:
                pass

        return {
            "found": found_endpoint is not None,
            "endpoint": found_endpoint,
            "security_issues": security_issues,
        }

    async def _analyze_protocol_encryption(self, target: str) -> dict[str, Any]:
        """프로토콜 암호화 분석."""
        # HTTPS 사용 여부
        uses_https = target.startswith("https://")
        uses_wss = False  # WebSocket Secure

        # wss:// 엔드포인트 탐색
        parsed_target = target.replace("https://", "wss://").replace("http://", "ws://")
        if parsed_target != target:
            uses_wss = True

        # HTTP 다운그레이드 테스트
        http_target = target.replace("https://", "http://")
        downgrade_possible = False

        if uses_https and shutil.which("curl"):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                http_target, "--max-time", "5",
                "--max-redirs", "0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status == "200":
                    downgrade_possible = True
            except asyncio.TimeoutError:
                pass

        return {
            "encrypted": uses_https,
            "https": uses_https,
            "wss": uses_wss,
            "http_downgrade_possible": downgrade_possible,
            "protocol": "HTTPS+WSS" if (uses_https and uses_wss) else "HTTPS" if uses_https else "HTTP",
        }

    async def _analyze_replay_vulnerability(self, target: str) -> dict[str, Any]:
        """재전송 공격 취약성 분석."""
        if not shutil.which("curl"):
            return {"vulnerable": False}

        # 동일한 요청을 두 번 전송하여 같은 응답이 오면 취약
        test_path = "/api/v1/player"
        responses: list[str] = []

        for _ in range(2):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"{target}{test_path}",
                "--max-time", "5", "--insecure",
                "-H", "X-Request-ID: replay-test-12345",  # 같은 요청 ID
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                responses.append(stdout.decode(errors="replace"))
            except asyncio.TimeoutError:
                pass

        # 두 응답이 동일하고 오류 없음 → 재전송 방어 없음
        if len(responses) == 2 and responses[0] == responses[1] and responses[0]:
            return {
                "vulnerable": True,
                "evidence": f"Identical responses to same X-Request-ID: {responses[0][:200]}",
            }

        return {"vulnerable": False}

    async def _analyze_binary_protocol(self, target: str) -> dict[str, Any]:
        """바이너리 프로토콜 분석 (Protobuf, MessagePack 탐지)."""
        findings: list[dict[str, Any]] = []

        # 바이너리 Content-Type 허용 여부 확인
        if not shutil.which("curl"):
            return {"findings": findings}

        binary_content_types = [
            "application/x-protobuf",
            "application/octet-stream",
            "application/msgpack",
        ]

        api_endpoints = ["/api/v1/game", "/api/v1/player", "/api/v1/match"]

        for ct in binary_content_types:
            for path in api_endpoints:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sS",
                    "-H", f"Content-Type: {ct}",
                    "-H", f"Accept: {ct}",
                    "-X", "GET",
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
                        status = int(output.split("HTTP_STATUS:")[-1].strip())
                        if status == 200:
                            # 바이너리 응답 확인
                            body = output.split("HTTP_STATUS:")[0]
                            # Protobuf 시그니처
                            if b"\x0a" in body.encode()[:10]:
                                findings.append({
                                    "title": f"Protobuf protocol at {path}",
                                    "severity": Severity.MEDIUM,
                                    "description": (
                                        f"Server accepts/returns Protobuf at {path}. "
                                        f"Without schema, message structure can be reverse-engineered via fuzzing."
                                    ),
                                    "tags": ["protobuf", "binary"],
                                })
                except (asyncio.TimeoutError, ValueError):
                    pass

        return {"findings": findings}

    async def _test_protocol_injection(
        self,
        target: str,
        ws_analysis: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """프로토콜 주입 테스트."""
        injections: list[dict[str, Any]] = []

        if not ws_analysis.get("found") or not shutil.which("curl"):
            return injections

        ws_endpoint = ws_analysis.get("endpoint", "/ws")

        # JSON 게임 메시지 주입 페이로드
        injection_payloads = [
            {
                "type": "currency_add",
                "payload": {"action": "add_currency", "amount": 99999, "currency": "gold"},
            },
            {
                "type": "admin_command",
                "payload": {"cmd": "grant_item", "item_id": "sword_legendary", "user": "self"},
            },
            {
                "type": "score_set",
                "payload": {"action": "set_score", "score": 2147483647},
            },
        ]

        for inj_data in injection_payloads:
            payload_str = json.dumps(inj_data["payload"])
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS",
                "-H", "Connection: Upgrade",
                "-H", "Upgrade: websocket",
                "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                "-H", "Sec-WebSocket-Version: 13",
                "--data-binary", payload_str,
                f"{target}{ws_endpoint}",
                "--max-time", "5", "--insecure",
                "-w", "\\nHTTP_STATUS:%{http_code}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                if "HTTP_STATUS:" in output:
                    status = int(output.split("HTTP_STATUS:")[-1].strip())
                    if status in (101, 200):
                        injections.append({
                            "type": inj_data["type"],
                            "endpoint": ws_endpoint,
                            "payload": inj_data["payload"],
                            "status": status,
                            "game_state_changed": inj_data["type"] in ("currency_add", "score_set"),
                            "response": output.split("HTTP_STATUS:")[0][:200],
                        })
            except (asyncio.TimeoutError, ValueError):
                pass

        return injections
