"""GamePipeline — 16 Phase 게임 보안 분석 파이프라인.

게임 클라이언트, 서버, 경제, 메모리, 프로토콜 등 게임 특화 보안 분석.
ScanPipeline과 동일한 패턴을 따름 (Phase async 메서드 + GameScanContext 공유).

Architecture:
    ┌───────────────────────────────────────────────────────────┐
    │                 GamePipeline.run(target)                   │
    │                                                           │
    │  Foundation:                                              │
    │    P0 Foundation → P1 Recon → P2 Protocol Fingerprint     │
    │                                                           │
    │  Traffic Analysis:                                        │
    │    P3 Network Intercept → P4 Protocol Reverse             │
    │                                                           │
    │  API & Auth:                                              │
    │    P5 API Testing → P6 Auth & Session                     │
    │                                                           │
    │  Game Economy:                                            │
    │    P7 Economy Analysis → P8 Economy Exploit               │
    │                                                           │
    │  Game Mechanics:                                          │
    │    P9 Leaderboard & Matchmaking                           │
    │                                                           │
    │  Client Analysis:                                         │
    │    P10 Client Analysis → P11 Memory Scan                  │
    │                                                           │
    │  Defense & Social:                                        │
    │    P12 Anti-Cheat Assessment → P13 Social & Chat          │
    │                                                           │
    │  DRM & Output:                                            │
    │    P14 DRM & License → P15 Report                         │
    └───────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Callable, Awaitable

from vxis.pipeline.game_context import GameScanContext

logger = logging.getLogger(__name__)


class GamePipeline:
    """16 Phase 게임 보안 분석 파이프라인.

    Usage:
        pipeline = GamePipeline(brain=brain_instance)
        ctx = await pipeline.run(
            target="https://game.example.com",
            client_binary="/path/to/game.exe",
            game_type="desktop",
        )
    """

    def __init__(
        self,
        brain: Any,
        config: Any | None = None,
        enable_deferred_approval: bool = True,
        approval_callback: Callable[[list[Any]], Awaitable[list[bool]]] | None = None,
    ) -> None:
        self.brain = brain
        self.config = config
        self.enable_deferred_approval = enable_deferred_approval
        self._approval_callback = approval_callback

    async def run(
        self,
        target: str,
        client_binary: str = "",
        game_type: str = "unknown",
        game_title: str = "",
        app_context_en: str = "",
        app_context_ko: str = "",
    ) -> GameScanContext:
        """전체 16 Phase 게임 파이프라인 실행.

        Args:
            target: 게임 서버 베이스 URL (e.g., "https://game.example.com").
            client_binary: 게임 클라이언트 바이너리 경로 (데스크탑/모바일 타깃).
            game_type: "web" | "desktop" | "mobile" | "console" | "unknown".
            game_title: 게임 타이틀 (리포트에 사용).
            app_context_en: 앱 컨텍스트 영문.
            app_context_ko: 앱 컨텍스트 한국어.
        """
        ctx = GameScanContext(
            target=target,
            app_context_en=app_context_en or f"Game security assessment: {game_title or target}",
            app_context_ko=app_context_ko or f"게임 보안 분석: {game_title or target}",
            scan_id=f"VXIS-GAME-{time.strftime('%Y%m%d-%H%M%S')}",
            client_binary=client_binary,
            game_type=game_type,
            game_title=game_title,
        )

        logger.info("=" * 70)
        logger.info("  VXIS GamePipeline — 16 Phase Game Security Assessment")
        logger.info("  Target:  %s", target)
        logger.info("  Scan ID: %s", ctx.scan_id)
        logger.info("  Type:    %s | Binary: %s", game_type, client_binary or "N/A")
        logger.info("  Brain:   %s", type(self.brain).__name__)
        logger.info("=" * 70)

        # ── Phase 실행 ──────────────────────────────────────────────
        await self._run_phase("Phase 0: Foundation — Config & Game Type Detection", self._phase0_foundation, ctx)
        await self._run_phase("Phase 1: Recon — Backend API & Server Endpoint Discovery", self._phase1_recon, ctx)
        await self._run_phase("Phase 2: Protocol Fingerprint — Transport Layer Identification", self._phase2_protocol_fingerprint, ctx)
        await self._run_phase("Phase 3: Network Intercept — X-Ray Traffic Capture", self._phase3_network_intercept, ctx)
        await self._run_phase("Phase 4: Protocol Reverse — Binary Protocol Decoding", self._phase4_protocol_reverse, ctx)
        await self._run_phase("Phase 5: API Testing — Web API Security Assessment", self._phase5_api_testing, ctx)
        await self._run_phase("Phase 6: Auth & Session — Authentication & Session Analysis", self._phase6_auth_session, ctx)
        await self._run_phase("Phase 7: Economy Analysis — Virtual Economy Mapping", self._phase7_economy_analysis, ctx)
        await self._run_phase("Phase 8: Economy Exploit — Manipulation & Race Conditions", self._phase8_economy_exploit, ctx)
        await self._run_phase("Phase 9: Leaderboard & Matchmaking — Score & Rank Manipulation", self._phase9_leaderboard_matchmaking, ctx)
        await self._run_phase("Phase 10: Client Analysis — Binary RE & String Extraction", self._phase10_client_analysis, ctx)
        await self._run_phase("Phase 11: Memory Scan — FridaBridge Runtime Analysis", self._phase11_memory_scan, ctx)
        await self._run_phase("Phase 12: Anti-Cheat Assessment — Detection Effectiveness", self._phase12_anti_cheat, ctx)
        await self._run_phase("Phase 13: Social & Chat — Injection & Phishing Vectors", self._phase13_social_chat, ctx)
        await self._run_phase("Phase 14: DRM & License — Bypass Assessment", self._phase14_drm_license, ctx)

        # Deferred Actions 처리
        if ctx.deferred_actions and self.enable_deferred_approval:
            await self._execute_deferred_actions(ctx)

        await self._run_phase("Phase 15: Report — NCC-Style Game Security Report", self._phase15_report, ctx)

        # ── 완료 로그 ────────────────────────────────────────────────
        c = sum(1 for f in ctx.findings if f.severity.value == "critical")
        h = sum(1 for f in ctx.findings if f.severity.value == "high")
        m = sum(1 for f in ctx.findings if f.severity.value == "medium")

        logger.info("\n" + "=" * 70)
        logger.info("  GAME PIPELINE COMPLETE")
        logger.info("  Phases:         %d/16", len(ctx.phases_completed))
        logger.info("  Findings:       %d (C:%d H:%d M:%d)", len(ctx.findings), c, h, m)
        logger.info("  Game Issues:    %d", len(ctx.game_logic_findings))
        logger.info("  Protocols:      %d identified", len(ctx.protocols))
        logger.info("  Packets:        %d captured", len(ctx.captured_packets))
        logger.info("  Duration:       %.1fs", ctx.duration_seconds)
        logger.info("=" * 70)

        return ctx

    # ── Phase Runner ──────────────────────────────────────────────

    async def _run_phase(
        self,
        name: str,
        func: Callable[[GameScanContext], Awaitable[None]],
        ctx: GameScanContext,
    ) -> None:
        """Phase 실행 + 자동 로깅/타이밍."""
        logger.info("\n[%s]", name)
        t0 = time.monotonic()
        pre_count = len(ctx.findings)
        try:
            await func(ctx)
        except Exception as exc:
            logger.warning("  %s failed: %s (continuing)", name, exc)
        elapsed = (time.monotonic() - t0) * 1000
        new_findings = len(ctx.findings) - pre_count
        ctx.log_phase(name, duration_ms=elapsed, findings_count=new_findings)

    # ── Deferred Action Approval ──────────────────────────────────

    async def _execute_deferred_actions(self, ctx: GameScanContext) -> None:
        """경제 조작 등 데이터 변조 작업 승인 + 실행."""
        logger.info("\n" + "=" * 70)
        logger.info("  DEFERRED ACTIONS — 게임 경제 조작 테스트 승인 요청")
        logger.info("  %d건의 쓰기 작업에 대해 승인이 필요합니다.", len(ctx.deferred_actions))
        logger.info("=" * 70)

        if self._approval_callback:
            approvals = await self._approval_callback(ctx.deferred_actions)
            for action, approved in zip(ctx.deferred_actions, approvals):
                action.approved = approved
        else:
            for action in ctx.deferred_actions:
                risk_icon = {"low": "[LOW]", "medium": "[MED]", "high": "[HIGH]"}.get(action.risk, "[?]")
                print(f"\n  {risk_icon} #{action.id} {action.method} {action.url}")
                print(f"     EN: {action.description_en}")
                print(f"     KO: {action.description_ko}")
                try:
                    answer = input("     Approve? (y/N): ").strip().lower()
                    action.approved = answer in ("y", "yes")
                except EOFError:
                    action.approved = False
                print(f"     -> {'APPROVED' if action.approved else 'DENIED'}")

        approved_count = sum(1 for a in ctx.deferred_actions if a.approved)
        logger.info("\n  Approved: %d / %d", approved_count, len(ctx.deferred_actions))

        if approved_count > 0:
            from vxis.interaction.hands import SessionManager
            mgr = SessionManager()
            for action in ctx.deferred_actions:
                if not action.approved:
                    continue
                try:
                    session = await mgr.get_session(ctx.target)
                    path = "/" + action.url.split("/", 3)[-1] if "://" in action.url else action.url
                    if action.method in ("POST", "PATCH", "PUT"):
                        r = await session.request(action.method, path, json_data=action.data)
                    elif action.method == "DELETE":
                        r = await session.request("DELETE", path)
                    else:
                        continue
                    action.executed = True
                    action.result = f"{r.status} | {r.text[:200]}"
                    logger.info("  Executed #%d: %s %s -> %d", action.id, action.method, action.url, r.status)
                except Exception as exc:
                    action.result = f"ERROR: {exc}"
                    logger.warning("  Failed #%d: %s", action.id, exc)
            await mgr.close_all()

    # ══════════════════════════════════════════════════════════════
    # Phase Implementations
    # ══════════════════════════════════════════════════════════════

    async def _phase0_foundation(self, ctx: GameScanContext) -> None:
        """Phase 0: Config 초기화 + 게임 타입 자동 탐지."""
        from vxis.config.schema import VXISConfig
        if self.config is None:
            try:
                self.config = VXISConfig()
            except Exception:
                pass

        # 타깃 URL에서 게임 타입 추론
        if ctx.game_type == "unknown":
            target_lower = ctx.target.lower()
            if any(k in target_lower for k in [".apk", "android", "play.google"]):
                ctx.game_type = "mobile"
                ctx.game_platform = "android"
            elif any(k in target_lower for k in [".ipa", "itunes", "apps.apple"]):
                ctx.game_type = "mobile"
                ctx.game_platform = "ios"
            elif ctx.client_binary:
                ctx.game_type = "desktop"
                ctx.game_platform = "windows" if ctx.client_binary.endswith(".exe") else "macos"
            else:
                ctx.game_type = "web"

        logger.info("  Game type: %s | Platform: %s", ctx.game_type, ctx.game_platform)
        logger.info("  Target: %s", ctx.target)
        logger.info("  Client binary: %s", ctx.client_binary or "N/A")

    async def _phase1_recon(self, ctx: GameScanContext) -> None:
        """Phase 1: 백엔드 API 탐색 + 게임 서버 엔드포인트 열거."""
        from vxis.interaction.hands import SessionManager
        from urllib.parse import urlparse

        mgr = SessionManager()
        try:
            session = await mgr.get_session(ctx.target)

            # 루트 페이지 수집 + 보안 헤더 체크
            resp = await session.get("/")
            ctx.tech_stack = []

            # 서버 기술 스택 탐지
            server_header = resp.headers.get("server", "")
            powered_by = resp.headers.get("x-powered-by", "")
            if server_header:
                ctx.tech_stack.append(server_header)
            if powered_by:
                ctx.tech_stack.append(powered_by)

            # 게임 전용 엔드포인트 목록
            game_api_paths = [
                # 공통 게임 API
                "/api/v1/game", "/api/v2/game", "/api/game",
                "/game/api", "/v1/game",
                # 인증
                "/api/auth/login", "/api/auth/register", "/api/auth/token",
                "/api/v1/auth", "/login", "/register",
                # 플레이어
                "/api/v1/player", "/api/v1/profile", "/api/player/info",
                "/api/v1/user", "/api/v1/me",
                # 경제
                "/api/v1/store", "/api/v1/shop", "/api/v1/purchase",
                "/api/v1/currency", "/api/v1/inventory", "/api/v1/items",
                "/api/v1/wallet", "/api/v1/transactions",
                # 게임 메카닉
                "/api/v1/match", "/api/v1/matchmaking", "/api/v1/ranking",
                "/api/v1/leaderboard", "/api/v1/scores",
                "/api/v1/quests", "/api/v1/achievements",
                "/api/v1/guild", "/api/v1/clan", "/api/v1/friends",
                # 채팅
                "/api/v1/chat", "/api/v1/messages",
                # 관리자
                "/api/admin", "/admin", "/api/internal",
                # WebSocket
                "/ws", "/game-ws", "/socket.io", "/ws/game",
                # 그래픽 / 에셋
                "/api/v1/assets", "/cdn",
            ]

            # 엔드포인트 탐색 (병렬)
            async def probe_path(path: str) -> dict[str, Any] | None:
                try:
                    r = await session.get(path)
                    if r.status < 404:
                        return {
                            "path": path,
                            "status": r.status,
                            "content_type": r.headers.get("content-type", ""),
                            "source": "recon",
                        }
                except Exception:
                    pass
                return None

            tasks = [probe_path(p) for p in game_api_paths]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, dict) and result is not None:
                    ctx.api_endpoints.append(result)
                    logger.debug("  Found: %s -> %d", result["path"], result["status"])

            # WebSocket 엔드포인트 탐지
            ws_paths = ["/ws", "/game-ws", "/socket.io/", "/ws/game", "/realtime"]
            for path in ws_paths:
                try:
                    r = await session.get(path)
                    if r.status in (101, 200, 400, 426):  # 101=Switching Protocols, 426=Upgrade Required
                        ws_url = ctx.target.replace("https://", "wss://").replace("http://", "ws://") + path
                        ctx.add_server_endpoint(ws_url, "websocket", "unknown")
                        logger.info("  WebSocket endpoint: %s (HTTP %d)", ws_url, r.status)
                except Exception:
                    pass

            # JS 번들에서 엔드포인트 추출
            js_urls = re.findall(r'src="(/[^"]+\.js)"', resp.text)
            for js_url in js_urls[:5]:  # 최대 5개
                try:
                    jr = await session.get(js_url)
                    # API 경로 추출
                    for m in re.finditer(r'["\'`](/(?:api|v\d+)/[^\s"\'`<>?#]{3,60})["\'`]', jr.text):
                        ep = m.group(1)
                        if ep not in [e.get("path", "") for e in ctx.api_endpoints]:
                            ctx.api_endpoints.append({"path": ep, "source": "js_bundle"})

                    # WebSocket URL 추출
                    for m in re.finditer(r'["\'`](wss?://[^\s"\'`]{5,100})["\'`]', jr.text):
                        ws_url = m.group(1)
                        ctx.add_server_endpoint(ws_url, "websocket", "unknown")

                    # 하드코딩된 시크릿 탐지
                    secret_patterns = [
                        (r'["\'`]((?:sk-|pk-|api[_-]?key|secret)[^\s"\'`]{10,})["\'`]', "api_key"),
                        (r'["\']([A-Za-z0-9+/]{40,}={0,2})["\']', "base64_secret"),
                        (r'password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', "hardcoded_password"),
                    ]
                    for pattern, secret_type in secret_patterns:
                        for sm in re.finditer(pattern, jr.text, re.I):
                            val = sm.group(1)
                            if len(val) > 8:
                                ctx.hardcoded_credentials.append({
                                    "type": secret_type,
                                    "value": val[:30] + "...",
                                    "source": js_url,
                                })
                                ctx.add_finding(
                                    title=f"Hardcoded {secret_type} in Game JS Bundle|||게임 JS 번들에 {secret_type} 노출",
                                    severity="critical",
                                    finding_type="sensitive_data_exposure",
                                    description=f"Credential in {js_url}: {val[:30]}...|||{js_url}에서 크리덴셜 발견: {val[:30]}...",
                                    target=ctx.target,
                                    affected_component=js_url,
                                    source_plugin="game-pipeline-phase1",
                                )
                except Exception:
                    pass

            # 서브도메인 열거
            base_domain = urlparse(ctx.target).netloc
            root_domain = ".".join(base_domain.split(".")[-2:])

            game_subdomains = [
                "api", "game", "play", "ws", "socket",
                "auth", "login", "store", "shop", "cdn",
                "assets", "static", "admin", "internal",
                "matchmaking", "lobby", "chat", "analytics",
            ]

            for sub in game_subdomains:
                fqdn = f"{sub}.{root_domain}"
                try:
                    sub_session = await mgr.get_session(f"https://{fqdn}")
                    sr = await sub_session.get("/")
                    ctx.subdomains.append({
                        "fqdn": fqdn, "status": sr.status, "live": True,
                        "headers": dict(sr.headers),
                    })
                    ctx.game_server_ips.append(fqdn)
                    logger.info("  [LIVE SUBDOMAIN] %s -> %d", fqdn, sr.status)
                except Exception:
                    pass

            logger.info(
                "  Recon complete: %d endpoints, %d subdomains, %d ws-endpoints",
                len(ctx.api_endpoints), len(ctx.subdomains), len(ctx.server_endpoints),
            )

            # 보안 헤더 체크
            sec_headers = [
                "strict-transport-security", "content-security-policy",
                "x-frame-options", "x-content-type-options",
            ]
            missing = [h for h in sec_headers if h not in resp.headers]
            if missing:
                ctx.add_finding(
                    title=f"Missing Security Headers ({len(missing)}/{len(sec_headers)})|||보안 헤더 누락 ({len(missing)}/{len(sec_headers)})",
                    severity="medium",
                    finding_type="security_misconfiguration",
                    description=f"Missing: {', '.join(missing)}|||누락된 헤더: {', '.join(missing)}",
                    target=ctx.target,
                    source_plugin="game-pipeline-phase1",
                )

        finally:
            await mgr.close_all()

    async def _phase2_protocol_fingerprint(self, ctx: GameScanContext) -> None:
        """Phase 2: 네트워크 프로토콜 식별 (HTTP/WS/TCP/UDP 커스텀)."""
        import socket

        # WebSocket 엔드포인트에서 서브프로토콜 탐지
        for endpoint in ctx.server_endpoints:
            if endpoint.get("type") == "websocket":
                url = endpoint["url"]
                logger.info("  Probing WebSocket: %s", url)

                # 일반적인 게임 WebSocket 서브프로토콜
                common_subprotocols = [
                    "game", "game-v1", "game-v2",
                    "protobuf", "msgpack", "json",
                    "binary", "text",
                ]
                endpoint["probed_subprotocols"] = common_subprotocols

        # TCP/UDP 포트 스캔 (일반 게임 포트)
        from urllib.parse import urlparse
        parsed = urlparse(ctx.target)
        host = parsed.hostname or ctx.target.split("//")[-1].split("/")[0]

        game_ports = {
            7777: ("tcp", "Unity/Unreal default"),
            7778: ("tcp", "Unity multiplayer"),
            8080: ("tcp", "HTTP alternate"),
            8443: ("tcp", "HTTPS alternate"),
            9001: ("tcp", "Nakama / game server"),
            9090: ("tcp", "Game admin"),
            27015: ("udp", "Source engine / Steam"),
            27016: ("udp", "Source engine alternate"),
            3074: ("udp", "Xbox Live"),
            3478: ("udp", "STUN/NAT traversal"),
            4380: ("udp", "Steam P2P"),
            25565: ("tcp", "Minecraft"),
        }

        open_ports: list[dict[str, Any]] = []
        for port, (transport, desc) in game_ports.items():
            sock_type = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
            try:
                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, sock_type)
                sock.settimeout(1)
                result = await loop.run_in_executor(None, lambda s=sock, h=host, p=port: s.connect_ex((h, p)))
                sock.close()
                if result == 0:
                    open_ports.append({
                        "port": port,
                        "transport": transport,
                        "description": desc,
                        "open": True,
                    })
                    logger.info("  [OPEN] %s:%d/%s — %s", host, port, transport, desc)

                    protocol_entry = {
                        "port": port,
                        "transport": transport,
                        "description": desc,
                        "identified": False,
                        "name": "unknown",
                    }
                    ctx.protocols.append(protocol_entry)
            except Exception:
                pass

        # 게임 엔진 탐지 (HTTP 헤더/응답 분석)
        engine_signatures: dict[str, list[str]] = {
            "unity": ["Unity", "UnityWebRequest", "UnityPlayer", "_unity_"],
            "unreal": ["Unreal", "UE4", "UE5", "UnrealEngine"],
            "godot": ["Godot", "GodotEngine"],
            "cocos": ["Cocos2D", "CocosCreator", "cocos-js"],
        }

        from vxis.interaction.hands import SessionManager
        mgr = SessionManager()
        try:
            session = await mgr.get_session(ctx.target)
            resp = await session.get("/")
            body = resp.text[:5000]
            combined = body + str(dict(resp.headers))

            for engine, sigs in engine_signatures.items():
                if any(sig.lower() in combined.lower() for sig in sigs):
                    ctx.game_engine = engine
                    logger.info("  Game engine identified: %s", engine)
                    break
        except Exception:
            pass
        finally:
            await mgr.close_all()

        if open_ports:
            ctx.add_finding(
                title=f"Game Server Ports Exposed ({len(open_ports)} open)|||게임 서버 포트 노출 ({len(open_ports)}개)",
                severity="informational",
                finding_type="information_disclosure",
                description=f"Open ports: {[p['port'] for p in open_ports]}|||열린 포트: {[p['port'] for p in open_ports]}",
                target=ctx.target,
                source_plugin="game-pipeline-phase2",
            )

        logger.info(
            "  Protocol fingerprint: engine=%s, open_ports=%d, ws_endpoints=%d",
            ctx.game_engine, len(open_ports), len(ctx.server_endpoints),
        )

    async def _phase3_network_intercept(self, ctx: GameScanContext) -> None:
        """Phase 3: X-Ray 트래픽 캡처 + 프로토콜 분석."""
        from vxis.interaction.xray import FlowAnalyzer, MitmProxyManager
        from vxis.interaction.hands import SessionManager

        analyzer = FlowAnalyzer()

        # mitmproxy가 있으면 사용
        if MitmProxyManager.is_available():
            mgr_proxy = MitmProxyManager(port=8082)
            try:
                proxy_url = await mgr_proxy.start()
                logger.info("  mitmproxy started at %s", proxy_url)

                # 게임 API 엔드포인트를 프록시를 통해 탐색
                session_mgr = SessionManager()
                session = await session_mgr.get_session(ctx.target)

                for endpoint in ctx.api_endpoints[:20]:
                    try:
                        path = endpoint.get("path", "")
                        if path:
                            await session.get(path)
                    except Exception:
                        pass

                await session_mgr.close_all()
                flows = mgr_proxy.get_captured_flows(analyzer)
                ctx.xray_flows = len(flows)
                logger.info("  Captured %d flows via mitmproxy", len(flows))

                await mgr_proxy.stop()
            except Exception as exc:
                logger.info("  mitmproxy intercept failed: %s", exc)
        else:
            logger.info("  mitmproxy not available — using passive FlowAnalyzer")

        # 패시브 분석: 알려진 엔드포인트 직접 프로브
        session_mgr = SessionManager()
        try:
            session = await session_mgr.get_session(ctx.target)

            # 중요 API 엔드포인트 직접 호출 + 플로우 수집
            analysis_targets = [
                e["path"] for e in ctx.api_endpoints
                if any(k in e.get("path", "").lower() for k in
                       ["auth", "login", "token", "currency", "shop", "purchase", "player", "rank"])
            ][:15]

            for path in analysis_targets:
                try:
                    flow = analyzer.create_flow_from_request("GET", ctx.target + path, {})
                    resp = await session.get(path)
                    analyzer.update_flow_response(
                        flow,
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=resp.text,
                    )
                    analyzer.add_flow(flow)
                except Exception:
                    pass

        finally:
            await session_mgr.close_all()

        # 트래픽 분석 요약
        summary = analyzer.get_summary()
        ctx.xray_flows = summary.total_flows

        # 취약점 발견
        for vuln in summary.vulnerabilities:
            ctx.add_finding(
                title=f"Traffic Analysis: {vuln['type']}|||트래픽 분석: {vuln['type']}",
                severity="medium",
                finding_type="traffic_analysis",
                description=f"Detected in traffic: {vuln['type']} at {vuln['url']}|||트래픽에서 탐지: {vuln['type']} ({vuln['url']})",
                target=ctx.target,
                affected_component=vuln["url"],
                source_plugin="game-pipeline-phase3",
            )

        # 인증 토큰 수집
        for token_info in summary.auth_tokens_found:
            ctx.game_auth_tokens.append(token_info)

        logger.info(
            "  Traffic intercept: %d flows, %d vulns, %d auth tokens",
            summary.total_flows,
            len(summary.vulnerabilities),
            len(summary.auth_tokens_found),
        )

    async def _phase4_protocol_reverse(self, ctx: GameScanContext) -> None:
        """Phase 4: 바이너리 프로토콜 디코딩 + 메시지 타입 식별."""
        if not ctx.protocols:
            logger.info("  No protocols to reverse-engineer")
            return

        # Protobuf 탐지
        for protocol in ctx.protocols:
            port = protocol.get("port", 0)
            protocol.get("description", "")

            # 일반적인 게임 프로토콜 서명으로 식별
            protocol_signatures: dict[str, dict[str, Any]] = {
                "protobuf": {
                    "ports": [9001, 9090, 8080],
                    "magic_bytes": b"\x0a",
                    "description": "Protocol Buffers (Google)",
                },
                "msgpack": {
                    "ports": [8080, 9000],
                    "magic_bytes": b"\x92\x93\x94",
                    "description": "MessagePack binary serialization",
                },
                "flatbuffers": {
                    "ports": [7777, 9001],
                    "magic_bytes": b"\x04\x00\x00\x00",
                    "description": "FlatBuffers serialization",
                },
                "nakama": {
                    "ports": [7349, 7350, 443],
                    "description": "Nakama game server protocol",
                },
            }

            for proto_name, sig in protocol_signatures.items():
                if port in sig.get("ports", []):
                    protocol["name"] = proto_name
                    protocol["identified"] = True
                    protocol["schema_hint"] = sig.get("description", "")
                    ctx.protocol_schemas[proto_name] = {
                        "port": port,
                        "description": sig.get("description", ""),
                    }
                    logger.info("  Protocol identified: %s on port %d", proto_name, port)
                    break

        # 커스텀 바이너리 프로토콜 탐지 힌트
        unknown_protocols = [p for p in ctx.protocols if not p.get("identified")]
        if unknown_protocols:
            ctx.add_finding(
                title=f"Unknown Binary Protocols Detected ({len(unknown_protocols)})|||미식별 바이너리 프로토콜 탐지 ({len(unknown_protocols)}개)",
                severity="medium",
                finding_type="protocol_analysis",
                description=(
                    f"Custom binary protocols on ports: {[p['port'] for p in unknown_protocols]}. "
                    f"Reverse engineering required.|||"
                    f"포트 {[p['port'] for p in unknown_protocols]}에서 커스텀 바이너리 프로토콜 탐지. 역공학 필요."
                ),
                target=ctx.target,
                source_plugin="game-pipeline-phase4",
            )

        # Brain으로 프로토콜 분석
        if ctx.captured_packets and hasattr(self.brain, "query"):
            packet_samples = ctx.captured_packets[:3]
            prompt = (
                f"Analyze these game network packets and identify the protocol:\n"
                f"{packet_samples}\n"
                f"Identify: 1) Protocol type 2) Message structure 3) Security issues"
            )
            try:
                analysis = await self.brain.query(prompt)
                ctx.protocol_schemas["brain_analysis"] = {"analysis": analysis[:500]}
                logger.info("  Brain protocol analysis complete")
            except Exception as exc:
                logger.debug("  Brain protocol analysis failed: %s", exc)

        logger.info(
            "  Protocol reverse: %d identified, %d unknown",
            len([p for p in ctx.protocols if p.get("identified")]),
            len(unknown_protocols),
        )

    async def _phase5_api_testing(self, ctx: GameScanContext) -> None:
        """Phase 5: 표준 웹 API 보안 테스트 (OWASP Top 10 + 게임 특화)."""
        from vxis.interaction.hands import SessionManager

        mgr = SessionManager()
        try:
            session = await mgr.get_session(ctx.target)

            # 1. IDOR 테스트 (게임 플레이어 ID)
            idor_paths = [
                "/api/v1/player/1", "/api/v1/player/2",
                "/api/v1/user/1", "/api/v1/user/2",
                "/api/v1/profile/1", "/api/v1/profile/2",
                "/api/v1/inventory/1", "/api/v1/wallet/1",
            ]
            for path in idor_paths:
                try:
                    r = await session.get(path)
                    if r.status == 200:
                        import json as json_lib
                        try:
                            data = json_lib.loads(r.text)
                            if any(k in data for k in ["username", "email", "gold", "gems", "balance"]):
                                ctx.add_finding(
                                    title=f"IDOR — Player Data Exposed at {path}|||IDOR — 플레이어 데이터 노출: {path}",
                                    severity="high",
                                    finding_type="idor",
                                    description=(
                                        f"Unauthenticated access to player data at {path}. "
                                        f"Sensitive fields: {list(data.keys())[:5]}|||"
                                        f"{path}에서 인증 없이 플레이어 데이터 접근 가능. "
                                        f"노출 필드: {list(data.keys())[:5]}"
                                    ),
                                    target=ctx.target,
                                    affected_component=path,
                                    source_plugin="game-pipeline-phase5",
                                )
                        except Exception:
                            pass
                except Exception:
                    pass

            # 2. Mass Assignment 테스트 (역할/관리자 권한 상승)
            admin_payloads = [
                {"role": "admin"},
                {"is_admin": True},
                {"user_type": "admin"},
                {"admin": True, "superuser": True},
            ]
            register_paths = [p["path"] for p in ctx.api_endpoints
                              if any(k in p.get("path", "").lower() for k in ["register", "signup", "create"])]

            for path in register_paths[:2]:
                for payload in admin_payloads:
                    try:
                        r = await session.request("POST", path, json_data={
                            "username": f"testuser_{int(time.time())}",
                            "password": "TestPass123!",
                            "email": f"test_{int(time.time())}@test.com",
                            **payload,
                        })
                        resp_lower = r.text.lower()
                        if r.status in (200, 201) and any(k in resp_lower for k in ["admin", "success", "created"]):
                            ctx.add_finding(
                                title="Mass Assignment — Admin Privilege Escalation|||Mass Assignment — 관리자 권한 상승",
                                severity="critical",
                                finding_type="mass_assignment",
                                description=(
                                    f"Admin role injection accepted at {path} with payload {payload}|||"
                                    f"{path}에서 관리자 역할 주입 허용: {payload}"
                                ),
                                target=ctx.target,
                                affected_component=path,
                                source_plugin="game-pipeline-phase5",
                            )
                    except Exception:
                        pass

            # 3. SQL Injection 테스트 (게임 리더보드, 검색)
            sqli_payloads = ["'", "1' OR '1'='1", "1 AND SLEEP(2)"]
            searchable_paths = [p["path"] for p in ctx.api_endpoints
                                if any(k in p.get("path", "").lower() for k in
                                       ["search", "rank", "leader", "score", "player"])]

            for path in searchable_paths[:5]:
                for payload in sqli_payloads:
                    try:
                        r = await session.get(f"{path}?q={payload}&id={payload}")
                        if any(err in r.text.lower() for err in
                               ["syntax error", "sql", "mysql", "postgresql", "sqlite"]):
                            ctx.add_finding(
                                title=f"SQL Injection at {path}|||SQL 인젝션: {path}",
                                severity="critical",
                                finding_type="sqli",
                                description=(
                                    f"SQL error triggered at {path} with payload '{payload}'|||"
                                    f"{path}에서 SQL 오류 발생: 페이로드 '{payload}'"
                                ),
                                target=ctx.target,
                                affected_component=path,
                                source_plugin="game-pipeline-phase5",
                            )
                    except Exception:
                        pass

            # 4. Rate Limiting 체크 (로그인 브루트포스)
            login_paths = [p["path"] for p in ctx.api_endpoints
                           if any(k in p.get("path", "").lower() for k in ["login", "auth"])]

            for path in login_paths[:1]:
                responses = []
                for _ in range(10):
                    try:
                        r = await session.request("POST", path, json_data={
                            "username": "admin",
                            "password": f"wrong_pass_{_}",
                        })
                        responses.append(r.status)
                    except Exception:
                        break

                if responses and all(s not in (429, 423, 403) for s in responses):
                    ctx.add_finding(
                        title="No Rate Limiting on Login Endpoint|||로그인 엔드포인트 레이트 리밋 미적용",
                        severity="high",
                        finding_type="brute_force_susceptibility",
                        description=(
                            f"Login endpoint {path} allows >10 attempts without rate limiting. "
                            f"Brute force possible.|||"
                            f"로그인 엔드포인트 {path}에서 10회 이상 시도에 레이트 리밋 없음. "
                            f"브루트포스 가능."
                        ),
                        target=ctx.target,
                        affected_component=path,
                        source_plugin="game-pipeline-phase5",
                    )

            logger.info(
                "  API testing: %d endpoints tested, findings=%d",
                len(ctx.api_endpoints), len(ctx.findings),
            )

        finally:
            await mgr.close_all()

    async def _phase6_auth_session(self, ctx: GameScanContext) -> None:
        """Phase 6: 인증 우회 + 세션 하이재킹 + 토큰 분석."""
        from vxis.interaction.hands import SessionManager
        import base64
        import json as json_lib

        mgr = SessionManager()
        try:
            session = await mgr.get_session(ctx.target)

            # 1. JWT 분석
            for token_info in ctx.game_auth_tokens:
                token_val = token_info.get("value", "")
                if token_val.startswith("eyJ"):  # JWT 패턴
                    try:
                        parts = token_val.split(".")
                        if len(parts) >= 2:
                            # Base64 패딩 보정
                            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                            payload = json_lib.loads(base64.b64decode(padded))

                            # 알고리즘 확인
                            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
                            header = json_lib.loads(base64.b64decode(header_padded))
                            alg = header.get("alg", "unknown")

                            if alg.lower() == "none":
                                ctx.add_finding(
                                    title="JWT 'none' Algorithm Vulnerability|||JWT 'none' 알고리즘 취약점",
                                    severity="critical",
                                    finding_type="broken_authentication",
                                    description=(
                                        "JWT token uses 'none' algorithm — signature verification bypassed.|||"
                                        "JWT 토큰이 'none' 알고리즘 사용 — 서명 검증 우회 가능."
                                    ),
                                    target=ctx.target,
                                    source_plugin="game-pipeline-phase6",
                                )
                            elif alg in ("HS256", "HS384", "HS512"):
                                ctx.add_finding(
                                    title=f"JWT HMAC Algorithm ({alg}) — Weak Secret Risk|||JWT HMAC 알고리즘 ({alg}) — 취약 시크릿 위험",
                                    severity="medium",
                                    finding_type="broken_authentication",
                                    description=(
                                        f"JWT uses symmetric {alg}. Weak secret allows token forgery.|||"
                                        f"JWT가 대칭 {alg} 사용. 취약한 시크릿 시 토큰 위조 가능."
                                    ),
                                    target=ctx.target,
                                    source_plugin="game-pipeline-phase6",
                                )

                            # 만료 시간 확인
                            exp = payload.get("exp", 0)
                            if exp == 0:
                                ctx.add_finding(
                                    title="JWT Token Without Expiry|||JWT 만료 시간 미설정",
                                    severity="high",
                                    finding_type="broken_authentication",
                                    description=(
                                        "Game JWT token has no expiration — permanent access token.|||"
                                        "게임 JWT 토큰에 만료 시간 없음 — 영구 액세스 토큰."
                                    ),
                                    target=ctx.target,
                                    source_plugin="game-pipeline-phase6",
                                )

                    except Exception:
                        pass

            # 2. 세션 고정 테스트
            try:
                resp1 = await session.get("/")
                resp2 = await session.get("/")
                cookie1 = resp1.headers.get("set-cookie", "")
                cookie2 = resp2.headers.get("set-cookie", "")

                if cookie1 and cookie1 == cookie2:
                    ctx.add_finding(
                        title="Session Fixation — Static Session Cookie|||세션 고정 공격 — 정적 세션 쿠키",
                        severity="high",
                        finding_type="session_management",
                        description=(
                            "Session cookie does not change between requests — session fixation possible.|||"
                            "요청 간 세션 쿠키가 변하지 않음 — 세션 고정 공격 가능."
                        ),
                        target=ctx.target,
                        source_plugin="game-pipeline-phase6",
                    )
            except Exception:
                pass

            # 3. 인증 우회 벡터
            bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Admin": "true"},
                {"X-Internal": "true"},
                {"X-Auth-Token": "bypass"},
            ]

            admin_paths = [p["path"] for p in ctx.api_endpoints
                           if any(k in p.get("path", "").lower() for k in ["admin", "internal", "manage"])]

            for path in admin_paths[:3]:
                for bypass_header in bypass_headers:
                    try:
                        r = await session.request("GET", path, extra_headers=bypass_header)
                        if r.status == 200:
                            ctx.session_hijacking_vectors.append({
                                "path": path,
                                "header": bypass_header,
                                "status": r.status,
                            })
                            ctx.add_finding(
                                title=f"Auth Bypass via Header Injection at {path}|||헤더 인젝션으로 인증 우회: {path}",
                                severity="critical",
                                finding_type="broken_authentication",
                                description=(
                                    f"Admin endpoint {path} bypassed with header {bypass_header}|||"
                                    f"관리자 엔드포인트 {path}가 헤더 {bypass_header}로 우회됨"
                                ),
                                target=ctx.target,
                                affected_component=path,
                                source_plugin="game-pipeline-phase6",
                            )
                    except Exception:
                        pass

        finally:
            await mgr.close_all()

        logger.info("  Auth/Session: %d vectors found", len(ctx.session_hijacking_vectors))

    async def _phase7_economy_analysis(self, ctx: GameScanContext) -> None:
        """Phase 7: 가상 경제 매핑 + 조작 벡터 식별."""
        from vxis.interaction.hands import SessionManager
        import json as json_lib

        mgr = SessionManager()
        currencies: list[dict[str, Any]] = []
        items: list[dict[str, Any]] = []
        transaction_endpoints: list[str] = []

        try:
            session = await mgr.get_session(ctx.target)

            # 경제 관련 엔드포인트 탐색
            economy_paths = [
                p["path"] for p in ctx.api_endpoints
                if any(k in p.get("path", "").lower() for k in
                       ["shop", "store", "item", "inventory", "currency", "gold",
                        "gem", "diamond", "coin", "wallet", "balance", "purchase",
                        "buy", "sell", "trade", "market"])
            ]

            for path in economy_paths[:15]:
                try:
                    r = await session.get(path)
                    if r.status == 200:
                        try:
                            data = json_lib.loads(r.text)
                            transaction_endpoints.append(path)

                            # 통화 탐지
                            if isinstance(data, dict):
                                for key in data:
                                    if any(c in key.lower() for c in
                                           ["gold", "gem", "coin", "diamond", "crystal",
                                            "currency", "balance", "credit"]):
                                        currencies.append({
                                            "name": key,
                                            "value": data[key],
                                            "endpoint": path,
                                            "type": "soft" if "gold" in key.lower() else "hard",
                                        })

                            # 아이템 탐지
                            if isinstance(data, (list, dict)):
                                items_data = data if isinstance(data, list) else data.get("items", [])
                                if isinstance(items_data, list):
                                    for item in items_data[:5]:
                                        if isinstance(item, dict):
                                            items.append({
                                                "id": item.get("id", ""),
                                                "name": item.get("name", ""),
                                                "price": item.get("price", item.get("cost", 0)),
                                                "type": item.get("type", "unknown"),
                                            })
                        except Exception:
                            pass
                except Exception:
                    pass

            # 경제 모델 설정
            ctx.set_economy_model(
                currencies=currencies,
                items=items,
                trading_enabled=any("trade" in p.lower() for p in transaction_endpoints),
                marketplace_url=next((p for p in transaction_endpoints if "market" in p.lower()), ""),
                transaction_endpoints=transaction_endpoints,
            )

            # 음수 금액 테스트 (클라이언트 검증 우회)
            for path in transaction_endpoints[:5]:
                if any(k in path.lower() for k in ["purchase", "buy", "transaction"]):
                    negative_payload = {
                        "amount": -9999,
                        "quantity": -1,
                        "price": -100,
                        "item_id": "sword_001",
                    }
                    ctx.defer_action(
                        phase="Phase 7: Economy Analysis",
                        description_en=f"Test negative amount purchase at {path} — may grant free items",
                        description_ko=f"{path}에서 음수 금액 구매 테스트 — 아이템 무료 획득 가능성",
                        method="POST",
                        url=ctx.target + path,
                        data=negative_payload,
                        risk="medium",
                    )

            # 정수 오버플로우 테스트
            if transaction_endpoints:
                path = transaction_endpoints[0]
                overflow_payload = {
                    "amount": 2147483648,  # INT_MAX + 1
                    "quantity": 4294967295,  # UINT_MAX
                }
                ctx.currency_manipulation_attempts.append({
                    "type": "integer_overflow",
                    "path": path,
                    "payload": overflow_payload,
                })
                ctx.defer_action(
                    phase="Phase 7: Economy Analysis",
                    description_en=f"Test integer overflow at {path} — INT_MAX+1 currency amount",
                    description_ko=f"{path}에서 정수 오버플로우 테스트 — 음수 통화 획득 가능성",
                    method="POST",
                    url=ctx.target + path,
                    data=overflow_payload,
                    risk="medium",
                )

        finally:
            await mgr.close_all()

        logger.info(
            "  Economy: %d currencies, %d items, %d transaction endpoints",
            len(currencies), len(items), len(transaction_endpoints),
        )

        if currencies:
            ctx.add_finding(
                title=f"Game Economy Mapped — {len(currencies)} Currencies|||게임 경제 분석 완료 — {len(currencies)}개 통화",
                severity="informational",
                finding_type="game_economy",
                description=(
                    f"Identified currencies: {[c['name'] for c in currencies]}. "
                    f"Transaction endpoints: {len(transaction_endpoints)}|||"
                    f"식별된 통화: {[c['name'] for c in currencies]}. "
                    f"거래 엔드포인트: {len(transaction_endpoints)}개"
                ),
                target=ctx.target,
                source_plugin="game-pipeline-phase7",
            )

    async def _phase8_economy_exploit(self, ctx: GameScanContext) -> None:
        """Phase 8: 아이템 복제 + 통화 조작 + 경쟁 조건 테스트."""
        from vxis.interaction.hands import SessionManager

        if not ctx.economy_model.get("analyzed"):
            logger.info("  Economy not analyzed — skipping exploitation phase")
            return

        mgr = SessionManager()
        try:
            session = await mgr.get_session(ctx.target)
            transaction_endpoints = ctx.economy_model.get("transaction_endpoints", [])

            # 1. 아이템 복제 테스트 (경쟁 조건)
            duplicate_candidates = [
                p for p in transaction_endpoints
                if any(k in p.lower() for k in ["trade", "transfer", "send", "gift"])
            ]

            for path in duplicate_candidates[:3]:
                # 동시 요청으로 경쟁 조건 탐지
                ctx.race_condition_windows.append({
                    "path": path,
                    "type": "item_duplication",
                    "method": "simultaneous_requests",
                })
                ctx.defer_action(
                    phase="Phase 8: Economy Exploit",
                    description_en=f"Race condition item duplication test at {path}",
                    description_ko=f"{path}에서 경쟁 조건 아이템 복제 테스트",
                    method="POST",
                    url=ctx.target + path,
                    data={"item_id": "test_item", "quantity": 1, "to_user": "test"},
                    risk="medium",
                )

            # 2. 서버 측 검증 없이 클라이언트 가격 조작
            purchase_paths = [
                p for p in transaction_endpoints
                if any(k in p.lower() for k in ["purchase", "buy", "checkout"])
            ]

            for path in purchase_paths[:2]:
                # 가격을 0 또는 1로 변조
                price_tampering_payload = {
                    "item_id": "premium_item_001",
                    "quantity": 1,
                    "price": 0,
                    "total": 0,
                }
                try:
                    r = await session.request("POST", path, json_data=price_tampering_payload)
                    if r.status in (200, 201):
                        ctx.add_finding(
                            title=f"Price Tampering — Server-Side Validation Missing at {path}|||가격 변조 — 서버 측 검증 없음: {path}",
                            severity="critical",
                            finding_type="business_logic",
                            description=(
                                f"Purchase with price=0 succeeded at {path}. "
                                f"Free item acquisition possible.|||"
                                f"{path}에서 가격=0 구매 성공. 무료 아이템 획득 가능."
                            ),
                            target=ctx.target,
                            affected_component=path,
                            source_plugin="game-pipeline-phase8",
                        )
                except Exception:
                    pass

            # 3. 통화 롤백 취약점 (트랜잭션 중단)
            for path in transaction_endpoints[:2]:
                ctx.add_game_finding(
                    category="economy",
                    issue=f"Transaction rollback vulnerability needs testing at {path}",
                    severity="medium",
                    details={
                        "path": path,
                        "attack": "Interrupt transaction mid-flight to duplicate items",
                        "technique": "Connection abort during purchase",
                    },
                )

            if ctx.race_condition_windows:
                ctx.add_finding(
                    title=f"Race Condition Windows in Economy ({len(ctx.race_condition_windows)} endpoints)|||경제 경쟁 조건 취약점 ({len(ctx.race_condition_windows)}개 엔드포인트)",
                    severity="high",
                    finding_type="race_condition",
                    description=(
                        f"Transaction endpoints vulnerable to concurrent request attacks: "
                        f"{[w['path'] for w in ctx.race_condition_windows]}|||"
                        f"동시 요청 공격에 취약한 거래 엔드포인트: "
                        f"{[w['path'] for w in ctx.race_condition_windows]}"
                    ),
                    target=ctx.target,
                    source_plugin="game-pipeline-phase8",
                )

        finally:
            await mgr.close_all()

        logger.info(
            "  Economy exploit: %d race windows, findings=%d",
            len(ctx.race_condition_windows), len(ctx.findings),
        )

    async def _phase9_leaderboard_matchmaking(self, ctx: GameScanContext) -> None:
        """Phase 9: 점수 조작 + 랭크 부스팅 + 매치메이킹 남용."""
        from vxis.interaction.hands import SessionManager
        import json as json_lib

        mgr = SessionManager()
        try:
            session = await mgr.get_session(ctx.target)

            # 리더보드 엔드포인트 수집
            lb_paths = [
                p["path"] for p in ctx.api_endpoints
                if any(k in p.get("path", "").lower() for k in
                       ["rank", "leader", "score", "top", "best", "chart"])
            ]
            ctx.leaderboard_endpoints = [{"path": p, "source": "recon"} for p in lb_paths]

            for path in lb_paths[:5]:
                # 1. 리더보드 데이터 분석
                try:
                    r = await session.get(path)
                    if r.status == 200:
                        try:
                            json_lib.loads(r.text)
                            # 점수 제출 엔드포인트 찾기
                            logger.info("  Leaderboard data at %s: %d bytes", path, len(r.text))
                        except Exception:
                            pass
                except Exception:
                    pass

                # 2. 점수 조작 테스트 (MAX_INT 점수 제출)
                score_paths = [p for p in lb_paths if any(k in p.lower() for k in ["submit", "post", "set"])]
                for score_path in score_paths[:2]:
                    try:
                        cheat_payload = {
                            "score": 2147483647,
                            "level": 99999,
                            "time": 0,
                            "kills": 99999,
                        }
                        r = await session.request("POST", score_path, json_data=cheat_payload)
                        if r.status in (200, 201):
                            ctx.rank_manipulation_vectors.append({
                                "path": score_path,
                                "payload": cheat_payload,
                                "response_status": r.status,
                            })
                            ctx.add_finding(
                                title=f"Score Manipulation — Server Validation Missing at {score_path}|||점수 조작 — 서버 검증 없음: {score_path}",
                                severity="critical",
                                finding_type="business_logic",
                                description=(
                                    f"Unrealistic score submitted to {score_path} was accepted. "
                                    f"Score: 2147483647|||"
                                    f"{score_path}에서 비현실적인 점수 2147483647 수락됨"
                                ),
                                target=ctx.target,
                                affected_component=score_path,
                                source_plugin="game-pipeline-phase9",
                            )
                    except Exception:
                        pass

            # 3. 매치메이킹 분석
            mm_paths = [
                p["path"] for p in ctx.api_endpoints
                if any(k in p.get("path", "").lower() for k in
                       ["match", "queue", "lobby", "room", "session"])
            ]

            for path in mm_paths[:3]:
                try:
                    r = await session.get(path)
                    if r.status == 200:
                        ctx.matchmaking_analysis["endpoint"] = path
                        ctx.matchmaking_analysis["status"] = "accessible"
                        ctx.matchmaking_analysis["response_size"] = len(r.text)

                        # 매치메이킹 조작 시도 (낮은 랭크 상대 선택)
                        rank_manipulation = {
                            "min_rank": 0,
                            "max_rank": 1,
                            "preferred_rank": "bronze",
                        }
                        ctx.defer_action(
                            phase="Phase 9: Leaderboard & Matchmaking",
                            description_en=f"Test rank range manipulation in matchmaking at {path}",
                            description_ko=f"{path}에서 매치메이킹 랭크 범위 조작 테스트",
                            method="POST",
                            url=ctx.target + path,
                            data=rank_manipulation,
                            risk="low",
                        )
                except Exception:
                    pass

            logger.info(
                "  Leaderboard/MM: %d lb endpoints, %d rank vectors",
                len(ctx.leaderboard_endpoints), len(ctx.rank_manipulation_vectors),
            )

        finally:
            await mgr.close_all()

    async def _phase10_client_analysis(self, ctx: GameScanContext) -> None:
        """Phase 10: 바이너리 역공학 + 문자열 추출 + 하드코딩 시크릿."""
        import shutil
        import subprocess
        from pathlib import Path

        if not ctx.client_binary:
            logger.info("  No client binary provided — skipping binary analysis")
            return

        binary_path = Path(ctx.client_binary)
        if not binary_path.exists():
            logger.info("  Client binary not found at %s", ctx.client_binary)
            return

        ctx.binary_analysis["path"] = ctx.client_binary
        ctx.binary_analysis["size"] = binary_path.stat().st_size

        # 1. 파일 타입 탐지
        if shutil.which("file"):
            try:
                result = subprocess.run(
                    ["file", ctx.client_binary],
                    capture_output=True, text=True, timeout=10,
                )
                file_info = result.stdout.strip()
                ctx.binary_analysis["file_type"] = file_info
                logger.info("  Binary type: %s", file_info[:80])

                # 아키텍처 추출
                if "x86-64" in file_info or "x86_64" in file_info:
                    ctx.binary_analysis["architecture"] = "x64"
                elif "ARM" in file_info or "aarch64" in file_info:
                    ctx.binary_analysis["architecture"] = "arm64"
                elif "i386" in file_info:
                    ctx.binary_analysis["architecture"] = "x86"
            except subprocess.TimeoutExpired:
                pass

        # 2. 문자열 추출 (strings 도구)
        if shutil.which("strings"):
            try:
                result = subprocess.run(
                    ["strings", "-n", "8", ctx.client_binary],
                    capture_output=True, text=True, timeout=60,
                )
                raw_strings = result.stdout.split("\n")

                # 관심 있는 문자열 필터링
                interesting_patterns = [
                    (r"https?://[^\s]{10,}", "url"),
                    (r"(?:api[_-]?key|apikey|secret|password|token)[^\s]{5,}", "credential"),
                    (r"(?:sk-|pk-)[A-Za-z0-9]{20,}", "api_key"),
                    (r"[A-Za-z0-9+/]{32,}={0,2}", "base64"),
                    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?", "ip_address"),
                ]

                for s in raw_strings:
                    for pattern, pattern_type in interesting_patterns:
                        if re.search(pattern, s, re.I):
                            ctx.extracted_strings.append(s)
                            if pattern_type == "credential":
                                ctx.hardcoded_credentials.append({
                                    "type": pattern_type,
                                    "value": s[:50],
                                    "source": "binary_strings",
                                })
                            break

                # 서버 주소 추출
                server_addrs = [s for s in raw_strings
                                if re.search(r"(?:game|api|play)\.[a-z]{2,}\.[a-z]{2,}", s)]
                for addr in server_addrs[:10]:
                    ctx.game_server_ips.append(addr.strip())

                logger.info("  Extracted %d interesting strings from binary", len(ctx.extracted_strings))

                if ctx.hardcoded_credentials:
                    ctx.add_finding(
                        title=f"Hardcoded Credentials in Binary ({len(ctx.hardcoded_credentials)})|||바이너리에 하드코딩된 크리덴셜 ({len(ctx.hardcoded_credentials)}개)",
                        severity="critical",
                        finding_type="sensitive_data_exposure",
                        description=(
                            f"Binary contains hardcoded credentials: "
                            f"{[c['value'][:20] for c in ctx.hardcoded_credentials[:3]]}|||"
                            f"바이너리에 하드코딩된 크리덴셜 포함: "
                            f"{[c['value'][:20] for c in ctx.hardcoded_credentials[:3]]}"
                        ),
                        target=ctx.target,
                        affected_component=ctx.client_binary,
                        source_plugin="game-pipeline-phase10",
                    )

            except subprocess.TimeoutExpired:
                logger.warning("  strings command timed out on binary")

        # 3. UPX 패킹 탐지
        if shutil.which("upx"):
            try:
                result = subprocess.run(
                    ["upx", "-t", ctx.client_binary],
                    capture_output=True, text=True, timeout=30,
                )
                if "is packed" in result.stdout.lower():
                    ctx.binary_analysis["is_packed"] = True
                    ctx.binary_analysis["packer"] = "UPX"
                    ctx.add_finding(
                        title="Binary Packed with UPX — Obfuscation Detected|||UPX로 패킹된 바이너리 탐지",
                        severity="informational",
                        finding_type="binary_analysis",
                        description=(
                            "Game client binary is UPX-packed. Unpack before analysis: upx -d game.exe|||"
                            "게임 클라이언트가 UPX로 패킹됨. 분석 전 언패킹 필요: upx -d game.exe"
                        ),
                        target=ctx.target,
                        affected_component=ctx.client_binary,
                        source_plugin="game-pipeline-phase10",
                    )
            except Exception:
                pass

        logger.info("  Binary analysis: %d strings, %d credentials", len(ctx.extracted_strings), len(ctx.hardcoded_credentials))

    async def _phase11_memory_scan(self, ctx: GameScanContext) -> None:
        """Phase 11: FridaBridge 메모리 분석 + 게임 상태 조작."""
        from vxis.interaction.frida_bridge import FridaBridge

        bridge = FridaBridge()

        if not bridge.is_available:
            logger.info("  frida not available — skipping memory scan")
            ctx.add_finding(
                title="Frida Not Available — Memory Analysis Skipped|||Frida 미설치 — 메모리 분석 생략",
                severity="informational",
                finding_type="analysis_limitation",
                description=(
                    "frida Python package not installed. Install: pip install frida frida-tools|||"
                    "frida 미설치. 설치: pip install frida frida-tools"
                ),
                target=ctx.target,
                source_plugin="game-pipeline-phase11",
            )
            return

        # 게임 프로세스 탐색
        processes = await bridge.enumerate_processes()
        from pathlib import PurePosixPath
        base_keywords = [ctx.game_title.lower(), "unity", "unreal", "game"]
        if ctx.client_binary:
            base_keywords.append(PurePosixPath(ctx.client_binary).stem.lower())
        game_process_keywords = base_keywords


        target_process = None
        for proc in processes:
            proc_name_lower = proc.name.lower()
            if any(kw in proc_name_lower for kw in game_process_keywords if kw):
                target_process = proc
                logger.info("  Found game process: %s (PID: %d)", proc.name, proc.pid)
                break

        if target_process is None:
            # 클라이언트 바이너리가 있으면 스폰 시도
            if ctx.client_binary:
                pid = await bridge.spawn(ctx.client_binary)
                if pid:
                    await bridge.resume(pid)
                    logger.info("  Spawned game process: PID %d", pid)
                else:
                    logger.info("  Could not spawn game process")
                    return
            else:
                logger.info("  No game process found — skipping memory scan")
                return
        else:
            success = await bridge.attach(target_process.pid)
            if not success:
                logger.info("  Failed to attach to game process")
                return

        try:
            # 모듈 열거
            modules = await bridge.enumerate_modules()
            ctx.memory_regions = [
                {
                    "address": m.base_address,
                    "size": m.size,
                    "description": m.name,
                    "type": "module",
                }
                for m in modules[:20]
            ]
            logger.info("  Found %d modules in game process", len(modules))

            # Brain으로 훅 스크립트 생성 + 실행
            if hasattr(self.brain, "query"):
                game_desc = (
                    f"Game: {ctx.game_title or 'unknown'}, "
                    f"Engine: {ctx.game_engine}, "
                    f"Type: {ctx.game_type}. "
                    f"Find and log all currency-related function calls (gold, gems, coins). "
                    f"Also hook any anti-cheat detection functions."
                )
                hook_script = await bridge.generate_hook_script(
                    brain=self.brain,
                    target_description=game_desc,
                    module_name=modules[0].name if modules else "",
                )
                result = await bridge.inject_script(hook_script, collect_duration=5.0)
                ctx.frida_hooks_applied.append({
                    "name": hook_script.name,
                    "generated_by_brain": hook_script.generated_by_brain,
                    "messages": result.message_count,
                    "captured_values": result.captured_values[:10],
                })
                logger.info(
                    "  Hook '%s': %d messages, %d values",
                    hook_script.name, result.message_count, len(result.captured_values),
                )

                # 경제 관련 값 분석
                economy_keywords = ["gold", "gems", "coins", "hp", "health", "mana", "score"]
                for val in result.captured_values:
                    if isinstance(val, dict):
                        for key in economy_keywords:
                            if key in str(val).lower():
                                ctx.memory_values[key] = val
                                break

            # 안티치트 감지 함수 탐색
            anticheat_patterns = [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "anti_cheat",
                "EasyAntiCheat", "BattleEye",
            ]
            for module in modules:
                exports = await bridge.get_exports(module.name)
                for export in exports:
                    if any(kw.lower() in export.get("name", "").lower() for kw in anticheat_patterns):
                        ctx.add_game_finding(
                            category="anticheat",
                            issue=f"Anti-cheat function detected: {export['name']} in {module.name}",
                            severity="informational",
                            details={"module": module.name, "function": export["name"], "address": export.get("address")},
                        )

        finally:
            await bridge.detach()

        logger.info(
            "  Memory scan: %d modules, %d hooks, %d memory values",
            len(modules), len(ctx.frida_hooks_applied), len(ctx.memory_values),
        )

    async def _phase12_anti_cheat(self, ctx: GameScanContext) -> None:
        """Phase 12: 안티치트 시스템 탐지 + 효과성 평가."""

        # 알려진 안티치트 시스템 시그니처
        anticheat_signatures = {
            "EasyAntiCheat": {
                "files": ["EasyAntiCheat.exe", "EasyAntiCheat_Setup.exe", "EasyAntiCheat64.sys"],
                "kernel_level": False,
                "bypass_difficulty": "medium",
            },
            "BattlEye": {
                "files": ["BEService.exe", "BEClient.dll", "BattlEye.sys"],
                "kernel_level": True,
                "bypass_difficulty": "hard",
            },
            "Vanguard": {
                "files": ["vgc.exe", "vgtray.exe", "vgk.sys"],
                "kernel_level": True,
                "bypass_difficulty": "hard",
                "note": "Ring-0 driver, always-on",
            },
            "VAC": {
                "files": [],
                "kernel_level": False,
                "bypass_difficulty": "medium",
                "note": "Valve Anti-Cheat — delayed bans",
            },
        }

        detected_ac = "none"
        kernel_level = False
        bypass_possible = True
        weaknesses: list[str] = []

        # 바이너리 문자열에서 안티치트 탐지
        ac_keywords_found = set()
        for s in ctx.extracted_strings:
            for ac_name, info in anticheat_signatures.items():
                if ac_name.lower() in s.lower():
                    ac_keywords_found.add(ac_name)
                if any(f.lower() in s.lower() for f in info.get("files", [])):
                    ac_keywords_found.add(ac_name)

        # Frida 훅 결과에서 안티치트 탐지
        for hook_data in ctx.frida_hooks_applied:
            for val in hook_data.get("captured_values", []):
                for ac_name in anticheat_signatures:
                    if ac_name.lower() in str(val).lower():
                        ac_keywords_found.add(ac_name)

        # game_logic_findings에서 탐지
        for finding in ctx.game_logic_findings:
            if finding.get("category") == "anticheat":
                for ac_name in anticheat_signatures:
                    if ac_name.lower() in str(finding).lower():
                        ac_keywords_found.add(ac_name)

        if ac_keywords_found:
            detected_ac = ", ".join(ac_keywords_found)
            ac_info = anticheat_signatures.get(list(ac_keywords_found)[0], {})
            kernel_level = ac_info.get("kernel_level", False)
            bypass_difficulty = ac_info.get("bypass_difficulty", "unknown")
            bypass_possible = bypass_difficulty != "hard"

            # 약점 분석
            if not kernel_level:
                weaknesses.append("User-mode only — kernel hooks possible")
            if "EasyAntiCheat" in ac_keywords_found:
                weaknesses.append("Known EAC bypasses exist via driver emulation")
            if "VAC" in ac_keywords_found:
                weaknesses.append("VAC uses delayed bans — cheating detectable only retrospectively")

        else:
            # 안티치트 없음
            weaknesses = [
                "No anti-cheat detected",
                "Memory manipulation trivially possible",
                "Speed hacks, wallhacks all feasible without anti-cheat",
            ]
            ctx.add_finding(
                title="No Anti-Cheat System Detected|||안티치트 시스템 없음",
                severity="high",
                finding_type="missing_security_control",
                description=(
                    "Game has no detectable anti-cheat system. Memory manipulation, "
                    "speed hacks, and wallhacks can be applied freely.|||"
                    "게임에 안티치트 시스템 없음. 메모리 조작, 스피드핵, 월핵 자유롭게 적용 가능."
                ),
                target=ctx.target,
                source_plugin="game-pipeline-phase12",
            )

        ctx.set_anti_cheat(
            system=detected_ac,
            kernel_level=kernel_level,
            detection_methods=["memory_scan", "process_list", "network_monitor"] if detected_ac != "none" else [],
            bypass_possible=bypass_possible,
            weaknesses=weaknesses,
        )

        # 안티치트 우회 가능성 리포트
        if bypass_possible and detected_ac != "none":
            ctx.add_finding(
                title=f"Anti-Cheat Bypass Possible — {detected_ac}|||안티치트 우회 가능: {detected_ac}",
                severity="high",
                finding_type="security_control_bypass",
                description=(
                    f"Detected anti-cheat: {detected_ac}. "
                    f"Bypass is feasible. Weaknesses: {', '.join(weaknesses[:2])}|||"
                    f"탐지된 안티치트: {detected_ac}. 우회 가능성 있음. "
                    f"취약점: {', '.join(weaknesses[:2])}"
                ),
                target=ctx.target,
                source_plugin="game-pipeline-phase12",
            )

        logger.info(
            "  Anti-cheat: detected=%s, kernel=%s, bypass_possible=%s",
            detected_ac, kernel_level, bypass_possible,
        )

    async def _phase13_social_chat(self, ctx: GameScanContext) -> None:
        """Phase 13: 채팅 인젝션 + 유저네임 XSS + 인게임 피싱 벡터."""
        from vxis.interaction.hands import SessionManager

        mgr = SessionManager()
        try:
            session = await mgr.get_session(ctx.target)

            # 채팅 엔드포인트 수집
            chat_paths = [
                p["path"] for p in ctx.api_endpoints
                if any(k in p.get("path", "").lower() for k in
                       ["chat", "message", "msg", "talk", "whisper", "guild"])
            ]
            ctx.chat_endpoints = [{"path": p} for p in chat_paths]

            # XSS 페이로드 (게임 채팅 특화)
            xss_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "'><script>alert(document.cookie)</script>",
                # 게임 특화 — 아이템 링크 인젝션
                "[item]<script>alert(1)</script>[/item]",
                "{{7*7}}",  # SSTI 탐지
            ]

            for path in chat_paths[:3]:
                for payload in xss_payloads[:4]:
                    try:
                        r = await session.request("POST", path, json_data={
                            "message": payload,
                            "channel": "global",
                        })
                        # 응답에 페이로드가 그대로 반사되면 취약
                        if payload in r.text or payload.replace("<", "&lt;") not in r.text:
                            if r.status in (200, 201):
                                ctx.chat_injection_vectors.append({
                                    "path": path,
                                    "payload": payload,
                                    "type": "xss",
                                })
                                ctx.add_finding(
                                    title="Chat XSS — Script Injection in Game Chat|||채팅 XSS — 게임 채팅 스크립트 인젝션",
                                    severity="high",
                                    finding_type="xss",
                                    description=(
                                        f"XSS payload accepted in chat at {path}: {payload[:50]}|||"
                                        f"{path} 채팅에서 XSS 페이로드 수락: {payload[:50]}"
                                    ),
                                    target=ctx.target,
                                    affected_component=path,
                                    source_plugin="game-pipeline-phase13",
                                )
                                break
                    except Exception:
                        pass

            # 유저네임 XSS (프로필/등록 엔드포인트)
            username_xss_payloads = [
                "<script>alert(1)</script>",
                "admin<img src=x onerror=alert(1)>",
            ]
            register_paths = [
                p["path"] for p in ctx.api_endpoints
                if any(k in p.get("path", "").lower() for k in ["register", "signup"])
            ]
            for path in register_paths[:1]:
                for payload in username_xss_payloads:
                    try:
                        r = await session.request("POST", path, json_data={
                            "username": payload,
                            "password": "TestPass123!",
                            "email": "xss_test@test.com",
                        })
                        if r.status in (200, 201):
                            ctx.add_finding(
                                title="Username XSS — Stored XSS via Profile Name|||유저네임 XSS — 프로필명 저장형 XSS",
                                severity="high",
                                finding_type="xss",
                                description=(
                                    f"Username field accepts XSS payload at {path}. "
                                    f"Stored XSS affects all players viewing this profile.|||"
                                    f"{path} 유저네임 필드에서 XSS 수락. "
                                    f"이 프로필을 보는 모든 플레이어에게 저장형 XSS 영향."
                                ),
                                target=ctx.target,
                                affected_component=path,
                                source_plugin="game-pipeline-phase13",
                            )
                    except Exception:
                        pass

            # 인게임 피싱 링크 탐지 (URL 필터링 없음)
            phishing_payloads = [
                "http://steampowered-secure.com/free-items",
                "https://bit.ly/free-gems",
            ]
            for path in chat_paths[:2]:
                for payload in phishing_payloads:
                    try:
                        r = await session.request("POST", path, json_data={
                            "message": payload,
                            "channel": "global",
                        })
                        if r.status in (200, 201):
                            ctx.chat_injection_vectors.append({
                                "path": path,
                                "payload": payload,
                                "type": "phishing",
                            })
                            ctx.add_finding(
                                title="In-Game Phishing — No URL Filtering in Chat|||인게임 피싱 — 채팅 URL 필터링 없음",
                                severity="medium",
                                finding_type="phishing",
                                description=(
                                    f"Phishing URL allowed in game chat at {path}: {payload}|||"
                                    f"{path} 게임 채팅에서 피싱 URL 허용: {payload}"
                                ),
                                target=ctx.target,
                                affected_component=path,
                                source_plugin="game-pipeline-phase13",
                            )
                    except Exception:
                        pass

        finally:
            await mgr.close_all()

        logger.info(
            "  Social/Chat: %d chat endpoints, %d injection vectors",
            len(ctx.chat_endpoints), len(ctx.chat_injection_vectors),
        )

    async def _phase14_drm_license(self, ctx: GameScanContext) -> None:
        """Phase 14: DRM 검증 우회 + 라이선스 강도 평가."""
        from vxis.interaction.hands import SessionManager
        import json as json_lib

        mgr = SessionManager()
        try:
            session = await mgr.get_session(ctx.target)

            # DRM 관련 엔드포인트 탐색
            drm_paths = [
                "/api/v1/license", "/api/license/verify", "/api/auth/drm",
                "/license", "/api/v1/entitlement", "/api/v1/ownership",
                "/api/v1/activate", "/api/v1/validate",
            ]

            license_endpoints: list[str] = []
            for path in drm_paths:
                try:
                    r = await session.get(path)
                    if r.status < 404:
                        license_endpoints.append(path)
                        logger.info("  DRM endpoint found: %s (%d)", path, r.status)
                except Exception:
                    pass

            # 라이선스 검증 우회 테스트
            bypass_payloads = [
                {"license_key": "", "valid": True},
                {"license_key": "AAAA-BBBB-CCCC-DDDD"},
                {"license_key": "bypass", "skip_validation": True},
                {"owned": True, "purchased": True},
            ]

            for path in license_endpoints[:2]:
                for payload in bypass_payloads:
                    try:
                        r = await session.request("POST", path, json_data=payload)
                        try:
                            data = json_lib.loads(r.text)
                            if data.get("valid") or data.get("success") or data.get("authorized"):
                                ctx.add_finding(
                                    title=f"DRM Bypass — License Validation Weak at {path}|||DRM 우회 — 라이선스 검증 취약: {path}",
                                    severity="critical",
                                    finding_type="drm_bypass",
                                    description=(
                                        f"License validation bypassed at {path} with payload {payload}. "
                                        f"Unauthorized game access possible.|||"
                                        f"{path}에서 페이로드 {payload}로 라이선스 검증 우회. "
                                        f"무단 게임 접근 가능."
                                    ),
                                    target=ctx.target,
                                    affected_component=path,
                                    source_plugin="game-pipeline-phase14",
                                )
                        except Exception:
                            pass
                    except Exception:
                        pass

            # DRM 시스템 탐지 (바이너리 문자열에서)
            drm_signatures = {
                "Denuvo": ["denuvo", "DENUVO", "drm.dll"],
                "Steam": ["steam_api", "SteamAPI", "steam.dll"],
                "Epic Games": ["EOSSDK", "EpicOnlineServices"],
                "Google Play": ["GooglePlayLicensing", "com.google.android.vending"],
                "Apple AppStore": ["StoreKit", "SKPaymentQueue"],
            }

            detected_drm = "none"
            for drm_name, signatures in drm_signatures.items():
                if any(sig.lower() in s.lower() for s in ctx.extracted_strings for sig in signatures):
                    detected_drm = drm_name
                    break

            bypass_difficulty = "low"
            if detected_drm == "Denuvo":
                bypass_difficulty = "high"
                ctx.add_finding(
                    title="Denuvo DRM Detected — High Bypass Difficulty|||Denuvo DRM 탐지 — 우회 난이도 높음",
                    severity="informational",
                    finding_type="drm_analysis",
                    description=(
                        "Denuvo DRM detected. Industry-grade protection, very difficult to bypass.|||"
                        "Denuvo DRM 탐지. 산업 표준급 보호, 우회 매우 어려움."
                    ),
                    target=ctx.target,
                    source_plugin="game-pipeline-phase14",
                )
            elif detected_drm == "none":
                bypass_difficulty = "trivial"
                ctx.add_finding(
                    title="No DRM Protection Detected|||DRM 보호 없음",
                    severity="medium",
                    finding_type="missing_security_control",
                    description=(
                        "No DRM system detected. Game can be freely copied and distributed.|||"
                        "DRM 시스템 없음. 게임을 자유롭게 복사 및 배포 가능."
                    ),
                    target=ctx.target,
                    source_plugin="game-pipeline-phase14",
                )

            ctx.drm_analysis = {
                "system": detected_drm,
                "license_check_endpoints": license_endpoints,
                "bypass_difficulty": bypass_difficulty,
            }

        finally:
            await mgr.close_all()

        logger.info(
            "  DRM: system=%s, difficulty=%s, license_endpoints=%d",
            ctx.drm_analysis.get("system"), ctx.drm_analysis.get("bypass_difficulty"), len(license_endpoints),
        )

    async def _phase15_report(self, ctx: GameScanContext) -> None:
        """Phase 15: NCC 스타일 게임 보안 리포트 생성."""
        from vxis.report.generator import ReportGenerator, ReportData
        from vxis.models.finding import Severity
        from pathlib import Path

        c = sum(1 for f in ctx.findings if f.severity == Severity.critical)
        h = sum(1 for f in ctx.findings if f.severity == Severity.high)
        m = sum(1 for f in ctx.findings if f.severity == Severity.medium)
        lo = sum(1 for f in ctx.findings if f.severity == Severity.low)
        inf = sum(1 for f in ctx.findings if f.severity == Severity.informational)

        # 게임 특화 요약
        economy_summary = ""
        if ctx.economy_model.get("analyzed"):
            currencies = ctx.economy_model.get("currencies", [])
            economy_summary = (
                f"\n\nGame Economy: {len(currencies)} currencies identified. "
                f"Race condition windows: {len(ctx.race_condition_windows)}. "
                f"Currency manipulation attempts: {len(ctx.currency_manipulation_attempts)}."
            )

        anticheat_summary = ""
        if ctx.anti_cheat:
            anticheat_summary = (
                f"\n\nAnti-Cheat: {ctx.anti_cheat.get('system', 'none')}. "
                f"Kernel-level: {ctx.anti_cheat.get('kernel_level', False)}. "
                f"Bypass possible: {ctx.anti_cheat.get('bypass_possible', True)}."
            )

        protocol_summary = ""
        if ctx.protocols:
            protocol_summary = (
                f"\n\nProtocols: {len(ctx.protocols)} identified. "
                f"Binary protocols: {len(ctx.binary_protocols)}. "
                f"Captured packets: {len(ctx.captured_packets)}."
            )

        phases_str = ", ".join(ctx.phases_completed[-5:]) if ctx.phases_completed else "N/A"
        deferred_str = (
            f"{sum(1 for a in ctx.deferred_actions if a.approved)}/{len(ctx.deferred_actions)} approved"
        )

        game_title = ctx.game_title or ctx.target
        rd = ReportData(
            scan_id=ctx.scan_id,
            client_name="",
            target=ctx.target,
            scan_date=ctx.started_at.strftime("%Y-%m-%d"),
            findings=ctx.findings,
            company_name="VXIS Security",
            author="VXIS GamePipeline",
            executive_summary=(
                f"VXIS GamePipeline conducted a comprehensive 16-phase security assessment "
                f"against {game_title} ({ctx.game_type} game, engine: {ctx.game_engine}).\n\n"
                f"Total findings: {len(ctx.findings)} "
                f"(Critical: {c}, High: {h}, Medium: {m}, Low: {lo}, Info: {inf})\n"
                f"Game logic issues: {len(ctx.game_logic_findings)}\n"
                f"Deferred actions: {deferred_str}\n"
                f"Duration: {ctx.duration_seconds:.0f}s"
                f"{economy_summary}{anticheat_summary}{protocol_summary}"
            ),
            methodology=(
                f"16-Phase GamePipeline: Foundation, Recon, Protocol Fingerprint, "
                f"Network Intercept, Protocol Reverse, API Testing, Auth & Session, "
                f"Economy Analysis, Economy Exploit, Leaderboard & Matchmaking, "
                f"Client Analysis, Memory Scan, Anti-Cheat Assessment, Social & Chat, "
                f"DRM & License, Report Generation.\n"
                f"Recent phases: {phases_str}"
            ),
        )

        gen = ReportGenerator()
        from urllib.parse import urlparse
        safe_name = urlparse(ctx.target).netloc.replace(".", "_") or "game_target"
        output = Path("reports") / f"VXIS_GameScan_{safe_name}_{ctx.started_at.strftime('%Y%m%d')}.html"
        output.parent.mkdir(exist_ok=True)
        gen.generate_html_file(rd, output)
        logger.info("  Game security report: %s", output)
        logger.info(
            "  Summary: C:%d H:%d M:%d L:%d I:%d | Game issues: %d",
            c, h, m, lo, inf, len(ctx.game_logic_findings),
        )
