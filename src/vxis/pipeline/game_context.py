"""GameScanContext — 게임 보안 스캔 전용 컨텍스트.

ScanContext를 확장하여 게임 보안 분석에 필요한 게임 특화 필드를 추가.
GamePipeline의 모든 Phase가 이 컨텍스트를 통해 데이터를 공유.

게임 타입:
    - web: 웹 기반 게임 (브라우저 게임, HTML5)
    - desktop: PC 클라이언트 (Windows/macOS 네이티브)
    - mobile: 모바일 앱 (iOS/Android)
    - console: 콘솔 게임 (PlayStation, Xbox, Nintendo)

게임 엔진:
    - unity: Unity3D
    - unreal: Unreal Engine
    - godot: Godot Engine
    - custom: 자체 엔진
    - cocos: Cocos2D/Cocos Creator
    - unknown: 미식별
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from vxis.pipeline.context import ScanContext

logger = logging.getLogger(__name__)


@dataclass
class GameScanContext(ScanContext):
    """게임 보안 분석을 위한 확장 스캔 컨텍스트.

    ScanContext의 모든 필드를 상속하며 게임 특화 필드를 추가.
    """

    # ── 게임 기본 정보 ──────────────────────────────────────────
    game_type: str = "unknown"
    # "web" | "desktop" | "mobile" | "console" | "unknown"

    game_engine: str = "unknown"
    # "unity" | "unreal" | "godot" | "custom" | "cocos" | "unknown"

    game_title: str = ""
    game_version: str = ""
    game_platform: str = ""  # "ios" | "android" | "windows" | "macos" | "linux"

    # ── 서버 인프라 ──────────────────────────────────────────────
    server_endpoints: list[dict[str, Any]] = field(default_factory=list)
    # [{"url": "wss://game.example.com:443", "type": "websocket", "protocol": "custom_binary", "live": True}]

    websocket_connections: list[dict[str, Any]] = field(default_factory=list)
    # [{"url": ..., "handshake": ..., "subprotocol": ..., "messages_captured": N}]

    game_server_ips: list[str] = field(default_factory=list)
    # 매치메이킹, 게임플레이, 채팅 서버 IP 목록

    # ── 프로토콜 분석 ─────────────────────────────────────────────
    protocols: list[dict[str, Any]] = field(default_factory=list)
    # [{"name": "protobuf", "port": 9001, "transport": "tcp", "identified": True, "schema": {...}}]

    protocol_schemas: dict[str, Any] = field(default_factory=dict)
    # 식별된 프로토콜 스키마 (Protobuf, MessagePack, 커스텀 바이너리 등)

    binary_protocols: list[dict[str, Any]] = field(default_factory=list)
    # [{"port": 7777, "transport": "udp", "format": "unknown_binary", "sample_bytes": "..."}]

    # ── 트래픽 캡처 ───────────────────────────────────────────────
    captured_packets: list[dict[str, Any]] = field(default_factory=list)
    # [{"timestamp": ..., "src": ..., "dst": ..., "protocol": ..., "payload_hex": ..., "decoded": {...}}]

    websocket_frames: list[dict[str, Any]] = field(default_factory=list)
    # [{"direction": "send"|"recv", "opcode": ..., "payload": ..., "decoded": {...}}]

    # ── 게임 경제 모델 ─────────────────────────────────────────────
    economy_model: dict[str, Any] = field(default_factory=dict)
    # {
    #   "currencies": [{"name": "gold", "type": "soft", "earn_rate": "quest|battle"}],
    #   "premium_currencies": [{"name": "gems", "type": "hard", "purchase_only": True}],
    #   "items": [...],
    #   "trading_enabled": True,
    #   "marketplace_url": "/api/marketplace",
    #   "transaction_endpoints": [...]
    # }

    economy_transactions: list[dict[str, Any]] = field(default_factory=list)
    # 캡처된 경제 거래 목록

    currency_manipulation_attempts: list[dict[str, Any]] = field(default_factory=list)
    # 시도된 통화 조작 (음수 금액, 오버플로우 등)

    # ── 안티치트 시스템 ────────────────────────────────────────────
    anti_cheat: dict[str, Any] = field(default_factory=dict)
    # {
    #   "system": "EasyAntiCheat" | "BattleEye" | "Vanguard" | "VAC" | "custom" | "none",
    #   "kernel_level": False,
    #   "bypass_possible": False,
    #   "detection_methods": ["memory_scan", "network_monitor", ...],
    #   "weaknesses": [...]
    # }

    anti_cheat_bypass_attempts: list[dict[str, Any]] = field(default_factory=list)
    # 안티치트 우회 시도 결과

    # ── 클라이언트 바이너리 ────────────────────────────────────────
    client_binary: str = ""
    # 게임 클라이언트 바이너리 경로

    binary_analysis: dict[str, Any] = field(default_factory=dict)
    # {
    #   "architecture": "x64",
    #   "is_packed": True,
    #   "packer": "UPX",
    #   "strings": [...],
    #   "imports": [...],
    #   "hardcoded_secrets": [...],
    #   "encryption_keys": [...]
    # }

    extracted_strings: list[str] = field(default_factory=list)
    # 바이너리에서 추출한 주목할 만한 문자열

    hardcoded_credentials: list[dict[str, Any]] = field(default_factory=list)
    # [{"type": "api_key", "value": "...", "source": "binary_offset_0x1234"}]

    # ── 메모리 분석 ───────────────────────────────────────────────
    memory_regions: list[dict[str, Any]] = field(default_factory=list)
    # [{"address": "0x...", "size": N, "protection": "rw-", "description": "player_stats"}]

    memory_values: dict[str, Any] = field(default_factory=dict)
    # 식별된 메모리 주소의 값 {"player_hp": {"addr": "0x...", "value": 100, "type": "int32"}}

    frida_hooks_applied: list[dict[str, Any]] = field(default_factory=list)
    # 적용된 Frida 훅 목록

    # ── 게임 로직 취약점 ───────────────────────────────────────────
    game_logic_findings: list[dict[str, Any]] = field(default_factory=list)
    # [{"category": "economy", "issue": "item_duplication", "severity": "critical", "details": {...}}]

    race_condition_windows: list[dict[str, Any]] = field(default_factory=list)
    # 경쟁 조건 가능성이 있는 거래 엔드포인트

    # ── 리더보드 / 매치메이킹 ──────────────────────────────────────
    leaderboard_endpoints: list[dict[str, Any]] = field(default_factory=list)
    matchmaking_analysis: dict[str, Any] = field(default_factory=dict)
    rank_manipulation_vectors: list[dict[str, Any]] = field(default_factory=list)

    # ── 소셜 / 채팅 ───────────────────────────────────────────────
    chat_endpoints: list[dict[str, Any]] = field(default_factory=list)
    chat_injection_vectors: list[dict[str, Any]] = field(default_factory=list)
    # XSS, 인젝션, 피싱 벡터

    # ── DRM / 라이선스 ─────────────────────────────────────────────
    drm_analysis: dict[str, Any] = field(default_factory=dict)
    # {
    #   "system": "Denuvo" | "Steam" | "none",
    #   "license_check_endpoints": [...],
    #   "bypass_difficulty": "high" | "medium" | "low",
    # }

    # ── 인증 / 세션 ───────────────────────────────────────────────
    game_auth_tokens: list[dict[str, Any]] = field(default_factory=list)
    session_hijacking_vectors: list[dict[str, Any]] = field(default_factory=list)

    # ── 시간 조작 (Time Manipulation) ─────────────────────────────
    time_manipulation_results: list[dict[str, Any]] = field(default_factory=list)
    # [{"endpoint": "/api/v1/daily-reward", "vector": "future_timestamp",
    #   "bypassed": True, "response_status": 200}]

    # ── 세이브파일 / 설정파일 분석 ────────────────────────────────
    save_files: list[dict[str, Any]] = field(default_factory=list)
    # [{"path": "/saves/slot1.sav", "format": "json", "plaintext_values": True,
    #   "encrypted": False, "fields": {"gold": 1000}}]

    config_files: list[dict[str, Any]] = field(default_factory=list)
    # [{"path": "settings.ini", "cheat_options": ["god_mode=false"]}]

    # ── 가챠 / RNG 조작 ───────────────────────────────────────────
    gacha_results: list[dict[str, Any]] = field(default_factory=list)
    # [{"endpoint": "/api/v1/gacha/pull", "attempt": 1, "result": {...},
    #   "seed_predictable": False}]

    gacha_endpoints: list[str] = field(default_factory=list)
    # 식별된 가챠 관련 엔드포인트

    # ── GM 커맨드 / 어드민 엔드포인트 ────────────────────────────
    gm_endpoints_found: list[dict[str, Any]] = field(default_factory=list)
    # [{"path": "/admin/gm", "status": 200, "accessible": True}]

    gm_command_responses: list[dict[str, Any]] = field(default_factory=list)
    # 채팅에서 GM 명령어 주입 시도 결과

    # ── 선물 / 거래 남용 ──────────────────────────────────────────
    trade_abuse_results: list[dict[str, Any]] = field(default_factory=list)
    # [{"vector": "negative_quantity", "endpoint": "/api/v1/gift",
    #   "vulnerable": True, "response": "..."}]

    # ── 리플레이 공격 ────────────────────────────────────────────
    replay_attack_results: list[dict[str, Any]] = field(default_factory=list)
    # [{"endpoint": "/api/v1/claim", "replayed_n_times": 5,
    #   "successes": 3, "nonce_protected": False}]

    # ── 클라우드 세이브 ───────────────────────────────────────────
    cloud_save_endpoints: list[str] = field(default_factory=list)
    # 식별된 클라우드 세이브 관련 엔드포인트

    cloud_save_results: list[dict[str, Any]] = field(default_factory=list)
    # [{"endpoint": "/api/v1/cloud-save", "integrity_check": False,
    #   "manipulable": True}]

    def add_game_finding(
        self,
        category: str,
        issue: str,
        severity: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """게임 특화 로직 이슈를 game_logic_findings에 추가.

        Args:
            category: 이슈 카테고리 ("economy", "anticheat", "protocol", "memory" 등).
            issue: 이슈 설명.
            severity: "critical" | "high" | "medium" | "low" | "informational".
            details: 추가 세부 정보.
        """
        entry: dict[str, Any] = {
            "category": category,
            "issue": issue,
            "severity": severity,
            "details": details or {},
        }
        self.game_logic_findings.append(entry)
        logger.info("[GAME] [%s] %s — %s", severity.upper(), category, issue)

    def add_server_endpoint(
        self,
        url: str,
        endpoint_type: str = "http",
        protocol: str = "",
        live: bool = True,
        **kwargs: Any,
    ) -> None:
        """게임 서버 엔드포인트 추가.

        Args:
            url: 엔드포인트 URL (e.g., "wss://game.example.com:7777").
            endpoint_type: "http" | "websocket" | "tcp" | "udp" | "grpc".
            protocol: 애플리케이션 레이어 프로토콜 (e.g., "protobuf", "json", "custom_binary").
            live: 현재 접근 가능한 상태인지.
        """
        entry: dict[str, Any] = {
            "url": url,
            "type": endpoint_type,
            "protocol": protocol,
            "live": live,
            **kwargs,
        }
        if url not in [e["url"] for e in self.server_endpoints]:
            self.server_endpoints.append(entry)
            logger.debug("Game endpoint added: [%s] %s", endpoint_type.upper(), url)

    def add_captured_packet(
        self,
        direction: str,
        protocol: str,
        payload_hex: str,
        decoded: dict[str, Any] | None = None,
        source: str = "",
        destination: str = "",
    ) -> None:
        """캡처된 게임 패킷 추가.

        Args:
            direction: "client_to_server" | "server_to_client".
            protocol: 전송 프로토콜.
            payload_hex: 페이로드 16진수 문자열.
            decoded: 디코딩된 패킷 내용.
            source: 출발지 IP:Port.
            destination: 목적지 IP:Port.
        """
        import time
        self.captured_packets.append({
            "timestamp": time.time(),
            "direction": direction,
            "protocol": protocol,
            "payload_hex": payload_hex[:500],  # 500자 제한
            "decoded": decoded or {},
            "source": source,
            "destination": destination,
        })

    def set_economy_model(
        self,
        currencies: list[dict[str, Any]] | None = None,
        items: list[dict[str, Any]] | None = None,
        trading_enabled: bool = False,
        marketplace_url: str = "",
        transaction_endpoints: list[str] | None = None,
    ) -> None:
        """게임 경제 모델 설정."""
        self.economy_model = {
            "currencies": currencies or [],
            "items": items or [],
            "trading_enabled": trading_enabled,
            "marketplace_url": marketplace_url,
            "transaction_endpoints": transaction_endpoints or [],
            "analyzed": True,
        }
        logger.info(
            "Economy model set: %d currencies, %d items, trading=%s",
            len(currencies or []), len(items or []), trading_enabled,
        )

    def set_anti_cheat(
        self,
        system: str,
        kernel_level: bool = False,
        detection_methods: list[str] | None = None,
        bypass_possible: bool = False,
        weaknesses: list[str] | None = None,
    ) -> None:
        """안티치트 시스템 정보 설정."""
        self.anti_cheat = {
            "system": system,
            "kernel_level": kernel_level,
            "detection_methods": detection_methods or [],
            "bypass_possible": bypass_possible,
            "weaknesses": weaknesses or [],
        }
        logger.info("Anti-cheat identified: %s (kernel=%s)", system, kernel_level)

    @property
    def total_game_findings(self) -> int:
        """game_logic_findings + findings 합산."""
        return len(self.findings) + len(self.game_logic_findings)

    @property
    def has_binary_client(self) -> bool:
        """클라이언트 바이너리가 있는지 확인."""
        return bool(self.client_binary)

    @property
    def economy_analyzed(self) -> bool:
        """경제 모델이 분석되었는지 확인."""
        return bool(self.economy_model.get("analyzed"))

    def get_critical_game_issues(self) -> list[dict[str, Any]]:
        """critical/high severity 게임 로직 이슈만 필터링."""
        return [
            f for f in self.game_logic_findings
            if f.get("severity") in ("critical", "high")
        ]
