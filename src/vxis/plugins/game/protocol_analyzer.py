"""ProtocolAnalyzerPlugin — 게임 트래픽 프로토콜 구조 분석.

캡처된 게임 네트워크 트래픽을 분석하여 프로토콜 구조, 메시지 타입,
암호화 여부, 서명 검증을 식별.

지원 프로토콜:
    - HTTP/1.1, HTTP/2, WebSocket
    - Protocol Buffers (Protobuf)
    - MessagePack
    - FlatBuffers
    - 커스텀 바이너리 (마직 바이트 기반 휴리스틱)
"""

from __future__ import annotations

import json
import logging
import re
import struct
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

logger = logging.getLogger(__name__)


class ProtocolAnalyzerPlugin(BasePlugin):
    """캡처된 게임 트래픽 프로토콜 구조 분석 플러그인.

    외부 CLI 도구 없이 순수 Python으로 동작.
    tool_binary는 "tcpdump"로 설정하나 validate_environment()가 False여도 동작.
    """

    _meta = PluginMeta(
        name="protocol_analyzer",
        version="1.0.0",
        tool_binary="tcpdump",  # 선택적 — 없어도 수동 분석 가능
        category="game",
        tier=1,
        produces=("protocols", "message_types", "encryption_status"),
        timeout_seconds=120,
    )

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        """tcpdump 명령어 생성 (선택적 사용)."""
        duration = "60" if scan_profile == "aggressive" else "30"
        interface = tool_config.get("interface", "any")
        return (
            f"tcpdump -i {interface} -w /tmp/vxis_game_{target.replace('.', '_')}.pcap "
            f"-G {duration} -W 1 'host {target}'"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """tcpdump 출력 파싱 (주로 캡처 파일 경로 추출)."""
        findings: list[dict[str, Any]] = []
        pcap_pattern = re.search(r"(/tmp/vxis_game_\S+\.pcap)", raw_stdout + raw_stderr)

        parsed_data: dict[str, Any] = {
            "pcap_file": pcap_pattern.group(1) if pcap_pattern else None,
            "capture_complete": "packets captured" in (raw_stdout + raw_stderr).lower(),
        }

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )

    # ── 핵심 분석 메서드 ────────────────────────────────────────────

    def analyze_packets(self, packets: list[dict[str, Any]]) -> dict[str, Any]:
        """캡처된 패킷 목록 분석.

        Args:
            packets: GameScanContext.captured_packets 형식의 패킷 딕셔너리 목록.

        Returns:
            프로토콜 분석 결과 딕셔너리.
        """
        if not packets:
            return {"error": "No packets provided"}

        protocols_found: dict[str, int] = {}
        message_types: list[dict[str, Any]] = []
        encryption_hints: list[str] = []
        anomalies: list[dict[str, Any]] = []

        for pkt in packets:
            payload_hex = pkt.get("payload_hex", "")
            if not payload_hex:
                continue

            try:
                payload_bytes = bytes.fromhex(payload_hex.replace(" ", ""))
            except ValueError:
                continue

            # 프로토콜 식별
            detected_proto = self._identify_protocol(payload_bytes)
            protocols_found[detected_proto] = protocols_found.get(detected_proto, 0) + 1

            # 메시지 타입 추출
            msg_type = self._extract_message_type(payload_bytes, detected_proto)
            if msg_type:
                message_types.append({
                    "protocol": detected_proto,
                    "type": msg_type,
                    "size": len(payload_bytes),
                    "direction": pkt.get("direction", "unknown"),
                })

            # 암호화 탐지
            encryption = self._detect_encryption(payload_bytes)
            if encryption:
                encryption_hints.append(encryption)

            # 이상 패킷 탐지
            anomaly = self._detect_anomaly(payload_bytes, pkt)
            if anomaly:
                anomalies.append(anomaly)

        return {
            "total_packets": len(packets),
            "protocols": protocols_found,
            "dominant_protocol": max(protocols_found, key=lambda k: protocols_found[k]) if protocols_found else "unknown",
            "message_types": message_types[:20],
            "encryption": list(set(encryption_hints)),
            "anomalies": anomalies,
            "security_issues": self._identify_security_issues(protocols_found, encryption_hints, anomalies),
        }

    def analyze_websocket_frames(self, frames: list[dict[str, Any]]) -> dict[str, Any]:
        """WebSocket 프레임 분석.

        Args:
            frames: GameScanContext.websocket_frames 형식의 프레임 딕셔너리.

        Returns:
            WebSocket 프레임 분석 결과.
        """
        if not frames:
            return {"error": "No frames provided"}

        send_frames = [f for f in frames if f.get("direction") == "send"]
        recv_frames = [f for f in frames if f.get("direction") == "recv"]

        # 페이로드 타입 분류
        json_frames = []
        binary_frames = []
        text_frames = []

        for frame in frames:
            payload = frame.get("payload", "")
            if isinstance(payload, (bytes, bytearray)):
                binary_frames.append(frame)
            elif isinstance(payload, str):
                try:
                    json.loads(payload)
                    json_frames.append(frame)
                except (json.JSONDecodeError, ValueError):
                    text_frames.append(frame)

        # 메시지 구조 분석
        message_schema: dict[str, Any] = {}
        for frame in json_frames[:10]:
            try:
                payload = json.loads(frame.get("payload", "{}"))
                if isinstance(payload, dict):
                    for key in payload:
                        message_schema[key] = type(payload[key]).__name__
            except Exception:
                pass

        # 보안 이슈
        security_issues: list[str] = []

        # 평문 인증 토큰 탐지
        for frame in json_frames:
            try:
                payload = json.loads(frame.get("payload", "{}"))
                if isinstance(payload, dict):
                    for key in ("token", "auth", "session", "jwt", "password"):
                        if key in payload:
                            security_issues.append(
                                f"Auth credential '{key}' transmitted in plaintext WebSocket"
                            )
            except Exception:
                pass

        # 입력 검증 없는 커맨드 탐지
        for frame in send_frames[:20]:
            try:
                payload = json.loads(frame.get("payload", "{}"))
                if isinstance(payload, dict):
                    if "cmd" in payload or "command" in payload or "action" in payload:
                        security_issues.append(
                            "Command-pattern messages in WebSocket — command injection risk"
                        )
                        break
            except Exception:
                pass

        return {
            "total_frames": len(frames),
            "send_count": len(send_frames),
            "recv_count": len(recv_frames),
            "json_frames": len(json_frames),
            "binary_frames": len(binary_frames),
            "text_frames": len(text_frames),
            "message_schema_sample": message_schema,
            "security_issues": security_issues,
        }

    # ── Private Helpers ─────────────────────────────────────────────

    def _identify_protocol(self, payload: bytes) -> str:
        """페이로드 바이트로 프로토콜 식별 (휴리스틱)."""
        if not payload:
            return "empty"

        # Protobuf: 필드 태그는 varint, 첫 바이트가 0x08~0x7F 범위
        if len(payload) >= 2 and payload[0] & 0x07 in (0, 1, 2, 5):
            if all(b < 0x80 or (b & 0x80 and b & 0x7F > 0) for b in payload[:4]):
                return "protobuf"

        # MessagePack: 특정 매직 바이트
        if payload[0] in (0x82, 0x83, 0x84, 0x85, 0x92, 0x93, 0x94, 0x95):
            return "msgpack"

        # JSON: { 또는 [으로 시작
        stripped = payload.lstrip(b" \t\n\r")
        if stripped and stripped[0] in (ord("{"), ord("[")):
            try:
                json.loads(payload.decode("utf-8", errors="ignore"))
                return "json"
            except Exception:
                pass

        # FlatBuffers: 처음 4바이트가 오프셋
        if len(payload) >= 8:
            try:
                offset = struct.unpack_from("<I", payload, 0)[0]
                if 4 <= offset <= len(payload):
                    return "flatbuffers"
            except Exception:
                pass

        # HTTP
        http_methods = (b"GET ", b"POST ", b"HTTP/", b"PUT ", b"DELETE ", b"PATCH ")
        if any(payload.startswith(m) for m in http_methods):
            return "http"

        # 고엔트로피 → 암호화 가능성
        entropy = self._calculate_entropy(payload)
        if entropy > 7.5:
            return "encrypted_binary"

        return "unknown_binary"

    def _extract_message_type(self, payload: bytes, protocol: str) -> str | None:
        """프로토콜별 메시지 타입 추출."""
        if protocol == "json":
            try:
                data = json.loads(payload.decode("utf-8", errors="ignore"))
                if isinstance(data, dict):
                    for key in ("type", "msg_type", "op", "action", "cmd", "event"):
                        if key in data:
                            return str(data[key])
            except Exception:
                pass
        elif protocol == "protobuf" and len(payload) >= 2:
            # 첫 번째 필드 번호 추출
            field_number = (payload[0] >> 3) & 0x1F
            return f"field_{field_number}"
        elif protocol == "msgpack":
            return "msgpack_message"

        return None

    def _detect_encryption(self, payload: bytes) -> str | None:
        """암호화 패턴 탐지."""
        if not payload:
            return None

        entropy = self._calculate_entropy(payload)

        # TLS 레코드 헤더
        if len(payload) >= 5 and payload[0] in (0x16, 0x17) and payload[1] == 0x03:
            return "TLS"

        # 고엔트로피 + 균등한 바이트 분포 → 암호화
        if entropy > 7.8:
            return "AES_or_XOR_cipher"

        # XOR 암호화 탐지 (낮은 키 사이즈 패턴)
        if 4 <= entropy <= 6 and len(payload) > 16:
            return "possible_XOR_cipher"

        return None

    def _detect_anomaly(self, payload: bytes, pkt: dict[str, Any]) -> dict[str, Any] | None:
        """이상 패킷 탐지 (리플레이, 대용량 등)."""
        # 비정상적으로 큰 패킷
        if len(payload) > 65535:
            return {
                "type": "oversized_packet",
                "size": len(payload),
                "direction": pkt.get("direction"),
            }

        # 반복 패턴 (replay attack 시그니처)
        if len(payload) >= 16:
            chunk = payload[:16]
            repeat_count = sum(1 for i in range(0, len(payload) - 15, 16) if payload[i:i+16] == chunk)
            if repeat_count > 3:
                return {
                    "type": "repetitive_pattern",
                    "repeat_count": repeat_count,
                    "possible_replay": True,
                }

        return None

    def _identify_security_issues(
        self,
        protocols: dict[str, int],
        encryption: list[str],
        anomalies: list[dict[str, Any]],
    ) -> list[str]:
        """식별된 프로토콜 분석에서 보안 이슈 추출."""
        issues: list[str] = []

        if "unknown_binary" in protocols and not encryption:
            issues.append(
                "Custom binary protocol without detectable encryption — "
                "potential plaintext game state transmission"
            )

        if "json" in protocols:
            issues.append(
                "JSON protocol identified — game state in plaintext. "
                "Parameter tampering and value injection possible."
            )

        if not encryption:
            issues.append(
                "No encryption detected in game traffic — "
                "MITM attacks, packet injection, and replay attacks possible"
            )

        if any(a.get("possible_replay") for a in anomalies):
            issues.append("Replay attack patterns detected in captured traffic")

        return issues

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Shannon entropy 계산."""
        if not data:
            return 0.0
        import math
        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )
