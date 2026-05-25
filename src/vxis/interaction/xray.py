"""VXIS CPR — X-Ray: 트래픽 인터셉트 엔진.

Brain이 모든 네트워크 트래픽을 "투시"하는 X-Ray.
Eyes(브라우저)와 Hands(httpx) 사이의 트래픽을 중간에서 캡처/수정.

핵심 기능:
    1. 트래픽 캡처 — 모든 HTTP/HTTPS 요청/응답 기록
    2. 패턴 분석 — 인증 토큰, API 키, 세션 ID 자동 탐지
    3. 요청 변조 — 인터셉트 규칙으로 실시간 요청/응답 수정
    4. 취약점 탐지 — 트래픽 분석 기반 수동적 취약점 발견
    5. 리플레이 — 캡처된 요청을 변조해서 재전송

Architecture:
    TrafficInterceptor (mitmproxy 래퍼)
        ├── FlowCapture (트래픽 캡처)
        ├── FlowAnalyzer (패턴 분석)
        ├── FlowModifier (요청/응답 변조 규칙)
        └── FlowReplayer (캡처된 요청 리플레이)

Implementation Note:
    mitmproxy를 인프로세스로 사용하지 않고, 별도 프로세스로 실행.
    addon script를 통해 제어하며, 캡처된 데이터는 파일/메모리로 공유.
    mitmproxy가 없으면 순수 Python으로 패시브 분석만 수행.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Data Types ───────────────────────────────────────────────────


class FlowDirection(Enum):
    REQUEST = "request"
    RESPONSE = "response"


@dataclass
class CapturedFlow:
    """캡처된 HTTP 요청/응답 쌍."""

    id: str
    timestamp: float
    # Request
    method: str = ""
    url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    request_content_type: str = ""
    # Response
    status_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_content_type: str = ""
    # Analysis
    is_api_call: bool = False
    has_auth_token: bool = False
    auth_type: str = ""  # bearer, cookie, basic, api-key
    detected_tokens: list[str] = field(default_factory=list)
    detected_secrets: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)

    @property
    def host(self) -> str:
        from urllib.parse import urlparse

        return urlparse(self.url).netloc


@dataclass
class InterceptRule:
    """요청/응답 변조 규칙."""

    name: str
    direction: FlowDirection
    url_pattern: str  # regex
    # 변조 사항
    modify_headers: dict[str, str] = field(default_factory=dict)
    remove_headers: list[str] = field(default_factory=list)
    replace_body: str | None = None
    body_replacements: dict[str, str] = field(default_factory=dict)  # old → new
    modify_status: int | None = None
    enabled: bool = True


@dataclass
class TrafficSummary:
    """트래픽 분석 요약 — Brain에게 보고."""

    total_flows: int = 0
    unique_hosts: set[str] = field(default_factory=set)
    api_endpoints: set[str] = field(default_factory=set)
    auth_tokens_found: list[dict[str, str]] = field(default_factory=list)
    secrets_found: list[dict[str, str]] = field(default_factory=list)
    vulnerabilities: list[dict[str, str]] = field(default_factory=list)
    content_types: dict[str, int] = field(default_factory=dict)
    status_codes: dict[int, int] = field(default_factory=dict)
    interesting_headers: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON 직렬화 가능한 딕셔너리 반환."""
        return {
            "total_flows": self.total_flows,
            "unique_hosts": sorted(self.unique_hosts),
            "api_endpoints": sorted(self.api_endpoints),
            "auth_tokens_found": self.auth_tokens_found,
            "secrets_found": self.secrets_found,
            "vulnerabilities": self.vulnerabilities,
            "content_types": self.content_types,
            "status_codes": {str(k): v for k, v in self.status_codes.items()},
            "interesting_headers": self.interesting_headers,
        }


# ── Passive Traffic Analyzer (mitmproxy 없이도 동작) ─────────────


# 인증 토큰 패턴
_AUTH_PATTERNS = [
    (r"Bearer\s+([A-Za-z0-9_\-\.]+)", "bearer"),
    (r"Basic\s+([A-Za-z0-9+/=]+)", "basic"),
    (r"Token\s+([A-Za-z0-9_\-\.]+)", "token"),
    (r"[Aa]pi[_-]?[Kk]ey[\s:=]+['\"]?([A-Za-z0-9_\-]{20,})", "api-key"),
]

# 시크릿 패턴
_SECRET_PATTERNS = [
    (r"(?:password|passwd|pwd)[\s:=]+['\"]?([^\s'\"]{4,})", "password"),
    (r"(?:secret|private)[_-]?key[\s:=]+['\"]?([A-Za-z0-9_\-]{10,})", "secret-key"),
    (r"(?:aws_?access_?key_?id)[\s:=]+['\"]?([A-Z0-9]{20})", "aws-key"),
    (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}", "github-token"),
    (r"sk-[A-Za-z0-9]{32,}", "openai-key"),
    (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "jwt"),
]

# 패시브 취약점 패턴
_VULN_PATTERNS = [
    # 응답에서 탐지
    ("response", r"(?:sql|mysql|pg|ora).*(?:syntax|error|exception)", "SQL Error Disclosure"),
    ("response", r"(?:stack\s*trace|traceback|at\s+\w+\.\w+\()", "Stack Trace Disclosure"),
    ("response", r"(?:phpinfo|<title>phpinfo\(\))", "PHPInfo Exposure"),
    ("response", r"(?:directory\s+listing|index\s+of\s+/)", "Directory Listing"),
    ("response", r"(?:access-control-allow-origin:\s*\*)", "CORS Wildcard"),
    # 요청에서 탐지 (위험한 패턴)
    ("request", r"(?:\.\.\/|\.\.\\)", "Path Traversal Attempt"),
    ("request", r"(?:<script|javascript:|on\w+=)", "XSS Pattern"),
    ("request", r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*')", "SQLi Pattern"),
]

# 흥미로운 헤더
_INTERESTING_HEADERS = [
    "x-powered-by",
    "server",
    "x-aspnet-version",
    "x-debug",
    "x-runtime",
    "x-request-id",
    "x-forwarded-for",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "content-security-policy",
    "x-frame-options",
]


class FlowAnalyzer:
    """캡처된 트래픽을 분석하는 패시브 분석기.

    mitmproxy 없이도 동작 — Hands/Eyes에서 캡처한 트래픽도 분석 가능.
    """

    def __init__(self) -> None:
        self._flows: list[CapturedFlow] = []
        self._intercept_rules: list[InterceptRule] = []
        self._flow_counter = 0

    def add_flow(self, flow: CapturedFlow) -> CapturedFlow:
        """플로우 추가 + 자동 분석 (이미 분석된 경우 건너뜀)."""
        if not flow.detected_tokens and not flow.vulnerabilities:
            self._analyze_flow(flow)
        self._flows.append(flow)
        return flow

    def create_flow_from_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str = "",
    ) -> CapturedFlow:
        """요청 정보로 CapturedFlow 생성."""
        self._flow_counter += 1
        flow = CapturedFlow(
            id=f"flow-{self._flow_counter:04d}",
            timestamp=time.time(),
            method=method,
            url=url,
            request_headers=headers,
            request_body=body,
            request_content_type=headers.get("content-type", ""),
        )
        return flow

    def update_flow_response(
        self,
        flow: CapturedFlow,
        status_code: int,
        headers: dict[str, str],
        body: str = "",
    ) -> None:
        """응답 정보로 CapturedFlow 업데이트."""
        flow.status_code = status_code
        flow.response_headers = headers
        flow.response_body = body[:50000]  # 50KB 제한
        flow.response_content_type = headers.get("content-type", "")
        self._analyze_flow(flow)

    def get_summary(self) -> TrafficSummary:
        """전체 트래픽 분석 요약."""
        summary = TrafficSummary(total_flows=len(self._flows))

        for flow in self._flows:
            summary.unique_hosts.add(flow.host)

            if flow.is_api_call:
                summary.api_endpoints.add(f"{flow.method} {flow.url}")

            for token in flow.detected_tokens:
                summary.auth_tokens_found.append(
                    {
                        "type": flow.auth_type,
                        "value": token[:20] + "...",
                        "url": flow.url,
                    }
                )

            for secret in flow.detected_secrets:
                summary.secrets_found.append(
                    {
                        "value": secret[:10] + "...",
                        "url": flow.url,
                    }
                )

            for vuln in flow.vulnerabilities:
                summary.vulnerabilities.append(
                    {
                        "type": vuln,
                        "url": flow.url,
                        "method": flow.method,
                    }
                )

            # Content-Type 집계
            ct = (
                flow.response_content_type.split(";")[0].strip()
                if flow.response_content_type
                else "unknown"
            )
            summary.content_types[ct] = summary.content_types.get(ct, 0) + 1

            # Status code 집계
            if flow.status_code:
                summary.status_codes[flow.status_code] = (
                    summary.status_codes.get(flow.status_code, 0) + 1
                )

            # 흥미로운 헤더
            for h in _INTERESTING_HEADERS:
                val = flow.response_headers.get(h) or flow.request_headers.get(h)
                if val:
                    summary.interesting_headers.append({"header": h, "value": val, "url": flow.url})

        return summary

    def find_auth_flows(self) -> list[CapturedFlow]:
        """인증 관련 플로우만 필터."""
        return [f for f in self._flows if f.has_auth_token]

    def find_api_flows(self) -> list[CapturedFlow]:
        """API 호출만 필터."""
        return [f for f in self._flows if f.is_api_call]

    def find_by_status(self, status: int) -> list[CapturedFlow]:
        return [f for f in self._flows if f.status_code == status]

    def find_by_url(self, pattern: str) -> list[CapturedFlow]:
        return [f for f in self._flows if re.search(pattern, f.url)]

    def find_vulnerabilities(self) -> list[CapturedFlow]:
        return [f for f in self._flows if f.vulnerabilities]

    @property
    def flows(self) -> list[CapturedFlow]:
        return list(self._flows)

    # ── Intercept Rules ────────────────────────────────────────

    def add_rule(self, rule: InterceptRule) -> None:
        self._intercept_rules.append(rule)

    def apply_request_rules(
        self,
        url: str,
        headers: dict[str, str],
        body: str,
    ) -> tuple[dict[str, str], str]:
        """요청에 인터셉트 규칙 적용."""
        for rule in self._intercept_rules:
            if not rule.enabled or rule.direction != FlowDirection.REQUEST:
                continue
            if not re.search(rule.url_pattern, url):
                continue

            # 헤더 수정
            for k, v in rule.modify_headers.items():
                headers[k] = v
            for k in rule.remove_headers:
                headers.pop(k, None)

            # 바디 변조
            if rule.replace_body is not None:
                body = rule.replace_body
            for old, new in rule.body_replacements.items():
                body = body.replace(old, new)

            logger.debug("Rule '%s' applied to request: %s", rule.name, url)

        return headers, body

    def apply_response_rules(
        self,
        url: str,
        status: int,
        headers: dict[str, str],
        body: str,
    ) -> tuple[int, dict[str, str], str]:
        """응답에 인터셉트 규칙 적용."""
        for rule in self._intercept_rules:
            if not rule.enabled or rule.direction != FlowDirection.RESPONSE:
                continue
            if not re.search(rule.url_pattern, url):
                continue

            if rule.modify_status is not None:
                status = rule.modify_status
            for k, v in rule.modify_headers.items():
                headers[k] = v
            for k in rule.remove_headers:
                headers.pop(k, None)
            if rule.replace_body is not None:
                body = rule.replace_body
            for old, new in rule.body_replacements.items():
                body = body.replace(old, new)

            logger.debug("Rule '%s' applied to response: %s", rule.name, url)

        return status, headers, body

    # ── Internal Analysis ──────────────────────────────────────

    def _analyze_flow(self, flow: CapturedFlow) -> None:
        """단일 플로우 분석."""
        # API 호출 탐지
        ct = flow.request_content_type.lower()
        if "json" in ct or "graphql" in ct or "/api/" in flow.url:
            flow.is_api_call = True

        # 전체 텍스트
        req_text = " ".join(
            [
                " ".join(f"{k}: {v}" for k, v in flow.request_headers.items()),
                flow.request_body,
            ]
        )
        resp_text = " ".join(
            [
                " ".join(f"{k}: {v}" for k, v in flow.response_headers.items()),
                flow.response_body[:10000],
            ]
        )

        # 인증 토큰 탐지
        for pattern, auth_type in _AUTH_PATTERNS:
            for text in (req_text, resp_text):
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    flow.has_auth_token = True
                    flow.auth_type = auth_type
                    flow.detected_tokens.append(
                        match.group(1) if match.groups() else match.group(0)
                    )

        # 시크릿 탐지
        for pattern, _ in _SECRET_PATTERNS:
            for text in (req_text, resp_text):
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    flow.detected_secrets.append(
                        match.group(1) if match.groups() else match.group(0)
                    )

        # 패시브 취약점 탐지
        for direction, pattern, vuln_name in _VULN_PATTERNS:
            text = req_text if direction == "request" else resp_text
            if re.search(pattern, text, re.IGNORECASE):
                flow.vulnerabilities.append(vuln_name)


# ── mitmproxy Process Manager ────────────────────────────────────


def _mitm_available() -> bool:
    return shutil.which("mitmdump") is not None


class MitmProxyManager:
    """mitmproxy를 별도 프로세스로 실행하는 매니저.

    Usage:
        mgr = MitmProxyManager(port=8080)
        await mgr.start()
        # 브라우저/httpx에서 프록시로 localhost:8080 사용
        flows = mgr.get_captured_flows()
        await mgr.stop()
    """

    def __init__(self, port: int = 8080, capture_dir: str | None = None) -> None:
        self.port = port
        self._process: asyncio.subprocess.Process | None = None
        self._capture_dir = capture_dir or tempfile.mkdtemp(prefix="vxis-xray-")
        self._flow_file = os.path.join(self._capture_dir, "flows.jsonl")
        self._addon_file = os.path.join(self._capture_dir, "addon.py")

    @staticmethod
    def is_available() -> bool:
        return _mitm_available()

    async def start(self) -> str:
        """mitmproxy 시작, proxy URL 반환."""
        if not _mitm_available():
            raise RuntimeError("mitmdump not found. Install: pip install mitmproxy")

        # Addon 스크립트 생성 — 모든 플로우를 JSONL로 기록
        addon_code = f'''
import json, time
from mitmproxy import http

FLOW_FILE = "{self._flow_file}"

class FlowLogger:
    def response(self, flow: http.HTTPFlow):
        entry = {{
            "timestamp": time.time(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": dict(flow.request.headers),
            "request_body": flow.request.get_text()[:10000] if flow.request.content else "",
            "status_code": flow.response.status_code if flow.response else 0,
            "response_headers": dict(flow.response.headers) if flow.response else {{}},
            "response_body": flow.response.get_text()[:10000] if flow.response and flow.response.content else "",
        }}
        with open(FLOW_FILE, "a") as f:
            f.write(json.dumps(entry) + "\\n")

addons = [FlowLogger()]
'''
        with open(self._addon_file, "w") as f:
            f.write(addon_code)

        # mitmdump 시작
        cmd = [
            "mitmdump",
            "--listen-port",
            str(self.port),
            "--set",
            "ssl_insecure=true",
            "-s",
            self._addon_file,
            "--quiet",
        ]

        self._process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await asyncio.sleep(1)  # 시작 대기
        proxy_url = f"http://localhost:{self.port}"
        logger.info("mitmproxy started on %s (PID: %s)", proxy_url, self._process.pid)
        return proxy_url

    async def stop(self) -> None:
        if self._process:
            self._process.terminate()
            await self._process.wait()
            logger.info("mitmproxy stopped")
            self._process = None

    def get_captured_flows(self, analyzer: FlowAnalyzer | None = None) -> list[CapturedFlow]:
        """JSONL 파일에서 캡처된 플로우 읽기."""
        flows: list[CapturedFlow] = []
        if not os.path.exists(self._flow_file):
            return flows

        with open(self._flow_file) as f:
            for i, line in enumerate(f):
                try:
                    data = json.loads(line)
                    flow = CapturedFlow(
                        id=f"mitm-{i:04d}",
                        timestamp=data.get("timestamp", 0),
                        method=data.get("method", ""),
                        url=data.get("url", ""),
                        request_headers=data.get("request_headers", {}),
                        request_body=data.get("request_body", ""),
                        request_content_type=data.get("request_headers", {}).get(
                            "content-type", ""
                        ),
                        status_code=data.get("status_code", 0),
                        response_headers=data.get("response_headers", {}),
                        response_body=data.get("response_body", ""),
                        response_content_type=data.get("response_headers", {}).get(
                            "content-type", ""
                        ),
                    )
                    if analyzer:
                        analyzer.add_flow(flow)
                    flows.append(flow)
                except json.JSONDecodeError:
                    continue

        return flows

    @property
    def proxy_url(self) -> str:
        return f"http://localhost:{self.port}"

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.returncode is None

    # ── Export: HAR / mitm / pcap ──────────────────────────────
    # Note: 사용자 명세상 "TrafficInterceptor"라고 했으나 실제 클래스명은
    # MitmProxyManager. mitmproxy addon이 JSONL로 플로우를 기록하므로 실제로
    # 캡처가 가능하다. 캡처가 비어있으면(stub 상태) no-op + 경고로 동작.

    def export_har(self, output_path: Path) -> Path:
        """캡처된 플로우를 HAR 1.2 (HTTP Archive) 포맷으로 export.

        HAR은 단순 JSON 구조라 외부 의존성 없이 동작.
        """
        from datetime import datetime, timezone

        output_path = Path(output_path)
        flows = self.get_captured_flows()

        if not flows:
            logger.warning(
                "export_har: no captured flows (xray may not have run); writing empty HAR"
            )

        entries: list[dict[str, Any]] = []
        for flow in flows:
            started = datetime.fromtimestamp(flow.timestamp or 0, tz=timezone.utc).isoformat()
            req_headers = [{"name": k, "value": v} for k, v in flow.request_headers.items()]
            resp_headers = [{"name": k, "value": v} for k, v in flow.response_headers.items()]
            entry = {
                "startedDateTime": started,
                "time": 0,
                "request": {
                    "method": flow.method or "GET",
                    "url": flow.url,
                    "httpVersion": "HTTP/1.1",
                    "headers": req_headers,
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": len(flow.request_body or ""),
                    "postData": (
                        {
                            "mimeType": flow.request_content_type or "application/octet-stream",
                            "text": flow.request_body or "",
                        }
                        if flow.request_body
                        else None
                    ),
                },
                "response": {
                    "status": flow.status_code or 0,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": resp_headers,
                    "cookies": [],
                    "content": {
                        "size": len(flow.response_body or ""),
                        "mimeType": flow.response_content_type or "application/octet-stream",
                        "text": flow.response_body or "",
                    },
                    "redirectURL": flow.response_headers.get("location", ""),
                    "headersSize": -1,
                    "bodySize": len(flow.response_body or ""),
                },
                "cache": {},
                "timings": {"send": 0, "wait": 0, "receive": 0},
            }
            # Drop None postData (HAR spec)
            if entry["request"]["postData"] is None:
                del entry["request"]["postData"]
            entries.append(entry)

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "VXIS X-Ray", "version": "1.0"},
                "entries": entries,
            }
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(har, indent=2, ensure_ascii=False))
        logger.info("export_har: wrote %d entries to %s", len(entries), output_path)
        return output_path

    def export_pcap(self, output_path: Path) -> Path:
        """캡처된 플로우를 .pcap (scapy 있을 때) 또는 .mitm (네이티브 JSONL)로 export.

        - scapy 설치되어 있으면 HTTP 플로우를 TCP 패킷으로 변환해 .pcap 작성.
        - 없으면 .mitm (사실상 mitmproxy addon이 작성한 JSONL) 경로로 폴백.
        - 캡처된 플로우가 없으면 (stub 상태) 경고만 남기고 빈 파일 생성.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        flows = self.get_captured_flows()

        if not flows:
            logger.warning(
                "export_pcap: no captured flows; writing empty placeholder at %s", output_path
            )
            output_path.write_bytes(b"")
            return output_path

        # Try scapy
        try:
            from scapy.all import IP, TCP, Ether, Raw, wrpcap  # type: ignore
            from urllib.parse import urlparse

            packets = []
            seq = 1000
            for flow in flows:
                parsed = urlparse(flow.url)
                dst_host = parsed.hostname or "0.0.0.0"
                dst_port = parsed.port or (443 if parsed.scheme == "https" else 80)

                req_line = f"{flow.method} {parsed.path or '/'} HTTP/1.1\r\n"
                req_headers = "".join(f"{k}: {v}\r\n" for k, v in flow.request_headers.items())
                req_raw = (req_line + req_headers + "\r\n" + (flow.request_body or "")).encode(
                    "utf-8", errors="replace"
                )

                resp_line = f"HTTP/1.1 {flow.status_code} OK\r\n"
                resp_headers = "".join(f"{k}: {v}\r\n" for k, v in flow.response_headers.items())
                resp_raw = (resp_line + resp_headers + "\r\n" + (flow.response_body or "")).encode(
                    "utf-8", errors="replace"
                )

                try:
                    pkt_req = (
                        Ether()
                        / IP(dst=dst_host)
                        / TCP(sport=12345, dport=dst_port, flags="PA", seq=seq)
                        / Raw(load=req_raw)
                    )
                    pkt_resp = (
                        Ether()
                        / IP(src=dst_host)
                        / TCP(sport=dst_port, dport=12345, flags="PA", seq=seq + 1)
                        / Raw(load=resp_raw)
                    )
                    packets.append(pkt_req)
                    packets.append(pkt_resp)
                    seq += 2
                except Exception as e:  # pragma: no cover
                    logger.debug("export_pcap: skip flow %s: %s", flow.id, e)

            wrpcap(str(output_path), packets)
            logger.info("export_pcap: wrote %d packets to %s (scapy)", len(packets), output_path)
            return output_path

        except ImportError:
            logger.warning(
                "export_pcap: scapy not installed; falling back to native .mitm (JSONL) format"
            )
            # Native .mitm fallback — copy JSONL or write equivalent
            mitm_path = output_path.with_suffix(".mitm")
            if os.path.exists(self._flow_file):
                shutil.copy(self._flow_file, mitm_path)
            else:
                with open(mitm_path, "w") as f:
                    for flow in flows:
                        f.write(
                            json.dumps(
                                {
                                    "timestamp": flow.timestamp,
                                    "method": flow.method,
                                    "url": flow.url,
                                    "request_headers": flow.request_headers,
                                    "request_body": flow.request_body,
                                    "status_code": flow.status_code,
                                    "response_headers": flow.response_headers,
                                    "response_body": flow.response_body,
                                }
                            )
                            + "\n"
                        )
            logger.info("export_pcap: wrote %d flows to %s (.mitm fallback)", len(flows), mitm_path)
            return mitm_path
