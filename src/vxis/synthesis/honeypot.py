"""허니팟 생성기 — 취약한 것처럼 보이는 가짜 엔드포인트.

공격자가 접근하면:
1. 성공한 것처럼 가짜 응답 반환
2. 모든 요청/페이로드를 로그에 기록
3. 공격자 IP, User-Agent, 기법 수집
4. 수집된 패턴을 VXIS 학습에 피드백

stdlib만 사용 (Flask 설치 불필요 — 코드를 문자열로 생성).

Usage:
    generator = HoneypotGenerator()
    config = generator.generate_honeypot(exploit)
    print(config.app_code)   # Flask 앱 코드 출력
    print(config.dockerfile) # Dockerfile 출력
"""

from __future__ import annotations

import ast
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .red_vs_blue import VerifiedExploit

logger = logging.getLogger(__name__)

HONEYPOT_LOG_DIR = Path("~/.vxis/honeypot_logs").expanduser()
AGENT_MEMORY_PATH = Path("~/.vxis/agent_memory.json").expanduser()


# ── Data Models ─────────────────────────────────────────────────


@dataclass
class HoneypotConfig:
    """생성된 허니팟 설정 및 코드."""

    app_code: str  # Python Flask 앱 코드 (실행 가능)
    dockerfile: str  # Dockerfile 내용
    deploy_command: str  # 배포 명령어
    log_path: str  # 로그 파일 경로
    description: str  # 허니팟 설명 (한국어)

    def verify_syntax(self) -> bool:
        """생성된 Python 코드가 문법적으로 올바른지 검증한다."""
        try:
            ast.parse(self.app_code)
            return True
        except SyntaxError as exc:
            logger.error("허니팟 코드 문법 오류: %s", exc)
            return False


# ── Fake Response Templates ──────────────────────────────────────


class _FakeResponseTemplates:
    """공격 유형별 가짜 응답 데이터."""

    @staticmethod
    def sqli_response() -> dict[str, Any]:
        """SQLi 성공처럼 보이는 가짜 DB 행."""
        return {
            "status": "success",
            "data": [
                {
                    "id": 1,
                    "username": "admin",
                    "email": "admin@internal.corp",
                    "role": "administrator",
                    "created_at": "2023-01-15T09:23:11Z",
                },
                {
                    "id": 2,
                    "username": "dbuser",
                    "email": "dbuser@internal.corp",
                    "role": "user",
                    "created_at": "2023-03-22T14:05:33Z",
                },
                {
                    "id": 3,
                    "username": "service_account",
                    "email": "svc@internal.corp",
                    "role": "service",
                    "created_at": "2023-06-01T00:00:00Z",
                },
            ],
            "rows_affected": 3,
            "query_time_ms": 12,
        }

    @staticmethod
    def xss_response(payload: str = "") -> dict[str, Any]:
        """XSS 반사된 것처럼 보이는 가짜 응답."""
        return {
            "status": "ok",
            "message": f"검색 결과: {payload}",
            "results": [
                {"title": "Sample Article", "content": f"관련 내용: {payload}"},
            ],
            "total": 1,
        }

    @staticmethod
    def ssrf_response() -> dict[str, Any]:
        """SSRF 성공처럼 보이는 가짜 내부 서비스 응답."""
        return {
            "status": "ok",
            "service": "internal-metadata-service",
            "data": {
                "instance_id": "i-0abc123def456789",
                "region": "ap-northeast-2",
                "private_ip": "10.0.1.42",
                "role": "EC2Role-Production",
                "account_id": "123456789012",
                "credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "Token": "AQoDYXdzEJr//////////...",
                    "Expiration": "2099-12-31T00:00:00Z",
                },
            },
        }

    @staticmethod
    def lfi_response() -> str:
        """LFI 성공처럼 보이는 가짜 /etc/passwd."""
        return (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n"
            "postgres:x:1002:1002:PostgreSQL:/var/lib/postgresql:/bin/bash\n"
        )

    @staticmethod
    def rce_response() -> dict[str, Any]:
        """RCE 성공처럼 보이는 가짜 명령어 실행 결과."""
        return {
            "status": "executed",
            "output": (
                "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
                "Linux honeypot-prod 5.15.0-91-generic #101-Ubuntu SMP\n"
                "total 48\n"
                "drwxr-xr-x  8 root root 4096 Jan 15 09:23 .\n"
                "drwxr-xr-x 23 root root 4096 Jan 15 09:20 ..\n"
                "drwxr-xr-x  3 www-data www-data 4096 Mar 22 14:05 app\n"
            ),
            "exit_code": 0,
            "duration_ms": 38,
        }


# ── Honeypot App Code Generator ─────────────────────────────────


def _generate_flask_app(exploit: VerifiedExploit) -> str:
    """허니팟 Flask 앱 Python 코드를 생성한다."""
    attack = exploit.attack_type.lower()
    path = exploit.affected_component or "/api/data"

    # 공격 유형별 가짜 응답 로직 결정
    fake_response_code = _build_fake_response_code(attack)

    # 허니팟 코드 템플릿 (f-string 안의 중괄호는 이중 이스케이프)
    app_code = f'''\
#!/usr/bin/env python3
"""VXIS 허니팟 — {exploit.title} 공격 추적용 가짜 엔드포인트.

생성 시각: {datetime.now(timezone.utc).isoformat()}
공격 유형: {attack}
대상 경로: {path}

WARNING: 이 코드는 연구/방어 목적으로 생성된 허니팟입니다.
         실제 취약한 서비스가 아닙니다.
"""

import json
import logging
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

LOG_DIR = Path(os.path.expanduser("~/.vxis/honeypot_logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "honeypot_{exploit.finding_id[:8]}.jsonl"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HONEYPOT] %(message)s",
)
logger = logging.getLogger("honeypot")


def _log_request(
    src_ip: str,
    method: str,
    path: str,
    headers: dict,
    payload: str,
    user_agent: str,
) -> None:
    """요청을 JSON Lines 파일에 추가 기록한다."""
    entry = {{
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "method": method,
        "path": path,
        "headers": headers,
        "payload": payload,
        "user_agent": user_agent,
    }}
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\\n")
    logger.info("공격 요청 캡처: %s %s from %s", method, path, src_ip)


def _json_response(handler, status: int, data) -> None:
    """JSON 응답을 전송한다."""
    body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Server", "nginx/1.18.0")  # 가짜 서버 헤더
    handler.send_header("X-Powered-By", "PHP/8.1.0")  # 가짜 기술 스택
    handler.end_headers()
    handler.wfile.write(body)


def _text_response(handler, status: int, text: str) -> None:
    """텍스트 응답을 전송한다."""
    body = text.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Server", "Apache/2.4.54")
    handler.end_headers()
    handler.wfile.write(body)


class HoneypotHandler(BaseHTTPRequestHandler):
    """모든 요청을 로깅하고 가짜 응답을 반환한다."""

    def log_message(self, format_str, *args):
        """BaseHTTPRequestHandler 기본 로그 비활성화."""
        pass

    def _get_headers_dict(self) -> dict:
        return {{k: v for k, v in self.headers.items()}}

    def _get_payload(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="replace")
        parsed = urlparse(self.path)
        return parsed.query

    def _capture(self) -> str:
        """요청 캡처 및 페이로드 반환."""
        src_ip = (
            self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or self.client_address[0]
        )
        payload = self._get_payload()
        _log_request(
            src_ip=src_ip,
            method=self.command,
            path=self.path,
            headers=self._get_headers_dict(),
            payload=payload,
            user_agent=self.headers.get("User-Agent", ""),
        )
        return payload

    def do_GET(self):
        payload = self._capture()
        self._handle(payload)

    def do_POST(self):
        payload = self._capture()
        self._handle(payload)

    def do_PUT(self):
        payload = self._capture()
        self._handle(payload)

    def _handle(self, payload: str) -> None:
        """공격 유형에 따른 가짜 응답 반환."""
{fake_response_code}


def run(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = HTTPServer((host, port), HoneypotHandler)
    logger.info("허니팟 시작: http://%s:%d", host, port)
    logger.info("로그 경로: %s", LOG_FILE)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("허니팟 종료")
        server.server_close()


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run(port=port)
'''

    return app_code


def _build_fake_response_code(attack: str) -> str:
    """공격 유형에 따른 _handle 메서드 본문을 생성한다."""
    indent = "        "  # 8 spaces (class method body)

    handlers: dict[str, str] = {
        "sqli": (
            f"{indent}# SQL Injection — 가짜 DB 행 반환\n"
            f"{indent}data = {{\n"
            f'{indent}    "status": "success",\n'
            f'{indent}    "data": [\n'
            f'{indent}        {{"id": 1, "username": "admin", "email": "admin@internal.corp", "role": "administrator"}},\n'
            f'{indent}        {{"id": 2, "username": "dbuser", "email": "dbuser@internal.corp", "role": "user"}},\n'
            f"{indent}    ],\n"
            f'{indent}    "rows_affected": 2,\n'
            f"{indent}}}\n"
            f"{indent}_json_response(self, 200, data)"
        ),
        "xss": (
            f"{indent}# XSS — 페이로드 반사된 것처럼 가짜 응답\n"
            f'{indent}safe_payload = payload[:200].replace("<", "&lt;").replace(">", "&gt;")\n'
            f"{indent}data = {{\n"
            f'{indent}    "status": "ok",\n'
            f'{indent}    "message": f"검색 결과: {{safe_payload}}",\n'
            f'{indent}    "results": [{{"title": "Article", "content": f"내용: {{safe_payload}}"}}],\n'
            f"{indent}}}\n"
            f"{indent}_json_response(self, 200, data)"
        ),
        "ssrf": (
            f"{indent}# SSRF — 가짜 AWS 메타데이터 응답\n"
            f"{indent}data = {{\n"
            f'{indent}    "status": "ok",\n'
            f'{indent}    "service": "internal-metadata-service",\n'
            f'{indent}    "data": {{\n'
            f'{indent}        "instance_id": "i-0abc123def456789",\n'
            f'{indent}        "private_ip": "10.0.1.42",\n'
            f'{indent}        "credentials": {{\n'
            f'{indent}            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",\n'
            f'{indent}            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
            f'{indent}            "Token": "AQoDYXdzEJr...",\n'
            f"{indent}        }},\n"
            f"{indent}    }},\n"
            f"{indent}}}\n"
            f"{indent}_json_response(self, 200, data)"
        ),
        "lfi": (
            f"{indent}# LFI — 가짜 /etc/passwd 반환\n"
            f"{indent}fake_passwd = (\n"
            f'{indent}    "root:x:0:0:root:/root:/bin/bash\\n"\n'
            f'{indent}    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\\n"\n'
            f'{indent}    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\\n"\n'
            f'{indent}    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\\n"\n'
            f'{indent}    "deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash\\n"\n'
            f"{indent})\n"
            f"{indent}_text_response(self, 200, fake_passwd)"
        ),
        "rce": (
            f"{indent}# RCE — 가짜 명령어 실행 결과\n"
            f"{indent}data = {{\n"
            f'{indent}    "status": "executed",\n'
            f'{indent}    "output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\\n",\n'
            f'{indent}    "exit_code": 0,\n'
            f'{indent}    "duration_ms": 42,\n'
            f"{indent}}}\n"
            f"{indent}_json_response(self, 200, data)"
        ),
    }

    # 기본: 공격 유형 불명 시 일반 성공 응답
    default = (
        f"{indent}# 일반 가짜 성공 응답\n"
        f'{indent}data = {{"status": "ok", "message": "요청이 처리되었습니다.", "code": 200}}\n'
        f"{indent}_json_response(self, 200, data)"
    )

    return handlers.get(attack, default)


# ── Honeypot Generator ───────────────────────────────────────────


class HoneypotGenerator:
    """취약한 엔드포인트를 모방하는 허니팟을 생성한다.

    Usage:
        generator = HoneypotGenerator()
        config = generator.generate_honeypot(exploit)
        if config.verify_syntax():
            print(config.app_code)
    """

    def generate_honeypot(self, exploit: VerifiedExploit) -> HoneypotConfig:
        """허니팟 Flask 앱 코드와 Dockerfile을 생성한다."""
        logger.info(
            "허니팟 생성 시작: %s (%s)",
            exploit.title,
            exploit.attack_type,
        )

        app_code = _generate_flask_app(exploit)
        dockerfile = self._generate_dockerfile(exploit)
        log_path = str(HONEYPOT_LOG_DIR / f"honeypot_{exploit.finding_id[:8]}.jsonl")
        deploy_command = self._generate_deploy_command(exploit)
        description = self._generate_description(exploit)

        config = HoneypotConfig(
            app_code=app_code,
            dockerfile=dockerfile,
            deploy_command=deploy_command,
            log_path=log_path,
            description=description,
        )

        # 문법 검증 (항상 수행)
        if not config.verify_syntax():
            logger.error("허니팟 코드 문법 오류 — 기본 코드로 대체")
            config.app_code = self._fallback_app_code(exploit)

        logger.info("허니팟 생성 완료 (문법 검증 통과)")
        return config

    def _generate_dockerfile(self, exploit: VerifiedExploit) -> str:
        """허니팟 컨테이너용 Dockerfile 생성."""
        return f"""\
# VXIS 허니팟 Dockerfile — {exploit.attack_type} 추적용
# 생성: {datetime.now(timezone.utc).strftime("%Y-%m-%d")}

FROM python:3.11-slim

LABEL maintainer="vxis-honeypot"
LABEL attack_type="{exploit.attack_type}"
LABEL finding_id="{exploit.finding_id}"

WORKDIR /honeypot

# 비루트 사용자로 실행 (보안)
RUN useradd -m -u 1001 honeypot

# 허니팟 스크립트 복사
COPY honeypot_app.py /honeypot/honeypot_app.py

# 로그 디렉토리
RUN mkdir -p /var/log/vxis-honeypot \\
    && chown honeypot:honeypot /var/log/vxis-honeypot

USER honeypot

EXPOSE 8080

# 헬스체크
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s \\
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/')" \\
    || exit 1

CMD ["python3", "honeypot_app.py", "8080"]
"""

    def _generate_deploy_command(self, exploit: VerifiedExploit) -> str:
        """허니팟 배포 명령어 생성."""
        safe_id = exploit.finding_id[:8].replace("-", "")
        return (
            f"# 1. 허니팟 빌드\n"
            f"docker build -t vxis-honeypot-{safe_id} .\n\n"
            f"# 2. 허니팟 실행\n"
            f"docker run -d \\\n"
            f"  --name honeypot-{safe_id} \\\n"
            f"  -p 8080:8080 \\\n"
            f"  -v ~/.vxis/honeypot_logs:/var/log/vxis-honeypot \\\n"
            f"  --memory=256m \\\n"
            f"  --cpus=0.5 \\\n"
            f"  --read-only \\\n"
            f"  --security-opt no-new-privileges \\\n"
            f"  vxis-honeypot-{safe_id}\n\n"
            f"# 3. 실시간 로그 모니터링\n"
            f"tail -f ~/.vxis/honeypot_logs/honeypot_{safe_id}.jsonl | python3 -m json.tool\n"
        )

    def _generate_description(self, exploit: VerifiedExploit) -> str:
        """허니팟 설명 (한국어)."""
        attack = exploit.attack_type.upper()
        path = exploit.affected_component or "/api/data"
        return (
            f"[{attack} 허니팟] '{path}' 경로를 모방하는 가짜 엔드포인트. "
            f"공격자가 접근하면 성공한 것처럼 가짜 응답을 반환하고 "
            f"모든 요청(IP, 헤더, 페이로드)을 JSONL 형식으로 기록합니다. "
            f"수집된 데이터는 VXIS 학습에 피드백됩니다."
        )

    def _fallback_app_code(self, exploit: VerifiedExploit) -> str:
        """문법 오류 발생 시 안전한 최소 허니팟 코드."""
        return (
            "#!/usr/bin/env python3\n"
            '"""VXIS 허니팟 — 최소 구현."""\n\n'
            "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
            "import json\n\n"
            "class Handler(BaseHTTPRequestHandler):\n"
            "    def do_GET(self):\n"
            '        body = json.dumps({"status": "ok"}).encode()\n'
            "        self.send_response(200)\n"
            '        self.send_header("Content-Type", "application/json")\n'
            '        self.send_header("Content-Length", str(len(body)))\n'
            "        self.end_headers()\n"
            "        self.wfile.write(body)\n"
            "    do_POST = do_GET\n\n"
            'if __name__ == "__main__":\n'
            '    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()\n'
        )

    def generate_fake_responses(self, attack_type: str) -> dict[str, Any]:
        """공격 유형별 가짜 응답 데이터를 반환한다."""
        attack = attack_type.lower()
        templates = _FakeResponseTemplates

        response_map: dict[str, Any] = {
            "sqli": templates.sqli_response(),
            "sql_injection": templates.sqli_response(),
            "sql injection": templates.sqli_response(),
            "xss": templates.xss_response(),
            "cross-site scripting": templates.xss_response(),
            "ssrf": templates.ssrf_response(),
            "server-side request forgery": templates.ssrf_response(),
            "lfi": {"content": templates.lfi_response(), "type": "text/plain"},
            "local file inclusion": {"content": templates.lfi_response(), "type": "text/plain"},
            "path traversal": {"content": templates.lfi_response(), "type": "text/plain"},
            "rce": templates.rce_response(),
            "remote code execution": templates.rce_response(),
            "command injection": templates.rce_response(),
        }

        return response_map.get(attack, {"status": "ok", "message": "처리 완료"})


# ── Honeypot Logger ──────────────────────────────────────────────


class HoneypotLogger:
    """허니팟 로그를 읽고 분석하는 클래스.

    로그 형식: JSONL (JSON Lines)
    위치: ~/.vxis/honeypot_logs/*.jsonl
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        self._log_dir = log_dir or HONEYPOT_LOG_DIR

    def _iter_log_entries(self) -> list[dict[str, Any]]:
        """로그 디렉토리의 모든 JSONL 파일에서 엔트리를 읽는다."""
        entries: list[dict[str, Any]] = []
        if not self._log_dir.exists():
            return entries

        for log_file in sorted(self._log_dir.glob("*.jsonl")):
            try:
                with open(log_file, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError as exc:
                logger.warning("로그 파일 읽기 실패 %s: %s", log_file, exc)

        return entries

    def append_log(
        self,
        src_ip: str,
        method: str,
        path: str,
        headers: dict[str, str],
        payload: str,
        user_agent: str,
        log_file: Path | None = None,
    ) -> None:
        """단일 요청 로그를 파일에 추가한다 (append-only)."""
        self._log_dir.mkdir(parents=True, exist_ok=True)
        target = log_file or (self._log_dir / "honeypot_default.jsonl")

        entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": src_ip,
            "method": method,
            "path": path,
            "headers": headers,
            "payload": payload,
            "user_agent": user_agent,
        }

        with open(target, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def analyze_logs(self) -> dict[str, Any]:
        """수집된 로그에서 공격자 패턴을 분석한다.

        반환 구조:
        {
          "total_requests": int,
          "unique_ips": list[str],
          "top_ips": list[{ip, count}],
          "top_payloads": list[str],
          "top_user_agents": list[str],
          "attack_techniques": list[str],  # 탐지된 공격 기법
          "timeline": {hour: count},       # 시간대별 분포
          "paths_targeted": list[str],
        }
        """
        entries = self._iter_log_entries()

        if not entries:
            return {
                "total_requests": 0,
                "unique_ips": [],
                "top_ips": [],
                "top_payloads": [],
                "top_user_agents": [],
                "attack_techniques": [],
                "timeline": {},
                "paths_targeted": [],
            }

        # IP 집계
        ip_counts: dict[str, int] = {}
        for e in entries:
            ip = e.get("src_ip", "unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        top_ips = sorted(
            [{"ip": ip, "count": c} for ip, c in ip_counts.items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:10]

        # 페이로드 집계
        payload_counts: dict[str, int] = {}
        for e in entries:
            payload = e.get("payload", "")[:500]
            if payload:
                payload_counts[payload] = payload_counts.get(payload, 0) + 1

        top_payloads = [
            p for p, _ in sorted(payload_counts.items(), key=lambda x: x[1], reverse=True)
        ][:20]

        # User-Agent 집계
        ua_counts: dict[str, int] = {}
        for e in entries:
            ua = e.get("user_agent", "unknown")
            ua_counts[ua] = ua_counts.get(ua, 0) + 1

        top_user_agents = [
            ua for ua, _ in sorted(ua_counts.items(), key=lambda x: x[1], reverse=True)
        ][:10]

        # 공격 기법 탐지 (페이로드 패턴 분석)
        techniques = _detect_attack_techniques(top_payloads)

        # 시간대별 분포
        timeline: dict[str, int] = {}
        for e in entries:
            ts = e.get("timestamp", "")
            if len(ts) >= 13:
                hour = ts[:13]  # "2024-01-15T09"
                timeline[hour] = timeline.get(hour, 0) + 1

        # 타겟 경로
        path_counts: dict[str, int] = {}
        for e in entries:
            path = e.get("path", "/")
            path_counts[path] = path_counts.get(path, 0) + 1

        paths_targeted = [
            p for p, _ in sorted(path_counts.items(), key=lambda x: x[1], reverse=True)
        ][:10]

        return {
            "total_requests": len(entries),
            "unique_ips": list(ip_counts.keys()),
            "top_ips": top_ips,
            "top_payloads": top_payloads,
            "top_user_agents": top_user_agents,
            "attack_techniques": techniques,
            "timeline": timeline,
            "paths_targeted": paths_targeted,
        }


def _detect_attack_techniques(payloads: list[str]) -> list[str]:
    """페이로드 목록에서 공격 기법을 탐지한다."""
    import re

    technique_patterns: list[tuple[str, str]] = [
        ("SQL Injection (UNION)", r"(?i)union\s+select"),
        ("SQL Injection (OR 1=1)", r"(?i)or\s+1\s*=\s*1"),
        ("SQL Injection (Blind SLEEP)", r"(?i)sleep\s*\("),
        ("XSS (script tag)", r"(?i)<script"),
        ("XSS (event handler)", r"(?i)on\w+\s*="),
        ("XSS (javascript:)", r"(?i)javascript:"),
        ("SSRF (localhost)", r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0)"),
        ("SSRF (metadata)", r"(?i)169\.254\.169\.254"),
        ("SSRF (IPv6)", r"\[::1\]|\[0:0:0:0:0:0:0:1\]"),
        ("LFI (path traversal)", r"\.\./|%2e%2e"),
        ("RCE (shell metachar)", r"[;|`]|\$\("),
        ("RCE (command)", r"(?i)(wget|curl|nc|bash|sh)\s"),
        ("Encoding bypass (double URL)", r"%25[0-9a-fA-F]{2}"),
        ("Encoding bypass (hex)", r"\\x[0-9a-fA-F]{2}"),
    ]

    detected: list[str] = []
    for payload in payloads:
        for technique_name, pattern in technique_patterns:
            if re.search(pattern, payload) and technique_name not in detected:
                detected.append(technique_name)

    return detected


# ── VXIS Feedback ────────────────────────────────────────────────


def feed_back_to_vxis(log_analysis: dict[str, Any]) -> None:
    """허니팟 분석 결과를 VXIS 에이전트 메모리에 피드백한다.

    1. agent_memory.json에 새 공격 패턴 추가
    2. 캡처된 페이로드로 새 WAF 규칙 생성
    3. 수집된 공격으로 nuclei 템플릿 생성 (향후 확장)
    """
    if not log_analysis.get("total_requests"):
        logger.info("피드백할 로그 데이터 없음")
        return

    AGENT_MEMORY_PATH.parent.mkdir(parents=True, exist_ok=True)

    # 기존 메모리 로드
    existing_memory: dict[str, Any] = {}
    if AGENT_MEMORY_PATH.exists():
        try:
            with open(AGENT_MEMORY_PATH, encoding="utf-8") as f:
                existing_memory = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("agent_memory.json 로드 실패: %s", exc)

    # 허니팟 데이터 섹션 업데이트
    honeypot_data = existing_memory.get(
        "honeypot_intelligence",
        {
            "attacker_ips": [],
            "captured_payloads": [],
            "attack_techniques": [],
            "waf_rules_generated": [],
            "last_updated": "",
        },
    )

    # 공격자 IP 추가 (중복 제거)
    existing_ips: set[str] = set(honeypot_data.get("attacker_ips", []))
    for ip_entry in log_analysis.get("top_ips", []):
        existing_ips.add(ip_entry["ip"])
    honeypot_data["attacker_ips"] = list(existing_ips)[:500]  # 최대 500개

    # 페이로드 추가 (중복 제거)
    existing_payloads: set[str] = set(honeypot_data.get("captured_payloads", []))
    for payload in log_analysis.get("top_payloads", []):
        existing_payloads.add(payload)
    honeypot_data["captured_payloads"] = list(existing_payloads)[:1000]  # 최대 1000개

    # 공격 기법 추가
    existing_techniques: set[str] = set(honeypot_data.get("attack_techniques", []))
    for technique in log_analysis.get("attack_techniques", []):
        existing_techniques.add(technique)
    honeypot_data["attack_techniques"] = list(existing_techniques)

    # 수집된 페이로드로 WAF 규칙 생성
    new_rules = _generate_waf_rules_from_payloads(log_analysis.get("top_payloads", [])[:20])
    existing_waf_rules: set[str] = set(honeypot_data.get("waf_rules_generated", []))
    for rule in new_rules:
        existing_waf_rules.add(rule)
    honeypot_data["waf_rules_generated"] = list(existing_waf_rules)[:200]

    honeypot_data["last_updated"] = datetime.now(timezone.utc).isoformat()
    honeypot_data["total_captured"] = log_analysis.get("total_requests", 0)

    existing_memory["honeypot_intelligence"] = honeypot_data

    # 저장
    try:
        with open(AGENT_MEMORY_PATH, "w", encoding="utf-8") as f:
            json.dump(existing_memory, f, ensure_ascii=False, indent=2)
        logger.info(
            "VXIS 메모리 업데이트 완료: IP %d개, 페이로드 %d개, 기법 %d개",
            len(honeypot_data["attacker_ips"]),
            len(honeypot_data["captured_payloads"]),
            len(honeypot_data["attack_techniques"]),
        )
    except OSError as exc:
        logger.error("agent_memory.json 저장 실패: %s", exc)


def _generate_waf_rules_from_payloads(payloads: list[str]) -> list[str]:
    """캡처된 페이로드에서 ModSecurity WAF 규칙을 생성한다."""
    import re

    rules: list[str] = []
    for i, payload in enumerate(payloads, 1):
        if not payload or len(payload) < 3:
            continue

        # 페이로드에서 핵심 패턴 추출
        escaped = re.escape(payload[:100])
        rule = (
            f'SecRule ARGS|REQUEST_BODY "@rx {escaped}" '
            f'"id:9{i:05d},phase:2,deny,status:403,'
            f"msg:'VXIS Honeypot: Captured payload blocked'"
            f'"'
        )
        rules.append(rule)

    return rules
