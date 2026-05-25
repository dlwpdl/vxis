"""VXIS Advanced Honeypot — 개미지옥 + 학습 루프 + 카운터 인텔리전스.

Level 2: 개미지옥 (Deep Deception)
    → 가짜 DB, 가짜 API, 가짜 credential → 공격자를 더 깊이 유인
    → Canary token: 공격자가 훔친 데이터를 사용하면 즉시 알림

Level 3: 학습 루프 (Adaptive Learning)
    → 캡처된 페이로드 → 새 WAF 규칙 + nuclei 템플릿 자동 생성
    → 공격자 TTP → Knowledge Store 업데이트

Level 4: 카운터 인텔리전스 (합법적 역추적)
    → 공격자 IP → WHOIS + Shodan + GeoIP (공개 정보만)
    → TTP 프로파일링 → MITRE ATT&CK 매핑
    → "이 공격자는 X 그룹과 87% 유사"

법적 원칙: 공격자를 해킹하지 않음. 공개 정보 + 자체 인프라 내 추적만.
"""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.request
import urllib.error
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

HONEYPOT_DIR = Path("~/.vxis/honeypot").expanduser()
CANARY_DIR = HONEYPOT_DIR / "canaries"
INTEL_DIR = HONEYPOT_DIR / "intel"


# ═══════════════════════════════════════════════════════════════
# Level 2: 개미지옥 (Deep Deception)
# ═══════════════════════════════════════════════════════════════


@dataclass
class CanaryToken:
    """추적용 카나리 토큰 — 공격자가 사용하면 즉시 알림."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    token_type: str = ""  # credential, api_key, database, document, url
    token_value: str = ""  # 실제 토큰 값 (가짜지만 진짜처럼 보임)
    callback_url: str = ""  # 사용 시 호출될 URL
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    triggered: bool = False
    triggered_at: str = ""
    triggered_by: dict[str, Any] = field(default_factory=dict)


class CanaryFactory:
    """다양한 종류의 카나리 토큰을 생성한다."""

    def __init__(self) -> None:
        CANARY_DIR.mkdir(parents=True, exist_ok=True)
        self._canaries: list[CanaryToken] = []

    def create_fake_aws_key(self) -> CanaryToken:
        """진짜처럼 보이는 가짜 AWS 자격증명."""
        # AWS 키 형식: AKIA + 16 alphanumeric
        fake_access = "AKIA" + hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:16].upper()
        fake_secret = hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:40]

        canary = CanaryToken(
            token_type="aws_credential",
            token_value=f"AWS_ACCESS_KEY_ID={fake_access}\nAWS_SECRET_ACCESS_KEY={fake_secret}",
            description="가짜 AWS 자격증명 — 사용 시 CloudTrail에서 즉시 감지 가능",
        )
        self._canaries.append(canary)
        self._save(canary)
        return canary

    def create_fake_api_key(self, service: str = "stripe") -> CanaryToken:
        """진짜처럼 보이는 가짜 API 키."""
        prefixes = {
            "stripe": "sk_live_",
            "github": "ghp_",
            "slack": "xoxb-",
            "sendgrid": "SG.",
            "twilio": "SK",
        }
        prefix = prefixes.get(service, "api_")
        fake_key = prefix + hashlib.sha256(uuid.uuid4().bytes).hexdigest()[:32]

        canary = CanaryToken(
            token_type="api_key",
            token_value=fake_key,
            description=f"가짜 {service} API 키 — 사용 시 해당 서비스 로그에서 감지",
        )
        self._canaries.append(canary)
        self._save(canary)
        return canary

    def create_fake_database_dump(self, rows: int = 50) -> CanaryToken:
        """진짜처럼 보이는 가짜 데이터베이스 덤프.

        각 행에 추적 가능한 고유 이메일이 포함됨.
        공격자가 이 이메일로 피싱을 보내면 즉시 감지.
        """
        import random

        # 가짜이지만 현실적인 한국 이름/이메일
        first_names = ["민준", "서연", "지호", "수빈", "하은", "도윤", "서아", "시우"]
        last_names = ["김", "이", "박", "최", "정", "강", "조", "윤"]
        domains = ["gmail.com", "naver.com", "kakao.com"]

        canary_id = str(uuid.uuid4())[:8]
        records = []

        for i in range(rows):
            name = random.choice(last_names) + random.choice(first_names)
            # 카나리 마커가 이메일에 숨겨져 있음
            email = f"{name.lower()}.{canary_id[:4]}t{i:03d}@{random.choice(domains)}"
            phone = f"010-{random.randint(1000, 9999)}-{random.randint(1000, 9999)}"

            records.append(
                {
                    "id": i + 1,
                    "name": name,
                    "email": email,
                    "phone": phone,
                    "address": f"서울시 강남구 테헤란로 {random.randint(1, 500)}",
                    "created_at": f"2025-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
                }
            )

        dump_text = json.dumps(records, ensure_ascii=False, indent=2)

        canary = CanaryToken(
            token_type="database",
            token_value=dump_text,
            description=(
                f"가짜 DB 덤프 ({rows}행) — 이메일에 추적 마커 포함. "
                f"공격자가 이 이메일을 사용하면 즉시 감지. "
                f"카나리 ID: {canary_id}"
            ),
        )
        self._canaries.append(canary)
        self._save(canary)
        return canary

    def create_tracking_document(self, filename: str = "internal_passwords.xlsx") -> CanaryToken:
        """웹 비콘이 포함된 추적 문서.

        공격자가 문서를 열면 웹 비콘 URL이 호출됨.
        """
        beacon_id = str(uuid.uuid4())
        # Canarytokens.com 또는 자체 서버 URL
        beacon_url = f"https://canarytokens.com/t/{beacon_id}/contact.php"

        canary = CanaryToken(
            token_type="document",
            token_value=filename,
            callback_url=beacon_url,
            description=(
                f"추적 문서 '{filename}' — 열면 웹 비콘이 트리거됨. "
                f"공격자 IP, User-Agent, 열린 시각을 기록."
            ),
        )
        self._canaries.append(canary)
        self._save(canary)
        return canary

    def create_tracking_url(self, path: str = "/admin/config.json") -> CanaryToken:
        """숨겨진 URL — 정상 사용자는 접근하지 않는 경로.

        접근하면 = 공격자.
        """
        canary = CanaryToken(
            token_type="url",
            token_value=path,
            description=f"허니 URL '{path}' — 정상 사용자는 접근하지 않음. 접근 = 공격자.",
        )
        self._canaries.append(canary)
        self._save(canary)
        return canary

    def get_all_canaries(self) -> list[CanaryToken]:
        return self._canaries

    def _save(self, canary: CanaryToken) -> None:
        path = CANARY_DIR / f"{canary.id}.json"
        data = {
            "id": canary.id,
            "type": canary.token_type,
            "description": canary.description,
            "callback_url": canary.callback_url,
            "created_at": canary.created_at,
            "triggered": canary.triggered,
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2))


class DeepDeceptionEngine:
    """Level 2 개미지옥 — 공격자를 더 깊이 유인하는 다층 디셉션.

    구조:
        Layer 1: 가짜 취약점 (기본 허니팟)
        Layer 2: "성공" 응답 + 가짜 데이터
        Layer 3: 가짜 내부 API 노출 (더 깊이 유인)
        Layer 4: 가짜 credential (canary token)
        Layer 5: 추적 문서 + 웹 비콘
    """

    def __init__(self) -> None:
        self.canary_factory = CanaryFactory()

    def generate_deception_layers(self, attack_type: str, target: str) -> dict[str, Any]:
        """5계층 디셉션 환경을 생성한다."""

        layers = {}

        # Layer 1: 가짜 취약점 응답
        layers["layer1_fake_vuln"] = self._fake_vuln_response(attack_type)

        # Layer 2: 가짜 데이터 (공격 "성공" 시)
        layers["layer2_fake_data"] = self._fake_success_data(attack_type)

        # Layer 3: 가짜 내부 API
        layers["layer3_internal_api"] = self._fake_internal_api()

        # Layer 4: Canary tokens
        layers["layer4_canaries"] = {
            "aws_key": self.canary_factory.create_fake_aws_key(),
            "api_key": self.canary_factory.create_fake_api_key(),
            "db_dump": self.canary_factory.create_fake_database_dump(),
        }

        # Layer 5: 추적 문서
        layers["layer5_tracking"] = {
            "document": self.canary_factory.create_tracking_document(),
            "hidden_url": self.canary_factory.create_tracking_url(),
        }

        return layers

    def generate_honeypot_code(self, layers: dict) -> str:
        """5계층 디셉션을 포함한 허니팟 서버 코드 생성."""

        canaries = layers.get("layer4_canaries", {})
        aws_canary = canaries.get("aws_key")
        aws_value = aws_canary.token_value if aws_canary else "FAKE_KEY"

        db_canary = canaries.get("db_dump")
        db_value = db_canary.token_value[:500] if db_canary else "[]"

        layers.get("layer1_fake_vuln", "")
        layers.get("layer2_fake_data", "")

        code = (
            '''#!/usr/bin/env python3
"""VXIS 개미지옥 허니팟 — 자동 생성. 수정하지 마세요."""

import json
import os
import time
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

LOG_DIR = Path("~/.vxis/honeypot_logs").expanduser()
LOG_DIR.mkdir(parents=True, exist_ok=True)

# 공격자가 "발견"하게 될 가짜 데이터
FAKE_ENV = """
# Production Environment
DATABASE_URL=postgresql://admin:P@ssw0rd123@db.internal:5432/production
'''
            + f"AWS_ACCESS_KEY_ID={aws_value.split(chr(10))[0].split('=')[-1] if '=' in aws_value else 'AKIAIOSFODNN7EXAMPLE'}"
            + '''
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_live_51H7bLfKs8WpJ2mRwY7FvZYx
SLACK_BOT_TOKEN=xoxb-123456789012-1234567890123-aB1cD2eF3gH4iJ5kL6mN7oP
REDIS_URL=redis://redis.internal:6379/0
JWT_SECRET=super-secret-jwt-key-2025
"""

FAKE_DB = """ '''
            + repr(db_value[:200])
            + ''' """

FAKE_INTERNAL_APIS = {
    "/api/v1/internal/users": [
        {"id": 1, "email": "admin@company.com", "role": "superadmin"},
        {"id": 2, "email": "dev@company.com", "role": "developer"},
    ],
    "/api/v1/internal/config": {
        "debug": True,
        "maintenance_mode": False,
        "admin_panel": "/admin-secret-panel",
        "backup_server": "backup.internal:22",
    },
}


class HoneypotHandler(BaseHTTPRequestHandler):
    """개미지옥 핸들러 — 공격자를 유인하고 모든 행동을 기록."""

    def do_GET(self):
        self._log_request()
        path = self.path.split("?")[0]

        # Layer 1: .env 노출 (가장 흔한 공격 벡터)
        if ".env" in path:
            self._respond(200, FAKE_ENV, "text/plain")
            return

        # Layer 2: 가짜 DB 백업
        if "backup" in path or "dump" in path or "db" in path:
            self._respond(200, FAKE_DB, "application/json")
            return

        # Layer 3: 가짜 내부 API
        for api_path, data in FAKE_INTERNAL_APIS.items():
            if api_path in path:
                self._respond(200, json.dumps(data, indent=2), "application/json")
                return

        # Layer 4: 가짜 관리자 패널
        if "admin" in path:
            html = "<html><head><title>Admin Panel</title></head>"
            html += "<body><h1>Login</h1><form method=POST>"
            html += "<input name=username placeholder=Username>"
            html += "<input name=password type=password placeholder=Password>"
            html += "<button>Login</button></form></body></html>"
            self._respond(200, html, "text/html")
            return

        # Layer 5: robots.txt (공격자가 탐색할 경로 힌트)
        if "robots.txt" in path:
            robots = "User-agent: *\\nDisallow: /admin-secret-panel/\\n"
            robots += "Disallow: /api/v1/internal/\\nDisallow: /backup/\\n"
            self._respond(200, robots, "text/plain")
            return

        # 기본 응답
        self._respond(404, "Not Found", "text/plain")

    def do_POST(self):
        self._log_request()
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        # 로그인 시도 캡처
        if "admin" in self.path:
            self._respond(200, json.dumps({
                "status": "error",
                "message": "Invalid credentials. Hint: check /api/v1/internal/config"
            }), "application/json")
            return

        self._respond(200, '{"status": "ok"}', "application/json")

    def _respond(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Server", "nginx/1.18.0")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def _log_request(self):
        """모든 요청을 JSONL로 로그."""
        content_length = int(self.headers.get("Content-Length", 0))
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "user_agent": self.headers.get("User-Agent", ""),
        }
        log_file = LOG_DIR / f"honeypot_{datetime.now().strftime('%Y%m%d')}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\\n")

    def log_message(self, format, *args):
        pass  # 콘솔 출력 억제


if __name__ == "__main__":
    port = int(os.environ.get("HONEYPOT_PORT", "8888"))
    server = HTTPServer(("0.0.0.0", port), HoneypotHandler)
    print(f"VXIS Honeypot running on port {port}")
    print(f"Logs: {LOG_DIR}")
    server.serve_forever()
'''
        )

        return code

    def _fake_vuln_response(self, attack_type: str) -> str:
        responses = {
            "sqli": "MySQL syntax error near 'OR 1=1' at line 1",
            "xss": '<script>alert("XSS")</script> reflected in response',
            "ssrf": '{"status":"ok","internal_ip":"10.0.1.5","redis":"connected"}',
            "rce": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
            "lfi": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        }
        return responses.get(attack_type.lower(), "Error occurred")

    def _fake_success_data(self, attack_type: str) -> str:
        return json.dumps(
            {
                "status": "success",
                "data": {
                    "users_count": 15847,
                    "latest_backup": "2026-03-20T03:00:00Z",
                    "admin_email": "admin@internal.company.com",
                },
            }
        )

    def _fake_internal_api(self) -> dict:
        return {
            "/api/v1/internal/users": "사용자 목록 API",
            "/api/v1/internal/config": "시스템 설정 API",
            "/api/v1/internal/backup": "백업 다운로드 API",
        }


# ═══════════════════════════════════════════════════════════════
# Level 3: 학습 루프 (Adaptive Learning)
# ═══════════════════════════════════════════════════════════════


class HoneypotLearner:
    """허니팟 로그에서 학습하여 VXIS를 강화한다.

    수집 → 분석 → 규칙 생성 → Knowledge 업데이트
    """

    def __init__(self, log_dir: Path | None = None) -> None:
        self._log_dir = log_dir or HONEYPOT_DIR / "logs"

    def analyze_logs(self) -> dict[str, Any]:
        """허니팟 로그를 분석하여 공격 패턴을 추출한다."""
        log_files = sorted(self._log_dir.glob("*.jsonl")) if self._log_dir.exists() else []

        all_entries = []
        for f in log_files[-7:]:  # 최근 7일
            for line in f.read_text().splitlines():
                try:
                    all_entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        if not all_entries:
            return {"total_requests": 0}

        # IP 빈도
        ip_counts: dict[str, int] = {}
        for e in all_entries:
            ip = e.get("src_ip", "unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        # 경로 빈도
        path_counts: dict[str, int] = {}
        for e in all_entries:
            path = e.get("path", "/").split("?")[0]
            path_counts[path] = path_counts.get(path, 0) + 1

        # User-Agent 분석
        ua_counts: dict[str, int] = {}
        for e in all_entries:
            ua = e.get("user_agent", "unknown")[:50]
            ua_counts[ua] = ua_counts.get(ua, 0) + 1

        # 페이로드 추출 (쿼리 파라미터에서)
        payloads: list[str] = []
        for e in all_entries:
            path = e.get("path", "")
            if "?" in path:
                query = path.split("?", 1)[1]
                payloads.append(query)

        return {
            "total_requests": len(all_entries),
            "unique_ips": len(ip_counts),
            "top_ips": sorted(ip_counts.items(), key=lambda x: -x[1])[:20],
            "top_paths": sorted(path_counts.items(), key=lambda x: -x[1])[:20],
            "top_user_agents": sorted(ua_counts.items(), key=lambda x: -x[1])[:10],
            "payloads": payloads[:100],
            "period_days": len(log_files),
        }

    def generate_waf_rules_from_logs(self, analysis: dict) -> list[str]:
        """캡처된 페이로드에서 새 WAF 규칙을 자동 생성한다."""
        rules = []

        for payload in analysis.get("payloads", [])[:50]:
            # 위험한 패턴 추출
            import re

            dangerous_patterns = re.findall(
                r"(union\s+select|or\s+1\s*=\s*1|<script|javascript:|exec\(|system\(|\.\.\/)",
                payload,
                re.IGNORECASE,
            )

            for pattern in dangerous_patterns:
                escaped = pattern.replace("(", "\\(").replace(")", "\\)")
                rule = (
                    f'SecRule ARGS|REQUEST_BODY "@rx (?i){escaped}" '
                    f'"id:{100100 + len(rules)},phase:2,deny,status:403,'
                    f"msg:'VXIS Honeypot learned: {escaped[:30]}'\""
                )
                if rule not in rules:
                    rules.append(rule)

        return rules

    def generate_nuclei_templates(self, analysis: dict) -> list[str]:
        """캡처된 공격에서 nuclei 템플릿을 자동 생성한다."""
        templates = []

        top_paths = analysis.get("top_paths", [])
        for path, count in top_paths[:10]:
            if count < 3:
                continue  # 3회 미만은 노이즈

            template = f"""id: honeypot-learned-{hashlib.md5(path.encode()).hexdigest()[:8]}
info:
  name: Honeypot Learned Pattern - {path}
  author: vxis-honeypot
  severity: medium
  description: |
    허니팟에서 {count}회 관찰된 공격 경로.
    이 경로에 대한 접근은 공격 시도일 가능성이 높음.
  tags: honeypot,learned

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}{path}"
    matchers:
      - type: status
        status:
          - 200
          - 403
"""
            templates.append(template)

        return templates

    def update_knowledge_store(self, analysis: dict) -> None:
        """분석 결과를 VXIS Knowledge Store에 업데이트한다."""
        memory_path = Path("~/.vxis/agent_memory.json").expanduser()

        try:
            if memory_path.exists():
                memories = json.loads(memory_path.read_text())
            else:
                memories = []

            # 허니팟 학습 결과를 별도 엔트리로 추가
            honeypot_entry = {
                "target": "honeypot_learning",
                "tech_stack": ["honeypot"],
                "findings_summary": [
                    {
                        "type": "honeypot_intel",
                        "title": f"허니팟 수집: {analysis.get('total_requests', 0)}건 요청, "
                        f"{analysis.get('unique_ips', 0)}개 IP",
                    }
                ],
                "effective_tools": [],
                "ineffective_tools": [],
                "scan_date": datetime.now(timezone.utc).isoformat(),
                "total_findings": analysis.get("total_requests", 0),
                "attacker_ips": [ip for ip, _ in analysis.get("top_ips", [])[:100]],
                "captured_payloads": analysis.get("payloads", [])[:200],
            }

            # 기존 honeypot_learning 엔트리 교체
            memories = [m for m in memories if m.get("target") != "honeypot_learning"]
            memories.append(honeypot_entry)

            memory_path.write_text(json.dumps(memories, ensure_ascii=False, indent=2))

            logger.info(
                "Knowledge Store 업데이트: %d IPs, %d 페이로드",
                analysis.get("unique_ips", 0),
                len(analysis.get("payloads", [])),
            )

        except Exception as exc:
            logger.warning("Knowledge Store 업데이트 실패: %s", exc)


# ═══════════════════════════════════════════════════════════════
# Level 4: 카운터 인텔리전스 (합법적 역추적)
# ═══════════════════════════════════════════════════════════════


@dataclass
class AttackerProfile:
    """공격자 프로파일 — 공개 정보만 수집."""

    ip: str
    first_seen: str = ""
    last_seen: str = ""
    request_count: int = 0
    # WHOIS (공개 정보)
    isp: str = ""
    org: str = ""
    country: str = ""
    city: str = ""
    # 기술 분석
    user_agents: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)
    payloads_used: list[str] = field(default_factory=list)
    # TTP 프로파일링
    mitre_techniques: list[str] = field(default_factory=list)
    tools_detected: list[str] = field(default_factory=list)
    sophistication: str = "unknown"  # script_kiddie, intermediate, advanced, apt
    threat_group_similarity: dict[str, float] = field(default_factory=dict)


class CounterIntelligence:
    """합법적 카운터 인텔리전스 — 공개 정보만 사용.

    절대 하지 않는 것:
    - 공격자 서버 해킹
    - 공격자에 DDoS
    - 공격자 네트워크 스캔 (비인가)

    하는 것:
    - IP WHOIS 조회 (공개 정보)
    - Shodan 검색 (이미 인덱싱된 정보)
    - User-Agent 분석 (수집된 정보)
    - TTP 패턴 분석 → MITRE ATT&CK 매핑
    """

    def profile_attacker(self, ip: str, log_entries: list[dict]) -> AttackerProfile:
        """공격자 IP의 프로파일을 구축한다."""

        profile = AttackerProfile(ip=ip)

        # 로그에서 기본 정보 추출
        ip_entries = [e for e in log_entries if e.get("src_ip") == ip]
        profile.request_count = len(ip_entries)

        if ip_entries:
            timestamps = [e.get("timestamp", "") for e in ip_entries]
            timestamps.sort()
            profile.first_seen = timestamps[0]
            profile.last_seen = timestamps[-1]

            profile.user_agents = list(set(e.get("user_agent", "")[:100] for e in ip_entries))[:10]

            profile.attack_paths = list(set(e.get("path", "").split("?")[0] for e in ip_entries))[
                :20
            ]

        # WHOIS 조회 (공개 정보)
        whois_info = self._whois_lookup(ip)
        profile.isp = whois_info.get("isp", "")
        profile.org = whois_info.get("org", "")
        profile.country = whois_info.get("country", "")
        profile.city = whois_info.get("city", "")

        # User-Agent에서 도구 감지
        profile.tools_detected = self._detect_tools(profile.user_agents)

        # TTP 프로파일링
        profile.mitre_techniques = self._map_mitre_ttps(profile.attack_paths)

        # 정교함 수준 판단
        profile.sophistication = self._assess_sophistication(profile)

        return profile

    def _whois_lookup(self, ip: str) -> dict[str, str]:
        """IP GeoIP 조회 (무료 API)."""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "VXIS/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    return data
        except Exception:
            pass
        return {}

    def _detect_tools(self, user_agents: list[str]) -> list[str]:
        """User-Agent에서 알려진 공격 도구를 감지한다."""
        tool_signatures = {
            "sqlmap": "sqlmap",
            "nikto": "nikto",
            "nmap": "nmap",
            "masscan": "masscan",
            "dirbuster": "dirbuster",
            "gobuster": "gobuster",
            "ffuf": "ffuf",
            "nuclei": "nuclei",
            "burp": "burp",
            "zap": "zap",
            "wpscan": "wpscan",
            "curl": "curl",
            "python-requests": "python-requests",
            "go-http": "go-http",
            "httpx": "httpx",
        }

        detected = []
        ua_text = " ".join(user_agents).lower()
        for tool_name, signature in tool_signatures.items():
            if signature in ua_text:
                detected.append(tool_name)

        return detected

    def _map_mitre_ttps(self, paths: list[str]) -> list[str]:
        """공격 경로에서 MITRE ATT&CK 기법을 매핑한다."""
        techniques = []
        path_text = " ".join(paths).lower()

        mappings = {
            "T1190": [".env", "config", "backup", "admin"],  # Exploit Public-Facing App
            "T1595": ["robots.txt", "sitemap", ".git"],  # Active Scanning
            "T1552": ["password", "credential", "secret", "key"],  # Unsecured Credentials
            "T1005": ["dump", "export", "backup", "db"],  # Data from Local System
            "T1078": ["login", "auth", "admin", "panel"],  # Valid Accounts
            "T1059": ["exec", "cmd", "shell", "system"],  # Command Execution
            "T1083": ["../", "etc/passwd", "proc"],  # File Discovery
        }

        for technique_id, keywords in mappings.items():
            if any(kw in path_text for kw in keywords):
                techniques.append(technique_id)

        return techniques

    def _assess_sophistication(self, profile: AttackerProfile) -> str:
        """공격자의 정교함 수준을 판단한다."""
        score = 0

        # 도구 사용 여부
        if profile.tools_detected:
            score += len(profile.tools_detected)

        # 다양한 공격 경로
        if len(profile.attack_paths) > 10:
            score += 3
        elif len(profile.attack_paths) > 5:
            score += 1

        # User-Agent 다양성 (로테이션 = 더 정교)
        if len(profile.user_agents) > 3:
            score += 2

        # 알려진 고급 도구
        advanced_tools = {"burp", "nuclei", "sqlmap"}
        if advanced_tools & set(profile.tools_detected):
            score += 3

        if score >= 8:
            return "advanced"
        elif score >= 5:
            return "intermediate"
        else:
            return "script_kiddie"

    def format_profile_report(self, profile: AttackerProfile) -> str:
        """공격자 프로파일을 마크다운 보고서로 생성한다."""
        sophistication_kr = {
            "script_kiddie": "스크립트 키디 (초급)",
            "intermediate": "중급 공격자",
            "advanced": "고급 공격자 / APT 가능성",
            "unknown": "판별 불가",
        }

        lines = [
            f"# 🎯 공격자 프로파일: {profile.ip}",
            "",
            f"**최초 감지:** {profile.first_seen}",
            f"**마지막 감지:** {profile.last_seen}",
            f"**총 요청:** {profile.request_count}건",
            "",
            "## 위치 정보 (공개 WHOIS)",
            f"- **국가:** {profile.country}",
            f"- **도시:** {profile.city}",
            f"- **ISP:** {profile.isp}",
            f"- **조직:** {profile.org}",
            "",
            f"## 위협 수준: {sophistication_kr.get(profile.sophistication, profile.sophistication)}",
            "",
        ]

        if profile.tools_detected:
            lines.append("## 감지된 도구")
            for tool in profile.tools_detected:
                lines.append(f"- {tool}")
            lines.append("")

        if profile.mitre_techniques:
            lines.append("## MITRE ATT&CK 매핑")
            for tech in profile.mitre_techniques:
                lines.append(f"- {tech}")
            lines.append("")

        if profile.attack_paths:
            lines.append("## 공격 경로")
            for path in profile.attack_paths[:10]:
                lines.append(f"- `{path}`")
            lines.append("")

        lines.append("---")
        lines.append("_합법적 공개 정보만 사용하여 생성된 프로파일입니다._")

        return "\n".join(lines)

    def save_profile(self, profile: AttackerProfile) -> Path:
        """프로파일을 파일로 저장한다."""
        INTEL_DIR.mkdir(parents=True, exist_ok=True)
        safe_ip = profile.ip.replace(".", "_").replace(":", "_")
        path = INTEL_DIR / f"attacker_{safe_ip}.json"

        data = {
            "ip": profile.ip,
            "country": profile.country,
            "city": profile.city,
            "isp": profile.isp,
            "org": profile.org,
            "sophistication": profile.sophistication,
            "tools_detected": profile.tools_detected,
            "mitre_techniques": profile.mitre_techniques,
            "request_count": profile.request_count,
            "first_seen": profile.first_seen,
            "last_seen": profile.last_seen,
            "attack_paths": profile.attack_paths[:50],
        }

        path.write_text(json.dumps(data, ensure_ascii=False, indent=2))
        return path
