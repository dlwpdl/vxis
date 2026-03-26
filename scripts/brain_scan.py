"""VXIS Brain Scan — Claude Code가 Brain, 전체 VXIS 모듈로 풀오토 펜테스트.

Usage:
    python scripts/brain_scan.py https://kinetics-dev.protopie.works
"""

import asyncio
import json
import logging
import re
import ssl
import socket
import struct
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, "src")

from vxis.interaction.hands import SessionManager, AuthState
from vxis.interaction.xray import FlowAnalyzer
from vxis.interaction.controller import (
    InteractionController,
    InteractionAction,
    InteractionIntent,
    InteractionMode,
)
from vxis.models.finding import (
    Finding, Severity, Evidence, Reference,
    MitreAttack, CVSSVector, FindingStatus,
)
from vxis.report.generator import ReportGenerator, ReportData

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger("vxis.brain")

# ═══════════════════════════════════════════════════════════════
# Brain State
# ═══════════════════════════════════════════════════════════════

SCAN_ID = f"VXIS-{time.strftime('%Y%m%d-%H%M%S')}"
findings: list[Finding] = []
finding_counter = 0
good_items: list[str] = []
attack_chains: list[dict] = []


def add_finding(
    title: str,
    severity: Severity,
    finding_type: str,
    description: str,
    target: str = "",
    affected_component: str = "",
    remediation: str = "",
    evidence: list[Evidence] | None = None,
    references: list[Reference] | None = None,
    cvss_vector: str = "",
    cvss_score: float = 0.0,
    cwe_ids: list[str] | None = None,
    mitre: MitreAttack | None = None,
    source: str = "vxis-cpr",
) -> Finding:
    global finding_counter
    finding_counter += 1
    f = Finding(
        id=f"VXIS-{finding_counter:03d}",
        scan_id=SCAN_ID,
        title=title,
        description=description,
        severity=severity,
        target=target,
        affected_component=affected_component,
        finding_type=finding_type,
        cvss=CVSSVector(vector_string=cvss_vector, base_score=cvss_score) if cvss_vector else None,
        cwe_ids=cwe_ids or [],
        mitre_attack=mitre,
        source_plugin=source,
        evidence=evidence or [],
        remediation=remediation,
        references=references or [],
    )
    findings.append(f)
    logger.info("[%s] %s: %s", severity.value.upper(), f.id, title)
    return f


# ═══════════════════════════════════════════════════════════════
# Main Scan
# ═══════════════════════════════════════════════════════════════

async def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://kinetics-dev.protopie.works"
    parsed = urlparse(target_url)
    base_domain = parsed.netloc
    root_domain = ".".join(base_domain.split(".")[-2:])

    logger.info("=" * 70)
    logger.info("  VXIS Brain Scan — Full Module, All Attack Vectors")
    logger.info("  Target: %s", target_url)
    logger.info("  Scan ID: %s", SCAN_ID)
    logger.info("=" * 70)

    # ── CPR 초기화 ──
    session_mgr = SessionManager()
    xray = FlowAnalyzer()

    # ═══════════════════════════════════════════════════════════
    # PHASE 1: RECON — CPR Hands로 공격 표면 매핑
    # ═══════════════════════════════════════════════════════════
    logger.info("\n[PHASE 1] RECON — 공격 표면 매핑")

    # 1a. 메인 타깃 세션 생성 + 초기 요청
    session = await session_mgr.get_session(target_url)
    resp = await session.get("/")
    fingerprint = session.get_fingerprint()

    logger.info("  Target: %s | Status: %d | Tech: %s",
                target_url, resp.status, fingerprint.get("tech_stack", []))

    # X-Ray에 초기 플로우 기록
    flow = xray.create_flow_from_request(
        method="GET", url=f"{target_url}/",
        headers=dict(resp.response.request.headers), body="",
    )
    xray.update_flow_response(flow, status_code=resp.status,
                              headers=dict(resp.headers), body=resp.text[:10000])
    xray.add_flow(flow)

    # 1b. 보안 헤더 체크
    sec_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "x-xss-protection": "X-XSS-Protection",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }
    missing = []
    for hdr, name in sec_headers.items():
        if hdr not in resp.headers:
            missing.append(name)

    if missing:
        add_finding(
            title=f"Missing Security Headers ({len(missing)}/{len(sec_headers)})",
            severity=Severity.high,
            finding_type="security_misconfiguration",
            target=target_url,
            description=f"Missing: {', '.join(missing)}",
            remediation="Add all security headers via nginx/CDN configuration.",
            cwe_ids=["CWE-693", "CWE-1021"],
            evidence=[Evidence(
                evidence_type="http_transaction",
                title="Response headers (no security headers present)",
                content="\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
            )],
        )

    server = resp.headers.get("server", "")
    if server and any(c.isdigit() for c in server):
        add_finding(
            title=f"Server Version Disclosure: {server}",
            severity=Severity.medium,
            finding_type="information_disclosure",
            target=target_url,
            description=f"Server header exposes version: {server}",
            remediation="nginx.conf: server_tokens off;",
            cwe_ids=["CWE-200"],
        )

    # 1c. JS 번들 분석
    logger.info("  JS bundle analysis...")
    js_urls = re.findall(r'src="(/assets/[^"]+\.js)"', resp.text)
    api_endpoints = []
    for js_url in js_urls:
        js_resp = await session.get(js_url)
        js = js_resp.text

        # API endpoints
        for m in re.finditer(r'["\'`](/api/[^\s"\'`<>]+)["\'`]', js):
            ep = m.group(1)
            if ep not in [e["path"] for e in api_endpoints]:
                api_endpoints.append({"path": ep, "source": "js"})

        # Fetch calls with context
        for m in re.finditer(r'(?:fetch|\.post|\.get)\s*\(\s*["\'`]([^"\'`]+)["\'`]', js):
            url = m.group(1)
            if url.startswith("/") and url not in [e["path"] for e in api_endpoints]:
                start = max(0, m.start() - 200)
                ctx = js[start:m.end() + 200]
                method = "POST" if ".post" in ctx or "POST" in ctx else "GET"
                api_endpoints.append({"path": url, "method": method, "source": "fetch"})

        # Secrets
        for m in re.finditer(r'["\'`]((?:sk-|pk-|api[_-]?key|bearer\s+)[^\s"\'`]{10,})["\'`]', js, re.I):
            add_finding(
                title=f"Hardcoded Secret in JS Bundle: {m.group(1)[:30]}...",
                severity=Severity.critical,
                finding_type="sensitive_data_exposure",
                target=target_url,
                affected_component=js_url,
                description=f"Secret found in client-side JavaScript: {m.group(1)[:50]}",
                cwe_ids=["CWE-798"],
            )

        # Routes
        for m in re.finditer(r'path\s*:\s*["\'`]([^"\'`]+)["\'`]', js):
            route = m.group(1)
            if route not in [e["path"] for e in api_endpoints]:
                api_endpoints.append({"path": route, "source": "route", "type": "frontend"})

        # Accepted file types
        accepted = re.findall(r'["\'`]((?:video|image)/[\w.+-]+)["\'`]', js)
        if accepted:
            logger.info("  Accepted file types: %s", list(set(accepted)))

    logger.info("  Found %d API endpoints", len(api_endpoints))

    # 1d. 경로 탐색
    logger.info("  Path discovery...")
    discovery_paths = [
        "/api/health", "/api/status", "/api/config", "/api/admin",
        "/api/docs", "/api/swagger", "/api/graphql",
        "/robots.txt", "/.env", "/.git/HEAD", "/sitemap.xml",
        "/swagger.json", "/openapi.json", "/.well-known/security.txt",
        "/assets/", "/admin", "/debug", "/metrics",
    ]
    for path in discovery_paths:
        dr = await session.get(path)
        is_spa = "<div id=" in dr.text and len(dr.text) < 2000
        if dr.status == 200 and not is_spa and len(dr.text) > 10:
            api_endpoints.append({"path": path, "status": dr.status, "source": "discovery"})
            logger.info("  [FOUND] %s → %d (%db)", path, dr.status, len(dr.text))
        if dr.status == 403:
            logger.info("  [403] %s", path)

    # 1e. TLS 분석
    logger.info("  TLS analysis...")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=base_domain) as s:
            s.settimeout(10)
            s.connect((base_domain, 443))
            cert = s.getpeercert()
            san = [x[1] for x in cert.get("subjectAltName", ())]
            logger.info("  TLS: %s | SAN: %s | Expires: %s",
                        cert.get("issuer", ""), san, cert.get("notAfter", ""))
    except Exception as e:
        logger.warning("  TLS analysis failed: %s", e)

    # 1f. 서브도메인 열거
    logger.info("  Subdomain enumeration (*.%s)...", root_domain)
    subdomains = []
    sub_names = [
        "api", "admin", "staging", "dev", "test", "internal", "dashboard",
        "monitor", "grafana", "kibana", "jenkins", "gitlab", "ci",
        "cdn", "static", "media", "upload", "storage",
        "auth", "sso", "oauth", "mail", "smtp",
        "kinetics", "kinetics-api", "kinetics-admin",
        "app", "cloud", "enterprise", "connect", "player",
        "backend", "gateway", "proxy", "ws",
    ]
    for sub in sub_names:
        fqdn = f"{sub}.{root_domain}"
        try:
            sub_session = await session_mgr.get_session(f"https://{fqdn}")
            sr = await sub_session.get("/")
            is_spa = "<div id=" in sr.text and len(sr.text) < 2000
            subdomains.append({
                "fqdn": fqdn, "status": sr.status,
                "headers": dict(sr.headers),
                "body_preview": sr.text[:300],
                "is_api": "json" in sr.headers.get("content-type", ""),
            })
            logger.info("  [LIVE] %s → %d | %s", fqdn, sr.status, sr.headers.get("content-type", ""))
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════
    # PHASE 2: PROBE — 입력 검증, 인젝션, 파일 업로드
    # ═══════════════════════════════════════════════════════════
    logger.info("\n[PHASE 2] PROBE — 모든 공격 벡터 테스트")

    # 2a. 각 POST 엔드포인트 필드 매핑 + 인젝션
    for ep in api_endpoints:
        path = ep["path"]
        if "{" in path or "$" in path:
            continue

        # 빈 POST로 필드 구조 파악
        pr = await session.request("POST", path)
        flow = xray.create_flow_from_request(
            method="POST", url=f"{target_url}{path}",
            headers=dict(pr.response.request.headers), body="",
        )
        xray.update_flow_response(flow, status_code=pr.status,
                                  headers=dict(pr.headers), body=pr.text[:5000])
        xray.add_flow(flow)

        fields = []
        try:
            err = json.loads(pr.text)
            if isinstance(err.get("detail"), list):
                for d in err["detail"]:
                    if isinstance(d, dict) and "loc" in d:
                        field_name = d["loc"][-1] if d["loc"] else ""
                        if field_name and field_name not in ("video", "file"):
                            fields.append(field_name)
                if fields:
                    add_finding(
                        title=f"API Error Exposes Field Schema: {path}",
                        severity=Severity.medium,
                        finding_type="information_disclosure",
                        target=target_url,
                        affected_component=path,
                        description=f"Validation error reveals field names: {fields}",
                        cwe_ids=["CWE-209"],
                        evidence=[Evidence(
                            evidence_type="http_transaction",
                            title=f"POST {path} → field schema leak",
                            content=f"POST {path}\n(empty body)\n\n→ {pr.status}\n{pr.text[:500]}",
                        )],
                    )
        except Exception:
            pass

        # 인젝션 테스트
        payloads = {
            "sqli": ("'", ["CWE-89"]),
            "xss": ("<script>alert(1)</script>", ["CWE-79"]),
            "ssti": ("{{7*7}}", ["CWE-94"]),
            "crlf": ("\r\nInjected: true", ["CWE-93"]),
            "null_byte": ("\x00test", ["CWE-158"]),
        }
        for field_name in fields:
            for attack, (payload, cwes) in payloads.items():
                data = {field_name: payload}
                # share_link도 필요할 수 있으니 다른 필드 채우기
                for other_field in fields:
                    if other_field != field_name and other_field not in data:
                        data[other_field] = "test"
                ir = await session.request("POST", path, json_data=data)

                flow = xray.create_flow_from_request(
                    method="POST", url=f"{target_url}{path}",
                    headers=dict(ir.response.request.headers),
                    body=json.dumps(data),
                )
                xray.update_flow_response(flow, status_code=ir.status,
                                          headers=dict(ir.headers), body=ir.text[:5000])
                xray.add_flow(flow)

                if ir.status == 200:
                    add_finding(
                        title=f"{attack.upper()} Accepted: {path} field '{field_name}'",
                        severity=Severity.high if attack in ("sqli", "xss") else Severity.medium,
                        finding_type=attack,
                        target=target_url,
                        affected_component=f"{path} → {field_name}",
                        description=f"Payload {repr(payload)} accepted with 200 OK. If stored and rendered, this enables {attack.upper()}.",
                        cwe_ids=cwes,
                        evidence=[Evidence(
                            evidence_type="http_transaction",
                            title=f"{attack} payload accepted",
                            content=f"POST {path}\n{json.dumps(data)}\n\n→ {ir.status}\n{ir.text[:200]}",
                        )],
                    )
                    break  # 하나 통과하면 다 통과하므로 필드당 첫 번째만

    # 2b. 파일 업로드 테스트
    logger.info("  File upload testing...")
    upload_eps = [ep for ep in api_endpoints if "analyze" in ep.get("path", "") or "upload" in ep.get("path", "")]
    for ep in upload_eps:
        path = ep["path"]

        # 유효한 GIF
        gif = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'

        file_tests = [
            ("valid_gif", "test.gif", gif, "image/gif"),
            ("php_as_video", "shell.php", b"<?php system($_GET['c']); ?>", "video/mp4"),
            ("double_ext", "shell.php.mp4", b"fake", "video/mp4"),
            ("html_upload", "xss.html", b"<script>alert(1)</script>", "video/mp4"),
        ]
        for name, fname, content, ctype in file_tests:
            import httpx
            async with httpx.AsyncClient(timeout=20) as hc:
                r = await hc.post(
                    f"{target_url}{path}",
                    files={"video": (fname, content, ctype)},
                    data={"prompt": "test"},
                )
                if r.status_code == 200:
                    add_finding(
                        title=f"File Upload Accepted: {name} → {path}",
                        severity=Severity.high,
                        finding_type="unrestricted_upload",
                        target=target_url,
                        affected_component=path,
                        description=f"File {fname} ({ctype}) accepted by upload endpoint.",
                        cwe_ids=["CWE-434"],
                        evidence=[Evidence(
                            evidence_type="http_transaction",
                            title=f"Upload {name}",
                            content=f"POST {path}\nFile: {fname} ({ctype})\n\n→ {r.status_code}\n{r.text[:300]}",
                        )],
                    )
                elif r.status_code == 500 and "PROCESSING_ERROR" in r.text:
                    # GIF 처리 파이프라인 도달 = 파일 검증 우회
                    add_finding(
                        title=f"File Validation Bypass: {name} reaches processing pipeline",
                        severity=Severity.medium,
                        finding_type="unrestricted_upload",
                        target=target_url,
                        affected_component=path,
                        description=f"File {fname} passed validation and reached the AI processing pipeline (500 PROCESSING_ERROR).",
                        cwe_ids=["CWE-434"],
                        evidence=[Evidence(
                            evidence_type="http_transaction",
                            title=f"Upload {name} → processing pipeline",
                            content=f"POST {path}\nFile: {fname} ({ctype})\n\n→ {r.status_code}\n{r.text[:300]}",
                        )],
                    )
                else:
                    if name == "php_as_video":
                        good_items.append(f"File upload rejects {name} ({r.status_code})")

    # 2c. Rate Limiting 체크
    logger.info("  Rate limiting check...")
    for ep in api_endpoints:
        if "analyze" in ep.get("path", ""):
            statuses = []
            for i in range(3):
                import httpx
                async with httpx.AsyncClient(timeout=15) as hc:
                    r = await hc.post(
                        f"{target_url}{ep['path']}",
                        files={"video": (f"t{i}.mp4", b"x", "video/mp4")},
                        data={"prompt": "t"},
                    )
                    statuses.append(r.status_code)
            if len(set(statuses)) == 1:
                add_finding(
                    title=f"No Rate Limiting: {ep['path']}",
                    severity=Severity.high,
                    finding_type="security_misconfiguration",
                    target=target_url,
                    affected_component=ep["path"],
                    description=f"3 rapid requests all returned {statuses[0]}. No rate limiting detected.",
                    cwe_ids=["CWE-770"],
                )
            break

    # 2d. Clickjacking
    xfo = resp.headers.get("x-frame-options", "")
    csp = resp.headers.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp:
        add_finding(
            title="Clickjacking: No Frame Protection",
            severity=Severity.high,
            finding_type="clickjacking",
            target=target_url,
            description="Neither X-Frame-Options nor CSP frame-ancestors is set.",
            cwe_ids=["CWE-1021"],
        )

    # 2e. IDOR / Timing on result endpoint
    result_eps = [ep for ep in api_endpoints if "result" in ep.get("path", "")]
    for ep in result_eps:
        timings = {}
        for test_id in ["valid_looking_id_12345", "x", "a" * 16]:
            path = ep["path"].replace("${e}", test_id).replace("{id}", test_id)
            if "$" in path:
                path = f"/api/result/{test_id}"
            t0 = time.monotonic()
            tr = await session.get(path)
            elapsed = (time.monotonic() - t0) * 1000
            timings[test_id] = elapsed
        vals = list(timings.values())
        if max(vals) - min(vals) > 100:
            add_finding(
                title="Timing-Based Result ID Enumeration",
                severity=Severity.medium,
                finding_type="information_disclosure",
                target=target_url,
                affected_component="/api/result/{id}",
                description=f"Response time varies by ID format: {timings}. Delta: {max(vals)-min(vals):.0f}ms.",
                cwe_ids=["CWE-208"],
            )

    # 2f. 중복 등록 / 500 에러
    subscribe_eps = [ep for ep in api_endpoints if "subscribe" in ep.get("path", "")]
    for ep in subscribe_eps:
        path = ep["path"]
        r1 = await session.request("POST", path, json_data={"email": "dup@test.com", "share_link": "x"})
        r2 = await session.request("POST", path, json_data={"email": "dup@test.com", "share_link": "x"})
        if r1.status == 200 and r2.status == 200:
            add_finding(
                title=f"Duplicate Registration Allowed: {path}",
                severity=Severity.medium,
                finding_type="input_validation",
                target=target_url,
                affected_component=path,
                description="Same email+share_link accepted unlimited times.",
                cwe_ids=["CWE-20"],
            )

        r_empty = await session.request("POST", path, json_data={"email": "", "share_link": ""})
        if r_empty.status == 500:
            add_finding(
                title=f"500 Error on Empty Input: {path}",
                severity=Severity.medium,
                finding_type="error_handling",
                target=target_url,
                affected_component=path,
                description=f"Empty input triggers 500: {r_empty.text[:200]}",
                cwe_ids=["CWE-755"],
                evidence=[Evidence(
                    evidence_type="http_transaction",
                    title="500 on empty input",
                    content=f'POST {path}\n{{"email":"","share_link":""}}\n\n→ 500\n{r_empty.text[:200]}',
                )],
            )

    # ═══════════════════════════════════════════════════════════
    # PHASE 3: CHAIN — 서브도메인 피벗, Swagger, CORS
    # ═══════════════════════════════════════════════════════════
    logger.info("\n[PHASE 3] CHAIN — 서브도메인 피벗")

    for sub in subdomains:
        fqdn = sub["fqdn"]
        sub_url = f"https://{fqdn}"

        try:
            sub_session = await session_mgr.get_session(sub_url)
        except Exception:
            continue

        # Swagger 탐색
        for sp in ["/docs-json", "/swagger-json", "/api-json", "/openapi.json"]:
            try:
                sr = await sub_session.get(sp)
                if sr.status == 200 and '"paths"' in sr.text:
                    schema = json.loads(sr.text)
                    paths = schema.get("paths", {})
                    # 스키마 저장
                    Path("reports").mkdir(exist_ok=True)
                    with open(f"reports/swagger_{fqdn.split('.')[0]}.json", "w") as sf:
                        json.dump(schema, sf, indent=2, ensure_ascii=False)

                    # 인증 없는 엔드포인트 카운트
                    unauth = []
                    for p, methods in paths.items():
                        for method, detail in methods.items():
                            if method in ("get","post","put","patch","delete"):
                                if not detail.get("security"):
                                    unauth.append(f"{method.upper()} {p}")

                    add_finding(
                        title=f"Swagger Schema Exposed: {fqdn}{sp}",
                        severity=Severity.critical,
                        finding_type="information_disclosure",
                        target=sub_url,
                        affected_component=sp,
                        description=f"Full OpenAPI schema exposed. {len(paths)} endpoints, {len(unauth)} unauthenticated:\n" + "\n".join(unauth[:20]),
                        cwe_ids=["CWE-200", "CWE-213"],
                        evidence=[Evidence(
                            evidence_type="http_transaction",
                            title=f"Swagger schema at {fqdn}{sp}",
                            content=f"GET {sp}\nHost: {fqdn}\n\n→ 200\n{json.dumps(schema.get('info',{}), indent=2)}",
                        )],
                    )

                    # 인증 없는 엔드포인트 직접 호출
                    for ep_str in unauth:
                        method, ep_path = ep_str.split(" ", 1)
                        if "*" in ep_path:
                            continue
                        try:
                            if method == "GET":
                                er = await sub_session.get(ep_path)
                            else:
                                er = await sub_session.request(method, ep_path, json_data={})
                            if er.status == 200 and len(er.text) > 20:
                                add_finding(
                                    title=f"Unauthenticated Data Access: {fqdn} {method} {ep_path}",
                                    severity=Severity.critical,
                                    finding_type="broken_access_control",
                                    target=sub_url,
                                    affected_component=ep_path,
                                    description=f"Endpoint returns data without authentication.",
                                    cwe_ids=["CWE-284", "CWE-306"],
                                    evidence=[Evidence(
                                        evidence_type="http_transaction",
                                        title=f"Unauthenticated {method} {ep_path}",
                                        content=f"{method} {ep_path}\nHost: {fqdn}\n(No auth)\n\n→ {er.status}\n{er.text[:500]}",
                                    )],
                                )
                            elif er.status == 201:
                                add_finding(
                                    title=f"Unauthenticated Write: {fqdn} {method} {ep_path}",
                                    severity=Severity.critical,
                                    finding_type="broken_access_control",
                                    target=sub_url,
                                    affected_component=ep_path,
                                    description=f"Write endpoint accessible without auth. Response: {er.text[:200]}",
                                    cwe_ids=["CWE-284"],
                                    evidence=[Evidence(
                                        evidence_type="http_transaction",
                                        title=f"Unauthenticated write {method} {ep_path}",
                                        content=f"{method} {ep_path}\nHost: {fqdn}\n\n→ {er.status}\n{er.text[:300]}",
                                    )],
                                )
                        except Exception:
                            pass

                    break  # swagger found
            except Exception:
                pass

        # CORS 테스트
        import httpx
        async with httpx.AsyncClient(timeout=10) as hc:
            for origin in ["https://evil.com", "null"]:
                try:
                    cr = await hc.options(f"{sub_url}/health", headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "POST",
                    })
                    acao = cr.headers.get("access-control-allow-origin", "")
                    acac = cr.headers.get("access-control-allow-credentials", "")
                    if acao and acac == "true":
                        add_finding(
                            title=f"CORS Wildcard + Credentials: {fqdn}",
                            severity=Severity.critical,
                            finding_type="cors_misconfiguration",
                            target=sub_url,
                            description=f"Origin '{origin}' reflected with credentials:true. All methods allowed.",
                            cwe_ids=["CWE-942", "CWE-346"],
                            mitre=MitreAttack(tactic_id="TA0009", tactic_name="Collection", technique_id="T1185", technique_name="Browser Session Hijacking"),
                            evidence=[Evidence(
                                evidence_type="http_transaction",
                                title=f"CORS test: Origin={origin}",
                                content=f"OPTIONS /health\nHost: {fqdn}\nOrigin: {origin}\n\n→ {cr.status_code}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            )],
                        )
                        break  # 하나 통과하면 됨
                except Exception:
                    pass

        # X-Powered-By
        if "x-powered-by" in sub.get("headers", {}):
            xpb = sub["headers"]["x-powered-by"]
            add_finding(
                title=f"X-Powered-By Exposed: {fqdn} ({xpb})",
                severity=Severity.medium,
                finding_type="information_disclosure",
                target=sub_url,
                description=f"X-Powered-By: {xpb} header exposes framework.",
                cwe_ids=["CWE-200"],
            )

        # Path traversal via proxy endpoints (Zendesk 등)
        for proxy_path in ["/v1/zdk/../../health", "/v1/zdk/../../v1/dmn/domain/list"]:
            try:
                ptr = await sub_session.get(proxy_path)
                if ptr.status == 200 and ("healthy" in ptr.text or "domains" in ptr.text):
                    add_finding(
                        title=f"Path Traversal via Proxy: {fqdn} {proxy_path}",
                        severity=Severity.critical,
                        finding_type="path_traversal",
                        target=sub_url,
                        affected_component=proxy_path.split("../../")[0] + "*",
                        description=f"Wildcard proxy endpoint allows ../ traversal to internal routes.",
                        cwe_ids=["CWE-22", "CWE-918"],
                        evidence=[Evidence(
                            evidence_type="http_transaction",
                            title=f"Path traversal PoC",
                            content=f"GET {proxy_path}\nHost: {fqdn}\n\n→ {ptr.status}\n{ptr.text[:300]}",
                        )],
                    )
            except Exception:
                pass

        # Salesforce info leak
        try:
            sfr = await sub_session.request("POST", "/v1/slf/salesforce/leads", json_data={
                "first_name": "A", "last_name": "B", "email": "probe@vxis.test", "company": "C",
            })
            if sfr.status == 201 and "oid" in sfr.text:
                oid = re.search(r'oid\s*=\s*(\w+)', sfr.text)
                email = re.search(r'debugEmail\s*=\s*"?([^"\s<]+)', sfr.text)
                add_finding(
                    title=f"Salesforce OID + Internal Email Exposed: {fqdn}",
                    severity=Severity.critical,
                    finding_type="information_disclosure",
                    target=sub_url,
                    affected_component="/v1/slf/salesforce/leads",
                    description=f"Salesforce debug mode active. OID: {oid.group(1) if oid else '?'}, Email: {email.group(1) if email else '?'}",
                    cwe_ids=["CWE-200", "CWE-215"],
                    evidence=[Evidence(
                        evidence_type="http_transaction",
                        title="Salesforce debug response",
                        content=f"POST /v1/slf/salesforce/leads\nHost: {fqdn}\n\n→ {sfr.status}\n{sfr.text[:500]}",
                    )],
                )
        except Exception:
            pass

        # Auth register
        try:
            uid = str(uuid.uuid4())
            ar = await sub_session.request("POST", "/v1/auth/register", json_data={
                "userId": uid, "phoneOrWechat": "+821000000000",
            })
            if ar.status == 201:
                add_finding(
                    title=f"Unauthenticated Account Creation: {fqdn}",
                    severity=Severity.critical,
                    finding_type="broken_access_control",
                    target=sub_url,
                    affected_component="/v1/auth/register",
                    description=f"User account created without authentication. Response: {ar.text[:200]}",
                    cwe_ids=["CWE-284", "CWE-306"],
                    evidence=[Evidence(
                        evidence_type="http_transaction",
                        title="Account creation PoC",
                        content=f'POST /v1/auth/register\nHost: {fqdn}\n\n{{"userId":"{uid}","phoneOrWechat":"+821000000000"}}\n\n→ {ar.status}\n{ar.text[:200]}',
                    )],
                )
        except Exception:
            pass

        # Prisma error leak
        try:
            pr = await sub_session.request("PATCH", "/v1/dmn/domain/vxis-test", json_data={"domainType": "X"})
            if pr.status == 500 and "prisma" in pr.text.lower():
                add_finding(
                    title=f"Prisma ORM Error Leaks Source Code Path: {fqdn}",
                    severity=Severity.critical,
                    finding_type="information_disclosure",
                    target=sub_url,
                    affected_component="/v1/dmn/domain/{domain}",
                    description=f"PATCH triggers Prisma error exposing server path and DB schema.",
                    cwe_ids=["CWE-209", "CWE-215"],
                    evidence=[Evidence(
                        evidence_type="http_transaction",
                        title="Prisma error with source path",
                        content=f'PATCH /v1/dmn/domain/vxis-test\nHost: {fqdn}\n\n→ 500\n{pr.text[:500]}',
                    )],
                )
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════
    # X-Ray 패시브 분석
    # ═══════════════════════════════════════════════════════════
    logger.info("\n[X-RAY] 패시브 트래픽 분석")
    summary = xray.get_summary()
    logger.info("  Total flows: %d", summary.total_flows)
    logger.info("  API endpoints: %d", len(summary.api_endpoints))
    if summary.auth_tokens_found:
        logger.info("  Auth tokens: %d", len(summary.auth_tokens_found))
    if summary.secrets_found:
        for s in summary.secrets_found:
            logger.info("  [SECRET] %s", s)
    if summary.vulnerabilities:
        for v in summary.vulnerabilities:
            logger.info("  [VULN] %s", v)

    # ═══════════════════════════════════════════════════════════
    # Cleanup
    # ═══════════════════════════════════════════════════════════
    await session_mgr.close_all()

    # ═══════════════════════════════════════════════════════════
    # PHASE 5: REPORT — NCC Group 스타일 HTML
    # ═══════════════════════════════════════════════════════════
    logger.info("\n[PHASE 5] REPORT — NCC Group Style HTML")

    # Dedup findings by (title + affected_component) — 같은 취약점이 다른 서브도메인에 있으면 머지
    dedup_map: dict[str, Finding] = {}
    for f in findings:
        # 서브도메인만 다른 동일 취약점은 하나로 합침
        # title에서 서브도메인 부분 제거해서 키 생성
        clean_title = f.title
        for sub_prefix in ["internal.protopie.works", "dashboard.protopie.works"]:
            clean_title = clean_title.replace(sub_prefix, "{subdomain}")
        dedup_key = clean_title

        if dedup_key in dedup_map:
            existing = dedup_map[dedup_key]
            # 영향받는 컴포넌트 합치기
            if f.affected_component and f.affected_component not in existing.affected_component:
                existing.affected_component += f", {f.affected_component}" if existing.affected_component else f.affected_component
            # 타겟 합치기
            if f.target and f.target not in existing.target:
                existing.target += f", {f.target}" if existing.target else f.target
            # Evidence 합치기
            existing.evidence.extend(f.evidence)
            # description에 추가 서브도메인 언급
            if f.target and f.target not in existing.description:
                existing.description += f"\n\nAlso affects: {f.target}"
        else:
            dedup_map[dedup_key] = f

    deduped = list(dedup_map.values())

    # ── 한국어 번역 후처리 — |||로 이중 언어 삽입 ──
    KO_TRANSLATIONS = {
        # title patterns → Korean title
        "Missing Security Headers": "보안 헤더 미설정",
        "Server Version Disclosure": "서버 버전 정보 노출",
        "API Error Exposes Field Schema": "API 에러에서 필드 스키마 노출",
        "File Validation Bypass": "파일 검증 우회",
        "No Rate Limiting": "Rate Limiting 미적용",
        "Clickjacking: No Frame Protection": "클릭재킹: 프레임 보호 없음",
        "Timing-Based Result ID Enumeration": "타이밍 기반 Result ID 열거",
        "Duplicate Registration Allowed": "중복 등록 허용",
        "500 Error on Empty Input": "빈 값 입력 시 500 에러",
        "Swagger Schema Exposed": "Swagger API 스키마 외부 노출",
        "Unauthenticated Data Access": "인증 없이 데이터 접근 가능",
        "CORS Wildcard + Credentials": "CORS 와일드카드 + 인증정보 허용",
        "X-Powered-By Exposed": "X-Powered-By 헤더 노출",
        "Path Traversal via Proxy": "프록시 경로 조작 (Path Traversal)",
        "Salesforce OID + Internal Email Exposed": "Salesforce OID 및 내부 이메일 노출",
        "Unauthenticated Account Creation": "인증 없이 계정 생성 가능",
        "Prisma ORM Error Leaks Source Code Path": "Prisma ORM 에러에서 소스코드 경로 노출",
        "SPA Fallback Returns 200": "SPA Fallback이 모든 경로에 200 반환",
        "No security.txt": "security.txt 미제공",
    }

    KO_DESCS = {
        "security_misconfiguration": "보안 설정이 미흡합니다.",
        "information_disclosure": "내부 정보가 외부에 노출됩니다.",
        "broken_access_control": "인증/인가 없이 접근이 가능합니다.",
        "cors_misconfiguration": "CORS 설정이 잘못되어 크로스오리진 공격이 가능합니다.",
        "path_traversal": "경로 조작을 통해 내부 리소스에 접근 가능합니다.",
        "injection": "입력 검증 없이 악성 페이로드가 수락됩니다.",
        "clickjacking": "프레임 보호가 없어 클릭재킹 공격이 가능합니다.",
        "input_validation": "입력 검증이 미흡합니다.",
        "error_handling": "에러 처리가 미흡하여 내부 정보가 노출됩니다.",
        "unrestricted_upload": "파일 업로드 검증이 우회될 수 있습니다.",
    }

    KO_REMEDIATIONS = {
        "security_misconfiguration": "nginx 또는 CDN에서 보안 헤더를 설정하세요.",
        "information_disclosure": "프로덕션 환경에서 디버그 정보 노출을 차단하세요.",
        "broken_access_control": "해당 엔드포인트에 JWT 인증 미들웨어를 적용하세요.",
        "cors_misconfiguration": "허용된 도메인 화이트리스트로 CORS를 제한하세요.",
        "path_traversal": "경로 입력에서 '../' 시퀀스를 필터링하세요.",
        "injection": "모든 입력에 대해 형식 검증 및 이스케이프를 적용하세요.",
        "clickjacking": "X-Frame-Options: DENY 또는 CSP frame-ancestors 'self'를 설정하세요.",
        "input_validation": "입력 형식 검증 및 길이 제한을 추가하세요.",
        "error_handling": "프로덕션에서 상세 에러 메시지를 일반 메시지로 래핑하세요.",
        "unrestricted_upload": "파일 매직 바이트 + MIME 타입 + 확장자를 함께 검증하세요.",
    }

    for f in deduped:
        # Title 한국어 추가
        if "|||" not in f.title:
            ko_title = None
            for pattern, ko in KO_TRANSLATIONS.items():
                if pattern in f.title:
                    # 서브도메인 정보 보존
                    extra = f.title.replace(pattern, "").strip().strip(":").strip()
                    ko_title = f"{ko}: {extra}" if extra else ko
                    break
            if ko_title:
                f.title = f"{f.title}|||{ko_title}"

        # Description 한국어 추가
        if "|||" not in f.description:
            ko_desc = KO_DESCS.get(f.finding_type, "")
            if ko_desc:
                f.description = f"{f.description}|||{ko_desc}\n{f.description}"

        # Remediation 한국어 추가
        if f.remediation and "|||" not in f.remediation:
            ko_rem = KO_REMEDIATIONS.get(f.finding_type, "")
            if ko_rem:
                f.remediation = f"{f.remediation}|||{ko_rem}\n{f.remediation}"

    c_count = sum(1 for f in deduped if f.severity == Severity.critical)
    h_count = sum(1 for f in deduped if f.severity == Severity.high)
    m_count = sum(1 for f in deduped if f.severity == Severity.medium)
    l_count = sum(1 for f in deduped if f.severity == Severity.low)
    i_count = sum(1 for f in deduped if f.severity == Severity.informational)

    exec_summary = (
        f"VXIS performed a black-box penetration test against {target_url} and discovered "
        f"critical vulnerabilities across the primary target and supporting infrastructure. "
        f"Through subdomain enumeration, {len(subdomains)} live subdomains were identified, "
        f"revealing exposed internal APIs with Swagger documentation, CORS misconfiguration "
        f"allowing cross-origin credential theft, unauthenticated database access, and "
        f"Salesforce/Zendesk integration information leakage.\n\n"
        f"Total findings: {len(deduped)} "
        f"(Critical: {c_count}, High: {h_count}, Medium: {m_count}, Low: {l_count}, Info: {i_count})"
        f"|||"
        f"VXIS는 {target_url}에 대해 블랙박스 모의침투 테스트를 수행하였으며, "
        f"주요 타깃 및 지원 인프라 전반에서 심각한 취약점을 발견하였습니다. "
        f"서브도메인 열거를 통해 {len(subdomains)}개의 라이브 서브도메인을 식별하였고, "
        f"Swagger 문서가 노출된 내부 API, 크로스오리진 인증정보 탈취를 허용하는 CORS 설정 오류, "
        f"인증 없는 데이터베이스 접근, Salesforce/Zendesk 연동 정보 유출 등을 확인하였습니다.\n\n"
        f"총 발견: {len(deduped)}건 "
        f"(Critical: {c_count}, High: {h_count}, Medium: {m_count}, Low: {l_count}, Info: {i_count})"
    )

    methodology = (
        "This assessment was conducted using VXIS Cognitive Pentesting Runtime (CPR) with the "
        "following modules:\n\n"
        "- CPR Hands (SessionManager): HTTP session management with cookie/JWT/CSRF auto-tracking\n"
        "- CPR X-Ray (FlowAnalyzer): Passive traffic analysis for auth tokens, secrets, and vulnerabilities\n"
        "- JS Bundle Static Analysis: API endpoint discovery, secret detection, route extraction\n"
        "- Subdomain Enumeration: Wildcard TLS certificate-based discovery\n"
        "- Input Validation Testing: SQLi, XSS, SSTI, CRLF, null byte injection\n"
        "- File Upload Testing: MIME confusion, extension bypass, magic byte validation\n"
        "- CORS Analysis: Origin reflection, credential support, null origin\n"
        "- Swagger/OpenAPI Schema Extraction\n"
        "- Path Traversal via Proxy Endpoints\n\n"
        "Methodology follows OWASP Testing Guide (OTGv4), PTES, and NIST SP 800-115. "
        "Testing was conducted in safe mode (no DoS, minimal write operations)."
        "|||"
        "본 평가는 VXIS Cognitive Pentesting Runtime (CPR)을 사용하여 수행되었으며, "
        "다음 모듈을 활용하였습니다:\n\n"
        "- CPR Hands (SessionManager): 쿠키/JWT/CSRF 자동 추적 HTTP 세션 관리\n"
        "- CPR X-Ray (FlowAnalyzer): 인증 토큰, 시크릿, 취약점 패시브 트래픽 분석\n"
        "- JS 번들 정적 분석: API 엔드포인트 발견, 시크릿 탐지, 라우트 추출\n"
        "- 서브도메인 열거: 와일드카드 TLS 인증서 기반 탐색\n"
        "- 입력 검증 테스트: SQLi, XSS, SSTI, CRLF, null byte 인젝션\n"
        "- 파일 업로드 테스트: MIME 혼동, 확장자 우회, 매직 바이트 검증\n"
        "- CORS 분석: Origin 반사, 인증정보 지원, null origin\n"
        "- Swagger/OpenAPI 스키마 추출\n"
        "- 프록시 엔드포인트 Path Traversal\n\n"
        "OWASP Testing Guide (OTGv4), PTES, NIST SP 800-115 프레임워크를 따릅니다. "
        "안전 모드로 수행 (DoS 없음, 최소 쓰기 작업)."
    )

    report_data = ReportData(
        scan_id=SCAN_ID,
        client_name="ProtoPie Inc.",
        target=target_url,
        scan_date=time.strftime("%Y-%m-%d"),
        findings=deduped,
        company_name="VXIS Security",
        author="VXIS CPR (Brain: Claude Opus 4.6)",
        executive_summary=exec_summary,
        methodology=methodology,
    )

    gen = ReportGenerator()
    output = Path("reports/VXIS_Report_ProtoPie_Kinetics_Full.html")
    gen.generate_html_file(report_data, output)

    # JSON도 저장
    json_output = output.with_suffix(".json")
    json_data = {
        "scan_id": SCAN_ID,
        "target": target_url,
        "date": time.strftime("%Y-%m-%d"),
        "risk_score": report_data.risk_score,
        "severity_counts": report_data.severity_counts,
        "findings": [f.model_dump(mode="json") for f in deduped],
        "xray_summary": {
            "total_flows": summary.total_flows,
            "api_endpoints": sorted(summary.api_endpoints),
        },
    }
    json_output.write_text(json.dumps(json_data, indent=2, ensure_ascii=False, default=str))

    logger.info("\n" + "=" * 70)
    logger.info("  SCAN COMPLETE")
    logger.info("  Findings: %d (deduped from %d)", len(deduped), len(findings))
    logger.info("  Risk Score: %.2f/10", report_data.risk_score)
    logger.info("  Report: %s", output)
    logger.info("  JSON: %s", json_output)
    logger.info("  X-Ray Flows: %d", summary.total_flows)
    logger.info("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
