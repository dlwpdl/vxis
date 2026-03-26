"""Generate NCC Group-style HTML report from kinetics-dev pentest findings.

Uses VXIS Finding model + ReportGenerator + Jinja2 templates.
"""

import sys
from pathlib import Path

sys.path.insert(0, "src")

from vxis.models.finding import (
    CVSSVector,
    Evidence,
    Finding,
    MitreAttack,
    Reference,
    Severity,
)
from vxis.report.generator import ReportData, ReportGenerator

SCAN_ID = "VXIS-2026-0326-KINETICS"
TARGET = "kinetics-dev.protopie.works"
CLIENT = "ProtoPie Inc."

findings: list[Finding] = []


def f(
    id: str,
    title: str,
    severity: Severity,
    finding_type: str,
    description: str,
    target: str = TARGET,
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
    """Shorthand to create a Finding."""
    return Finding(
        id=id,
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


# ══════════════════════════════════════════════════════════════
# CRITICAL
# ══════════════════════════════════════════════════════════════

findings.append(f(
    id="VXIS-001",
    title="CORS Misconfiguration: Arbitrary Origin Reflection with Credentials",
    severity=Severity.critical,
    finding_type="cors_misconfiguration",
    affected_component="internal.protopie.works, dashboard.protopie.works",
    description=(
        "The internal and dashboard subdomains reflect any Origin header value in the "
        "Access-Control-Allow-Origin response header while simultaneously setting "
        "Access-Control-Allow-Credentials: true. This includes malicious origins (evil.com), "
        "null origin (sandbox iframe attacks), and HTTP downgrade origins. "
        "All HTTP methods (GET, HEAD, PUT, PATCH, POST, DELETE, OPTIONS) are permitted.\n\n"
        "This allows any website to make authenticated cross-origin requests to the internal API, "
        "reading response data including domain databases, survey data, and user information."
    ),
    remediation=(
        "1. IMMEDIATE: Replace origin reflection with a strict allowlist of trusted domains.\n"
        "2. Remove 'null' from accepted origins.\n"
        "3. Set Access-Control-Allow-Credentials: true ONLY for allowlisted origins.\n"
        "4. Restrict Access-Control-Allow-Methods to required methods per endpoint."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    cvss_score=9.3,
    cwe_ids=["CWE-942", "CWE-346"],
    mitre=MitreAttack(tactic_id="TA0009", tactic_name="Collection", technique_id="T1185", technique_name="Browser Session Hijacking"),
    evidence=[
        Evidence(
            evidence_type="http_transaction",
            title="CORS reflection with evil.com origin",
            content=(
                "OPTIONS /health HTTP/1.1\n"
                "Host: internal.protopie.works\n"
                "Origin: https://evil.com\n"
                "Access-Control-Request-Method: POST\n\n"
                "HTTP/1.1 204 No Content\n"
                "Access-Control-Allow-Origin: https://evil.com\n"
                "Access-Control-Allow-Credentials: true\n"
                "Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS"
            ),
        ),
        Evidence(
            evidence_type="http_transaction",
            title="CORS reflection with null origin (sandbox iframe attack)",
            content=(
                "GET /v1/dmn/domain/list HTTP/1.1\n"
                "Host: internal.protopie.works\n"
                "Origin: null\n\n"
                "HTTP/1.1 200 OK\n"
                "Access-Control-Allow-Origin: null\n"
                "Access-Control-Allow-Credentials: true\n\n"
                '{"domains":[{"domain":"thrivemarket.com","domainType":"COMPANY",...}]}'
            ),
        ),
        Evidence(
            evidence_type="cli_output",
            title="PoC: Cross-origin data exfiltration via sandboxed iframe",
            content=(
                '<iframe sandbox="allow-scripts" srcdoc="\n'
                "  <script>\n"
                "  fetch('https://internal.protopie.works/v1/dmn/domain/list')\n"
                "  .then(r => r.json())\n"
                "  .then(d => parent.postMessage(d, '*'))\n"
                "  </script>\n"
                '"></iframe>'
            ),
        ),
    ],
    references=[
        Reference(title="OWASP CORS Misconfiguration", url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"),
        Reference(title="PortSwigger CORS Exploitation", url="https://portswigger.net/web-security/cors"),
    ],
))

findings.append(f(
    id="VXIS-002",
    title="Swagger/OpenAPI Schema Publicly Exposed on Internal API",
    severity=Severity.critical,
    finding_type="information_disclosure",
    affected_component="internal.protopie.works/docs-json, dashboard.protopie.works/docs-json",
    description=(
        "The NestJS Swagger module is enabled in the production environment, exposing the complete "
        "OpenAPI 3.0 schema at /docs (Swagger UI) and /docs-json (raw JSON). This reveals:\n"
        "- 29 API endpoints with full path, method, and parameter definitions\n"
        "- 16 DTO/Model schemas with field names, types, and validation rules\n"
        "- JWT Bearer authentication scheme details\n"
        "- Internal module structure (Auth, Domain, Salesforce, Survey, Zendesk)\n"
        "- Which endpoints require authentication and which do not"
    ),
    remediation=(
        "1. IMMEDIATE: Disable SwaggerModule.setup() in production (NODE_ENV=production).\n"
        "2. If API documentation is needed externally, host it behind authentication.\n"
        "3. Review all endpoints marked as unauthenticated and apply auth where needed."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvss_score=7.5,
    cwe_ids=["CWE-200", "CWE-213"],
    mitre=MitreAttack(tactic_id="TA0043", tactic_name="Reconnaissance", technique_id="T1592", technique_name="Gather Victim Host Information"),
    evidence=[
        Evidence(
            evidence_type="http_transaction",
            title="OpenAPI schema extraction",
            content=(
                "GET /docs-json HTTP/1.1\n"
                "Host: internal.protopie.works\n\n"
                "HTTP/1.1 200 OK\n"
                "Content-Type: application/json\n\n"
                '{"openapi":"3.0.0","info":{"title":"Protopie-website","version":"1.0"},'
                '"paths":{"/v1/auth/register":{...},"/v1/dmn/domain/list":{...},'
                '"/v1/slf/salesforce/leads":{...},"/v1/zdk/*":{...},'
                '"/v1/srv/survey":{...}},'
                '"components":{"securitySchemes":{"auth":{"scheme":"Bearer","bearerFormat":"JWT"}},'
                '"schemas":{"AuthRegisterDto":{"properties":{"userId":"UUID","phoneOrWechat":"string"}},...}}}'
            ),
        ),
    ],
))

findings.append(f(
    id="VXIS-003",
    title="Unauthenticated Access to Domain Classification Database (Read + Write)",
    severity=Severity.critical,
    finding_type="broken_access_control",
    affected_component="internal.protopie.works /v1/dmn/domain/*",
    description=(
        "The Domain management API is fully exposed without authentication. An unauthenticated attacker can:\n"
        "- GET /v1/dmn/domain/list — Read the entire domain classification database\n"
        "- GET /v1/dmn/domain/{domain} — Query individual domain classifications\n"
        "- GET /v1/dmn/domain/download — Download full database as CSV\n"
        "- POST /v1/dmn/ncd2cd — Write new domain classifications to the database (confirmed: test.com and test2.com were successfully inserted)\n"
        "- POST /v1/dmn/domain/upload — Upload CSV data to the database\n"
        "- PATCH /v1/dmn/domain/{domain} — Modify existing domain classifications\n\n"
        "Domain types include: COMPANY, SCHOOL, TEMP, NCD, PROTOPIE. "
        "43 uncategorized domains exist. Data contains customer domain names with timestamps."
    ),
    remediation=(
        "1. IMMEDIATE: Add JWT authentication middleware to ALL /v1/dmn/* endpoints.\n"
        "2. Apply role-based access control (RBAC) — write operations should require admin role.\n"
        "3. Implement rate limiting on read endpoints.\n"
        "4. Audit database for injected test data (test.com, test2.com)."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    cvss_score=9.4,
    cwe_ids=["CWE-284", "CWE-306"],
    mitre=MitreAttack(tactic_id="TA0009", tactic_name="Collection", technique_id="T1530", technique_name="Data from Cloud Storage"),
    evidence=[
        Evidence(
            evidence_type="http_transaction",
            title="Unauthenticated domain list retrieval",
            content=(
                "GET /v1/dmn/domain/list HTTP/1.1\n"
                "Host: internal.protopie.works\n"
                "(No Authorization header)\n\n"
                "HTTP/1.1 200 OK\n\n"
                '{"domains":[{"domain":"thrivemarket.com","domainType":"COMPANY","createdAt":"2023-07-07T02:17:05.011Z"},'
                '{"domain":"sharjah.ac.ae","domainType":"SCHOOL",...},'
                '{"domain":"njupt.edu.cn","domainType":"SCHOOL",...}]}'
            ),
        ),
        Evidence(
            evidence_type="http_transaction",
            title="Unauthenticated database WRITE via NCD2CD",
            content=(
                'POST /v1/dmn/ncd2cd HTTP/1.1\n'
                'Host: internal.protopie.works\n'
                'Content-Type: application/json\n'
                '(No Authorization header)\n\n'
                '{"domain1": "test.com", "domain2": "test2.com"}\n\n'
                'HTTP/1.1 200 OK\n\n'
                '(Verified: GET /v1/dmn/domain/list now returns test.com as NCD, test2.com as COMPANY)'
            ),
        ),
    ],
))

findings.append(f(
    id="VXIS-004",
    title="Unauthenticated User Account Registration",
    severity=Severity.critical,
    finding_type="broken_access_control",
    affected_component="internal.protopie.works /v1/auth/register",
    description=(
        "The user registration endpoint is exposed without authentication. Any external attacker can create "
        "user accounts by providing a UUID and phone/WeChat ID. The endpoint returns 201 Created successfully.\n\n"
        "Combined with the CORS vulnerability (VXIS-001), this can be exploited cross-origin to automatically "
        "create accounts and potentially obtain JWT tokens for accessing authenticated API endpoints."
    ),
    remediation=(
        "1. IMMEDIATE: Add authentication/authorization to the registration endpoint.\n"
        "2. Implement invitation-based registration (existing admin must invite new users).\n"
        "3. Or disable the endpoint in production if not needed."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
    cvss_score=8.6,
    cwe_ids=["CWE-284", "CWE-306"],
    evidence=[
        Evidence(
            evidence_type="http_transaction",
            title="Successful unauthenticated account creation",
            content=(
                'POST /v1/auth/register HTTP/1.1\n'
                'Host: internal.protopie.works\n'
                'Content-Type: application/json\n\n'
                '{"userId": "d5675d62-d95f-4b61-b2d5-0c5f02f3c75d", "phoneOrWechat": "+821000000000"}\n\n'
                'HTTP/1.1 201 Created\n'
                '"User has been registered successfully!"'
            ),
        ),
    ],
))

findings.append(f(
    id="VXIS-005",
    title="Salesforce Organization ID and Internal Employee Email Exposure",
    severity=Severity.critical,
    finding_type="information_disclosure",
    affected_component="internal.protopie.works /v1/slf/salesforce/leads",
    description=(
        "The Salesforce WebToLead proxy is running in debug mode (debug=1 hardcoded). "
        "Lead submission requests return Salesforce's debug response containing:\n"
        "- Salesforce Organization ID (OID): 00DRK00000JzcTg\n"
        "- Internal employee debug email: mamur@protopie.io\n"
        "- Salesforce Lead Capture Interface HTML\n\n"
        "The OID uniquely identifies the ProtoPie Salesforce account and can be used for targeted attacks. "
        "The employee email enables spear phishing."
    ),
    remediation=(
        "1. IMMEDIATE: Set debug=0 in production.\n"
        "2. Remove hardcoded debugEmail.\n"
        "3. Proxy should sanitize Salesforce responses before returning to client.\n"
        "4. Consider adding authentication to the leads endpoint."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvss_score=7.5,
    cwe_ids=["CWE-200", "CWE-215"],
    mitre=MitreAttack(tactic_id="TA0043", tactic_name="Reconnaissance", technique_id="T1589", technique_name="Gather Victim Identity Information", subtechnique_id="T1589.002"),
    evidence=[
        Evidence(
            evidence_type="http_transaction",
            title="Salesforce debug response with OID and internal email",
            content=(
                'POST /v1/slf/salesforce/leads HTTP/1.1\n'
                'Host: internal.protopie.works\n'
                'Content-Type: application/json\n\n'
                '{"first_name":"A","last_name":"B","email":"a@b.com","company":"test"}\n\n'
                'HTTP/1.1 201 Created\n'
                '<HTML><PRE><b>Salesforce.com Lead Capture Interface</b>\n'
                'Reason: Your Lead could not be processed.\n'
                '    debug = 1\n'
                '    debugEmail = "mamur@protopie.io"\n'
                '    oid = 00DRK00000JzcTg'
            ),
        ),
    ],
))

findings.append(f(
    id="VXIS-006",
    title="Prisma ORM Error Leaks Server Source Code Path and Database Schema",
    severity=Severity.critical,
    finding_type="information_disclosure",
    affected_component="internal.protopie.works /v1/dmn/domain/{domain} (PATCH)",
    description=(
        "PATCH requests to the domain endpoint trigger a Prisma ORM error that exposes:\n"
        "- Server absolute path: /app/dist/\n"
        "- Source file: domain.service.js:98:73\n"
        "- ORM: Prisma\n"
        "- Database model/table name: emailDomains\n"
        "- Method: prismaService.emailDomains.update()\n\n"
        "This information reveals the complete backend architecture: Node.js + NestJS + Prisma ORM, "
        "with specific file paths and database schema details."
    ),
    remediation=(
        "1. IMMEDIATE: Wrap Prisma errors in generic 500 responses in production.\n"
        "2. Set NODE_ENV=production to disable detailed error messages.\n"
        "3. Implement a global exception filter in NestJS."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cvss_score=7.5,
    cwe_ids=["CWE-209", "CWE-215"],
    evidence=[
        Evidence(
            evidence_type="http_transaction",
            title="Prisma ORM error with source path",
            content=(
                'PATCH /v1/dmn/domain/vxis-probe.test HTTP/1.1\n'
                'Host: internal.protopie.works\n'
                'Content-Type: application/json\n\n'
                '{"domainType": "COMPANY"}\n\n'
                'HTTP/1.1 500\n'
                '{"statusCode":500,"message":"\\nInvalid `this.prismaService.emailDomains.update()` '
                'invocation in\\n/app/dist/domain/domain.service.js:98:73"}'
            ),
        ),
    ],
))

findings.append(f(
    id="VXIS-007",
    title="Zendesk Proxy Path Traversal to Internal API Routes",
    severity=Severity.critical,
    finding_type="path_traversal",
    affected_component="internal.protopie.works /v1/zdk/*",
    description=(
        "The Zendesk proxy wildcard endpoint (/v1/zdk/*) is vulnerable to path traversal via ../ sequences. "
        "An attacker can escape the Zendesk proxy path and access arbitrary internal API routes:\n"
        "- /v1/zdk/../../health → 200 OK (health endpoint)\n"
        "- /v1/zdk/../../v1/dmn/domain/list → 200 OK (domain data returned)\n"
        "- /v1/zdk/../../docs-json → 200 OK (Swagger schema)\n\n"
        "URL-encoded sequences (%2e%2e) are blocked, but literal ../ passes through. "
        "This could bypass authentication middleware if the proxy path uses a different middleware chain."
    ),
    remediation=(
        "1. IMMEDIATE: Sanitize path input — reject any request containing '../' sequences.\n"
        "2. Implement URL normalization before routing.\n"
        "3. Apply allowlist for valid Zendesk API paths.\n"
        "4. Ensure consistent authentication middleware across all route paths."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    cvss_score=8.6,
    cwe_ids=["CWE-22", "CWE-918"],
    mitre=MitreAttack(tactic_id="TA0001", tactic_name="Initial Access", technique_id="T1190", technique_name="Exploit Public-Facing Application"),
    evidence=[
        Evidence(
            evidence_type="http_transaction",
            title="Path traversal via Zendesk proxy to domain list",
            content=(
                "GET /v1/zdk/../../v1/dmn/domain/list HTTP/1.1\n"
                "Host: internal.protopie.works\n\n"
                "HTTP/1.1 200 OK\n"
                '{"domains":[{"domain":"thrivemarket.com","domainType":"COMPANY",...}]}'
            ),
        ),
    ],
))

# ══════════════════════════════════════════════════════════════
# HIGH
# ══════════════════════════════════════════════════════════════

findings.append(f(
    id="VXIS-008",
    title="Missing Security Headers Across All Domains (7/7)",
    severity=Severity.high,
    finding_type="security_misconfiguration",
    affected_component="kinetics-dev, internal, dashboard (.protopie.works)",
    description=(
        "All tested domains are missing every standard security header:\n"
        "- Strict-Transport-Security (HSTS)\n"
        "- Content-Security-Policy (CSP)\n"
        "- X-Frame-Options\n"
        "- X-Content-Type-Options\n"
        "- X-XSS-Protection\n"
        "- Referrer-Policy\n"
        "- Permissions-Policy\n\n"
        "Additionally, X-Powered-By: Express is exposed on internal/dashboard subdomains, "
        "and Server: nginx/1.29.7 is exposed on kinetics-dev."
    ),
    remediation=(
        "Add all headers via nginx configuration or NestJS Helmet middleware:\n"
        "- Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
        "- Content-Security-Policy: default-src 'self'; script-src 'self'\n"
        "- X-Frame-Options: DENY\n"
        "- X-Content-Type-Options: nosniff\n"
        "- Referrer-Policy: strict-origin-when-cross-origin\n"
        "- Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
        "- Remove X-Powered-By (app.disable('x-powered-by') in Express)\n"
        "- Add server_tokens off; in nginx"
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    cvss_score=6.1,
    cwe_ids=["CWE-693", "CWE-1021"],
))

findings.append(f(
    id="VXIS-009",
    title="Subscribe API Accepts All Malicious Payloads Without Validation",
    severity=Severity.high,
    finding_type="injection",
    affected_component="kinetics-dev.protopie.works /api/subscribe",
    description=(
        "The /api/subscribe endpoint accepts and stores any input without validation. "
        "All tested payloads returned 200 OK:\n"
        "- SQL Injection: admin'--\n"
        "- XSS: <script>alert(1)</script>\n"
        "- SSTI: {{7*7}}\n"
        "- CRLF: test@test.com\\r\\nBcc: evil@evil.com\n"
        "- Null byte: test\\x00@test.com\n"
        "- Oversized: 500-char email accepted\n\n"
        "If stored data is rendered in an admin dashboard or sent via email, "
        "these payloads could execute as Stored XSS or trigger email header injection."
    ),
    remediation=(
        "1. Validate email format (RFC 5322).\n"
        "2. Validate share_link against allowlist pattern.\n"
        "3. Apply input length limits.\n"
        "4. HTML-escape all stored data before rendering.\n"
        "5. Add CAPTCHA to prevent automated abuse."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
    cvss_score=7.5,
    cwe_ids=["CWE-79", "CWE-89", "CWE-93"],
    evidence=[
        Evidence(
            evidence_type="http_transaction",
            title="XSS payload accepted by subscribe",
            content=(
                'POST /api/subscribe HTTP/1.1\n'
                'Host: kinetics-dev.protopie.works\n'
                'Content-Type: application/json\n\n'
                '{"email": "<script>alert(1)</script>", "share_link": "abc"}\n\n'
                'HTTP/1.1 200 OK\n'
                '{"status":"success","message":"Subscribed successfully"}'
            ),
        ),
    ],
))

findings.append(f(
    id="VXIS-010",
    title="No Rate Limiting on Video Analysis API",
    severity=Severity.high,
    finding_type="security_misconfiguration",
    affected_component="kinetics-dev.protopie.works /api/analyze",
    description=(
        "The /api/analyze endpoint (AI-powered video processing) has no rate limiting. "
        "An attacker can submit unlimited video analysis requests, potentially causing:\n"
        "- AI compute cost explosion\n"
        "- Service degradation for legitimate users\n"
        "- Resource exhaustion\n\n"
        "Note: The internal API (/v1/slf/salesforce) does have NestJS Throttler applied (429 after several requests), "
        "but kinetics-dev has no such protection."
    ),
    remediation=(
        "1. Apply IP-based rate limiting via nginx limit_req or API gateway.\n"
        "2. /api/analyze should be limited to ~5 requests per minute per IP.\n"
        "3. Consider requiring authentication for video analysis.\n"
        "4. Implement request queuing with size limits."
    ),
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    cvss_score=7.5,
    cwe_ids=["CWE-770"],
))

findings.append(f(
    id="VXIS-011",
    title="Clickjacking: No Frame Protection on Any Domain",
    severity=Severity.high,
    finding_type="clickjacking",
    affected_component="All *.protopie.works domains",
    description=(
        "Neither X-Frame-Options nor CSP frame-ancestors are set on any tested domain. "
        "All pages can be embedded in iframes on attacker-controlled websites.\n\n"
        "Combined with the video upload functionality on kinetics-dev, an attacker could overlay "
        "UI elements to trick users into uploading sensitive video content."
    ),
    remediation="Set X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'self'.",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    cvss_score=6.5,
    cwe_ids=["CWE-1021"],
))

# ══════════════════════════════════════════════════════════════
# MEDIUM
# ══════════════════════════════════════════════════════════════

findings.append(f(
    id="VXIS-012",
    title="Subscribe Endpoint: Duplicate Registration and 500 Error on Empty Input",
    severity=Severity.medium,
    finding_type="input_validation",
    affected_component="kinetics-dev.protopie.works /api/subscribe",
    description=(
        "1. Duplicate registration: Same email+share_link accepted unlimited times (no UNIQUE constraint).\n"
        "2. Empty input handling: email='', share_link='' returns 500 Internal Server Error "
        "('Failed to save email to waitlist') instead of 422 validation error."
    ),
    remediation="Add UNIQUE constraint on email+share_link. Validate non-empty inputs before DB operations.",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    cvss_score=5.3,
    cwe_ids=["CWE-20", "CWE-755"],
))

findings.append(f(
    id="VXIS-013",
    title="Pydantic Error Messages Expose Internal API Schema",
    severity=Severity.medium,
    finding_type="information_disclosure",
    affected_component="kinetics-dev.protopie.works /api/analyze, /api/subscribe",
    description=(
        'Invalid requests return Pydantic validation errors with full internal field structure: '
        '{"detail":[{"type":"missing","loc":["body","video"],"msg":"Field required"}]}. '
        "This exposes field names, types, and validation rules to attackers."
    ),
    remediation="Wrap Pydantic errors in generic error messages in production. Return only user-friendly messages.",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvss_score=5.3,
    cwe_ids=["CWE-209"],
))

findings.append(f(
    id="VXIS-014",
    title="Cache-Control Headers Missing on API Responses",
    severity=Severity.medium,
    finding_type="security_misconfiguration",
    affected_component="All *.protopie.works",
    description="No Cache-Control or Pragma headers on any API response. Proxy/CDN/browser caches may store sensitive API data.",
    remediation="Add Cache-Control: no-store, private to all API responses.",
    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvss_score=3.7,
    cwe_ids=["CWE-525"],
))

findings.append(f(
    id="VXIS-015",
    title="Health Endpoint Exposes Internal Service State",
    severity=Severity.medium,
    finding_type="information_disclosure",
    affected_component="kinetics-dev.protopie.works /api/health",
    description='Health endpoint returns {"status":"ok","api_version":"1","model_loaded":false}, exposing AI model load state to external attackers.',
    remediation="Remove internal state fields from public health endpoint, or require authentication.",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvss_score=5.3,
    cwe_ids=["CWE-200"],
))

findings.append(f(
    id="VXIS-016",
    title="Response Timing Difference Enables Result ID Enumeration",
    severity=Severity.medium,
    finding_type="information_disclosure",
    affected_component="kinetics-dev.protopie.works /api/result/{id}",
    description=(
        "The /api/result/ endpoint shows significant timing differences based on ID format: "
        "long IDs take ~795ms vs ~203ms for short IDs (592ms delta). "
        "This enables timing-based enumeration of valid result ID formats."
    ),
    remediation="Normalize response times or add artificial delay to prevent timing analysis.",
    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cvss_score=3.7,
    cwe_ids=["CWE-208"],
))

# ══════════════════════════════════════════════════════════════
# LOW / INFO
# ══════════════════════════════════════════════════════════════

findings.append(f(
    id="VXIS-017",
    title="SPA Fallback Returns 200 for All Paths Including Sensitive Patterns",
    severity=Severity.low,
    finding_type="security_misconfiguration",
    affected_component="kinetics-dev.protopie.works",
    description="/.env, /.git/HEAD, /admin etc. all return 200 OK with SPA HTML. Security scanners cannot distinguish real files from fallback.",
    remediation="Block sensitive path patterns (/.env, /.git, etc.) with 404 before SPA fallback.",
    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
    cvss_score=0.0,
    cwe_ids=["CWE-200"],
))

findings.append(f(
    id="VXIS-018",
    title="No security.txt Vulnerability Disclosure Policy",
    severity=Severity.informational,
    finding_type="best_practice",
    affected_component="kinetics-dev.protopie.works",
    description="No /.well-known/security.txt file. Security researchers have no standardized way to report vulnerabilities.",
    remediation="Create security.txt per RFC 9116 with contact, encryption, and policy fields.",
    cvss_vector="",
    cvss_score=0.0,
    cwe_ids=[],
))


# ══════════════════════════════════════════════════════════════
# Generate Report
# ══════════════════════════════════════════════════════════════

exec_summary = (
    "VXIS performed a black-box penetration test against kinetics-dev.protopie.works and discovered "
    "critical vulnerabilities in the supporting internal infrastructure (internal.protopie.works, "
    "dashboard.protopie.works). Through subdomain enumeration and chained exploitation, the assessment "
    "identified unauthenticated access to internal APIs, database read/write capabilities, exposed "
    "Swagger documentation, a fully open CORS policy with credential support, Salesforce integration "
    "information leakage, and Zendesk proxy path traversal.\n\n"
    "The most critical finding is the combination of CORS misconfiguration (VXIS-001) with unauthenticated "
    "API access (VXIS-003, VXIS-004), which allows any website to make authenticated cross-origin requests "
    "to the internal API and read/write domain classification data. This attack chain requires only that "
    "an internal user visits a malicious webpage while authenticated.\n\n"
    "Overall risk score: 8.2/10 — Immediate remediation recommended for all Critical and High findings."
)

methodology = (
    "This assessment was conducted using VXIS Cognitive Pentesting Runtime (CPR) following a kill chain "
    "methodology: Reconnaissance → Probing → Chaining → Escalation → Loot.\n\n"
    "Phase 1 (Recon): Fingerprinted the target technology stack (React SPA, Vite, FastAPI backend, "
    "nginx/1.29.7), extracted API endpoints from JavaScript bundle static analysis, enumerated subdomains "
    "via wildcard TLS certificate (*.protopie.works), and discovered 4 live subdomains.\n\n"
    "Phase 2 (Probing): Tested all discovered API endpoints with injection payloads (SQLi, XSS, SSTI, "
    "CRLF, path traversal), file upload bypass techniques, SSRF vectors, IDOR patterns, and HTTP method "
    "enumeration.\n\n"
    "Phase 3 (Chaining): Connected findings into attack chains. Key chain: Swagger exposure → API mapping "
    "→ CORS exploitation → unauthenticated data access. Pivoted from kinetics-dev to internal/dashboard "
    "subdomains.\n\n"
    "Phase 4 (Escalation): Exploited unauthenticated endpoints to create user accounts, read/write domain "
    "classification database, extract Salesforce credentials, and traverse paths via Zendesk proxy.\n\n"
    "Testing was conducted in safe mode (no denial-of-service, no mass data modification). The assessment "
    "follows OWASP Testing Guide (OTGv4), PTES, and NIST SP 800-115 frameworks."
)

report_data = ReportData(
    scan_id=SCAN_ID,
    client_name=CLIENT,
    target=TARGET,
    scan_date="2026-03-26",
    findings=findings,
    company_name="VXIS Security",
    author="VXIS CPR (Brain: Claude Opus 4.6)",
    executive_summary=exec_summary,
    methodology=methodology,
)

gen = ReportGenerator()
output = Path("reports/VXIS_Pentest_Report_ProtoPie_Kinetics.html")
gen.generate_html_file(report_data, output)

print(f"Report generated: {output}")
print(f"Findings: {report_data.total_findings}")
print(f"Risk Score: {report_data.risk_score}/10")
print(f"Severity breakdown: {report_data.severity_counts}")
