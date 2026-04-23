"""VXIS Attack Vector Registry.

각 타겟 타입(web/game/mobile)에 대한 공격 벡터 정의.
벡터 커버리지 스코어링의 Ground Truth로 사용된다.

네이밍 규칙:
  WEB-{CATEGORY}-{SEQ:03d}
  GAME-{CATEGORY}-{SEQ:03d}
  MOB-{CATEGORY}-{SEQ:03d}
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackVector:
    """단일 공격 벡터 정의."""

    id: str               # "WEB-SQLI-001"
    category: str         # "injection"
    name_en: str          # "SQL Injection — Union Based"
    name_ko: str          # "SQL 인젝션 — Union 기반"
    target_types: tuple[str, ...]  # ("web",) or ("web", "game")
    phase: str            # "Phase 5" — 해당 벡터를 테스트하는 Phase
    max_depth: int        # 0-4 (최대 익스플로잇 레벨)
    owasp_id: str         # "A03:2021" or "M1" (mobile)


# ─────────────────────────────────────────────
# WEB VECTORS (~55개)
# ─────────────────────────────────────────────

WEB_VECTORS: tuple[AttackVector, ...] = (
    # ── Injection: SQL ──
    AttackVector(
        id="WEB-SQLI-001", category="injection",
        name_en="SQL Injection — Union Based",
        name_ko="SQL 인젝션 — Union 기반",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-SQLI-002", category="injection",
        name_en="SQL Injection — Boolean Blind",
        name_ko="SQL 인젝션 — Boolean Blind",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-SQLI-003", category="injection",
        name_en="SQL Injection — Time Based Blind",
        name_ko="SQL 인젝션 — 시간 기반 Blind",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-SQLI-004", category="injection",
        name_en="SQL Injection — Error Based",
        name_ko="SQL 인젝션 — 에러 기반",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-SQLI-005", category="injection",
        name_en="SQL Injection — Out-of-Band (DNS/HTTP)",
        name_ko="SQL 인젝션 — Out-of-Band (DNS/HTTP)",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-SQLI-006", category="injection",
        name_en="SQL Injection — Second Order",
        name_ko="SQL 인젝션 — 이차 주입",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    # ── Injection: NoSQL ──
    AttackVector(
        id="WEB-NOSQL-001", category="injection",
        name_en="NoSQL Injection — MongoDB Operator",
        name_ko="NoSQL 인젝션 — MongoDB 연산자",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-NOSQL-002", category="injection",
        name_en="NoSQL Injection — JavaScript Injection",
        name_ko="NoSQL 인젝션 — JavaScript 주입",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    # ── Injection: Command ──
    AttackVector(
        id="WEB-CMDI-001", category="injection",
        name_en="OS Command Injection — Direct",
        name_ko="OS 명령 주입 — 직접",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-CMDI-002", category="injection",
        name_en="OS Command Injection — Blind (OOB)",
        name_ko="OS 명령 주입 — Blind OOB",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    # ── Injection: LDAP ──
    AttackVector(
        id="WEB-LDAP-001", category="injection",
        name_en="LDAP Injection",
        name_ko="LDAP 인젝션",
        target_types=("web",), phase="Phase 5", max_depth=3,
        owasp_id="A03:2021",
    ),
    # ── Injection: XPath ──
    AttackVector(
        id="WEB-XPATH-001", category="injection",
        name_en="XPath Injection",
        name_ko="XPath 인젝션",
        target_types=("web",), phase="Phase 5", max_depth=3,
        owasp_id="A03:2021",
    ),
    # ── Injection: Template (SSTI) ──
    AttackVector(
        id="WEB-SSTI-001", category="injection",
        name_en="Server-Side Template Injection (SSTI)",
        name_ko="서버사이드 템플릿 인젝션 (SSTI)",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    # ── XSS ──
    AttackVector(
        id="WEB-XSS-001", category="xss",
        name_en="Cross-Site Scripting — Reflected",
        name_ko="XSS — 반사형",
        target_types=("web",), phase="Phase 6", max_depth=2,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-XSS-002", category="xss",
        name_en="Cross-Site Scripting — Stored",
        name_ko="XSS — 저장형",
        target_types=("web",), phase="Phase 6", max_depth=3,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-XSS-003", category="xss",
        name_en="Cross-Site Scripting — DOM Based",
        name_ko="XSS — DOM 기반",
        target_types=("web",), phase="Phase 6", max_depth=2,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-XSS-004", category="xss",
        name_en="Cross-Site Scripting — Mutation (mXSS)",
        name_ko="XSS — Mutation (mXSS)",
        target_types=("web",), phase="Phase 6", max_depth=2,
        owasp_id="A03:2021",
    ),
    # ── SSRF ──
    AttackVector(
        id="WEB-SSRF-001", category="ssrf",
        name_en="SSRF — Direct Response",
        name_ko="SSRF — 직접 응답",
        target_types=("web",), phase="Phase 7", max_depth=4,
        owasp_id="A10:2021",
    ),
    AttackVector(
        id="WEB-SSRF-002", category="ssrf",
        name_en="SSRF — Blind (OOB DNS/HTTP)",
        name_ko="SSRF — Blind OOB",
        target_types=("web",), phase="Phase 7", max_depth=3,
        owasp_id="A10:2021",
    ),
    AttackVector(
        id="WEB-SSRF-003", category="ssrf",
        name_en="SSRF — DNS Rebinding",
        name_ko="SSRF — DNS 리바인딩",
        target_types=("web",), phase="Phase 7", max_depth=4,
        owasp_id="A10:2021",
    ),
    # ── Auth ──
    AttackVector(
        id="WEB-AUTH-001", category="auth",
        name_en="Brute Force — Login Endpoint",
        name_ko="무차별 대입 공격 — 로그인 엔드포인트",
        target_types=("web",), phase="Phase 4", max_depth=3,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-002", category="auth",
        name_en="Default Credentials",
        name_ko="기본 자격증명",
        target_types=("web",), phase="Phase 4", max_depth=3,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-003", category="auth",
        name_en="JWT — Algorithm Confusion (RS256→HS256)",
        name_ko="JWT — 알고리즘 혼동 (RS256→HS256)",
        target_types=("web",), phase="Phase 4", max_depth=4,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-004", category="auth",
        name_en="JWT — None Algorithm",
        name_ko="JWT — None 알고리즘",
        target_types=("web",), phase="Phase 4", max_depth=4,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-005", category="auth",
        name_en="Session Fixation",
        name_ko="세션 고정",
        target_types=("web",), phase="Phase 4", max_depth=3,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-006", category="auth",
        name_en="Session Hijacking — Cookie Theft",
        name_ko="세션 하이재킹 — 쿠키 탈취",
        target_types=("web",), phase="Phase 4", max_depth=3,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-007", category="auth",
        name_en="OAuth 2.0 — Open Redirect / State Bypass",
        name_ko="OAuth 2.0 — 오픈 리다이렉트 / State 우회",
        target_types=("web",), phase="Phase 4", max_depth=3,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-008", category="auth",
        name_en="Password Reset Poisoning",
        name_ko="패스워드 리셋 포이즈닝",
        target_types=("web",), phase="Phase 4", max_depth=3,
        owasp_id="A07:2021",
    ),
    # ── Access Control ──
    AttackVector(
        id="WEB-AC-001", category="access_control",
        name_en="IDOR — Direct Object Reference",
        name_ko="IDOR — 직접 객체 참조",
        target_types=("web",), phase="Phase 8", max_depth=4,
        owasp_id="A01:2021",
    ),
    AttackVector(
        id="WEB-AC-002", category="access_control",
        name_en="Privilege Escalation — Horizontal",
        name_ko="권한 상승 — 수평",
        target_types=("web",), phase="Phase 8", max_depth=4,
        owasp_id="A01:2021",
    ),
    AttackVector(
        id="WEB-AC-003", category="access_control",
        name_en="Privilege Escalation — Vertical",
        name_ko="권한 상승 — 수직",
        target_types=("web",), phase="Phase 8", max_depth=4,
        owasp_id="A01:2021",
    ),
    AttackVector(
        id="WEB-AC-004", category="access_control",
        name_en="Directory Traversal / Path Traversal",
        name_ko="디렉토리 탐색 / 경로 탐색",
        target_types=("web",), phase="Phase 8", max_depth=3,
        owasp_id="A01:2021",
    ),
    AttackVector(
        id="WEB-AC-005", category="access_control",
        name_en="Forced Browsing — Hidden Endpoints",
        name_ko="강제 브라우징 — 숨겨진 엔드포인트",
        target_types=("web",), phase="Phase 3", max_depth=2,
        owasp_id="A01:2021",
    ),
    # ── Security Misconfiguration ──
    AttackVector(
        id="WEB-MISCONF-001", category="misconfig",
        name_en="Debug Endpoints Exposed",
        name_ko="디버그 엔드포인트 노출",
        target_types=("web",), phase="Phase 3", max_depth=2,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-MISCONF-002", category="misconfig",
        name_en="Default Configuration Left Active",
        name_ko="기본 설정 활성화 상태",
        target_types=("web",), phase="Phase 3", max_depth=2,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-MISCONF-003", category="misconfig",
        name_en="Verbose Error Messages — Stack Trace Disclosure",
        name_ko="상세 에러 메시지 — 스택 트레이스 노출",
        target_types=("web",), phase="Phase 3", max_depth=1,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-MISCONF-004", category="misconfig",
        name_en="Missing Security Headers (CSP, HSTS, X-Frame)",
        name_ko="보안 헤더 누락 (CSP, HSTS, X-Frame)",
        target_types=("web",), phase="Phase 2", max_depth=1,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-MISCONF-005", category="misconfig",
        name_en="CORS Misconfiguration — Wildcard / Null Origin",
        name_ko="CORS 잘못된 설정 — 와일드카드 / Null 오리진",
        target_types=("web",), phase="Phase 2", max_depth=3,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-MISCONF-006", category="misconfig",
        name_en="Open Redirect",
        name_ko="오픈 리다이렉트",
        target_types=("web",), phase="Phase 6", max_depth=2,
        owasp_id="A05:2021",
    ),
    # ── Cryptographic Failures ──
    AttackVector(
        id="WEB-CRYPTO-001", category="crypto",
        name_en="Weak TLS Configuration (TLS 1.0/1.1, RC4, NULL)",
        name_ko="약한 TLS 설정 (TLS 1.0/1.1, RC4, NULL)",
        target_types=("web",), phase="Phase 2", max_depth=2,
        owasp_id="A02:2021",
    ),
    AttackVector(
        id="WEB-CRYPTO-002", category="crypto",
        name_en="Weak Hashing Algorithm (MD5, SHA1 for passwords)",
        name_ko="약한 해싱 알고리즘 (패스워드에 MD5, SHA1 사용)",
        target_types=("web",), phase="Phase 9", max_depth=2,
        owasp_id="A02:2021",
    ),
    AttackVector(
        id="WEB-CRYPTO-003", category="crypto",
        name_en="Hardcoded Secrets — Source Code / JS Bundle",
        name_ko="하드코딩된 시크릿 — 소스코드 / JS 번들",
        target_types=("web",), phase="Phase 9", max_depth=3,
        owasp_id="A02:2021",
    ),
    AttackVector(
        id="WEB-CRYPTO-004", category="crypto",
        name_en="Insecure Randomness — Predictable Tokens",
        name_ko="안전하지 않은 난수 — 예측 가능한 토큰",
        target_types=("web",), phase="Phase 9", max_depth=3,
        owasp_id="A02:2021",
    ),
    # ── Complex Web Attacks ──
    AttackVector(
        id="WEB-XXE-001", category="injection",
        name_en="XML External Entity (XXE) — File Read",
        name_ko="XML 외부 엔티티 (XXE) — 파일 읽기",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-DESER-001", category="injection",
        name_en="Insecure Deserialization — RCE",
        name_ko="안전하지 않은 역직렬화 — RCE",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A08:2021",
    ),
    AttackVector(
        id="WEB-UPLOAD-001", category="injection",
        name_en="Unrestricted File Upload — Webshell",
        name_ko="제한 없는 파일 업로드 — 웹쉘",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-RACE-001", category="logic",
        name_en="Race Condition — TOCTOU",
        name_ko="경쟁 조건 — TOCTOU",
        target_types=("web",), phase="Phase 10", max_depth=3,
        owasp_id="A04:2021",
    ),
    AttackVector(
        id="WEB-CSRF-001", category="auth",
        name_en="Cross-Site Request Forgery (CSRF)",
        name_ko="사이트 간 요청 위조 (CSRF)",
        target_types=("web",), phase="Phase 6", max_depth=2,
        owasp_id="A01:2021",
    ),
    AttackVector(
        id="WEB-WSS-001", category="injection",
        name_en="WebSocket — Message Injection",
        name_ko="WebSocket — 메시지 인젝션",
        target_types=("web",), phase="Phase 11", max_depth=3,
        owasp_id="A03:2021",
    ),
    # ── API-Specific ──
    AttackVector(
        id="WEB-API-001", category="api",
        name_en="Mass Assignment — Auto-binding Privilege Escalation",
        name_ko="대량 할당 — 자동 바인딩 권한 상승",
        target_types=("web",), phase="Phase 8", max_depth=3,
        owasp_id="A01:2021",
    ),
    AttackVector(
        id="WEB-API-002", category="api",
        name_en="Rate Limiting Bypass",
        name_ko="레이트 리미팅 우회",
        target_types=("web",), phase="Phase 12", max_depth=2,
        owasp_id="A04:2021",
    ),
    AttackVector(
        id="WEB-API-003", category="api",
        name_en="GraphQL — Introspection Enabled",
        name_ko="GraphQL — 인트로스펙션 활성화",
        target_types=("web",), phase="Phase 11", max_depth=1,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-API-004", category="api",
        name_en="GraphQL — Batching / DoS",
        name_ko="GraphQL — 배치 / DoS",
        target_types=("web",), phase="Phase 11", max_depth=2,
        owasp_id="A04:2021",
    ),
    AttackVector(
        id="WEB-API-005", category="api",
        name_en="REST — HTTP Verb Tampering",
        name_ko="REST — HTTP 메서드 변조",
        target_types=("web",), phase="Phase 8", max_depth=2,
        owasp_id="A01:2021",
    ),
    AttackVector(
        id="WEB-API-006", category="api",
        name_en="gRPC — Reflection Service Exposed",
        name_ko="gRPC — Reflection 서비스 노출",
        target_types=("web",), phase="Phase 2", max_depth=2,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-API-007", category="api",
        name_en="gRPC — Method Enumeration + Injection",
        name_ko="gRPC — 메서드 열거 + 인젝션",
        target_types=("web",), phase="Phase 5", max_depth=3,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-API-008", category="api",
        name_en="BOPLA — Broken Object Property Level Auth",
        name_ko="BOPLA — 객체 속성 수준 인증 손상",
        target_types=("web",), phase="Phase 8", max_depth=3,
        owasp_id="A01:2021",
    ),
    AttackVector(
        id="WEB-API-009", category="api",
        name_en="BFLA — Broken Function Level Auth",
        name_ko="BFLA — 기능 수준 인증 손상",
        target_types=("web",), phase="Phase 8", max_depth=3,
        owasp_id="A01:2021",
    ),
    # ── SAML / SSO ──
    AttackVector(
        id="WEB-AUTH-011", category="auth",
        name_en="SAML — Assertion Signing Bypass",
        name_ko="SAML — 서명 우회",
        target_types=("web",), phase="Phase 4", max_depth=4,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-012", category="auth",
        name_en="SAML — Replay Attack",
        name_ko="SAML — 리플레이 공격",
        target_types=("web",), phase="Phase 4", max_depth=3,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-AUTH-013", category="auth",
        name_en="OAuth — State Parameter Missing (CSRF)",
        name_ko="OAuth — State 파라미터 누락 (CSRF)",
        target_types=("web",), phase="Phase 4", max_depth=3,
        owasp_id="A01:2021",
    ),
    # ── Modern Injection ──
    AttackVector(
        id="WEB-INJECT-022", category="injection",
        name_en="Prototype Pollution — JSON Merge",
        name_ko="프로토타입 오염 — JSON Merge",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-INJECT-023", category="injection",
        name_en="CSP Bypass — Script-src Nonce Leak",
        name_ko="CSP 우회 — Script-src Nonce 유출",
        target_types=("web",), phase="Phase 3", max_depth=2,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-INJECT-024", category="injection",
        name_en="Cache Poisoning — Web Cache Deception",
        name_ko="캐시 오염 — 웹 캐시 기만",
        target_types=("web",), phase="Phase 5", max_depth=3,
        owasp_id="A03:2021",
    ),
    # ── Infrastructure ──
    AttackVector(
        id="WEB-INFRA-001", category="infrastructure",
        name_en="Subdomain Takeover",
        name_ko="서브도메인 탈취",
        target_types=("web",), phase="Phase 1", max_depth=3,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-INFRA-002", category="infrastructure",
        name_en="DNS Zone Transfer",
        name_ko="DNS 존 전송",
        target_types=("web",), phase="Phase 1", max_depth=1,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-INFRA-003", category="infrastructure",
        name_en="Cloud Misconfiguration — S3 Bucket Public",
        name_ko="클라우드 설정 오류 — S3 버킷 공개",
        target_types=("web",), phase="Phase 13", max_depth=3,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-INFRA-004", category="infrastructure",
        name_en="Cloud Misconfiguration — Firebase Public DB",
        name_ko="클라우드 설정 오류 — Firebase DB 공개",
        target_types=("web",), phase="Phase 13", max_depth=3,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="WEB-INFRA-005", category="infrastructure",
        name_en="Exposed Git Repository",
        name_ko="Git 저장소 노출",
        target_types=("web",), phase="Phase 3", max_depth=2,
        owasp_id="A05:2021",
    ),
    # ── CISA KEV 2026-03 + Domain Intel 트렌드 반영 ──
    AttackVector(
        id="WEB-INJECT-018", category="injection",
        name_en="AI/LLM Workflow Code Injection (CVE-2026-33017 Langflow)|||AI/LLM 워크플로우 코드 인젝션",
        name_ko="AI/LLM 워크플로우 코드 인젝션 (Langflow 등)",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-INJECT-019", category="injection",
        name_en="Laravel Livewire RCE (CVE-2025-54068)|||Laravel Livewire 원격 코드 실행",
        name_ko="Laravel Livewire 원격 코드 실행",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-INJECT-020", category="injection",
        name_en="CMS Code Injection (CVE-2025-32432 Craft CMS)|||CMS 코드 인젝션",
        name_ko="CMS 코드 인젝션 (Craft CMS 등)",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-INFRA-006", category="infrastructure",
        name_en="F5 BIG-IP APM RCE (CVE-2025-53521)|||F5 BIG-IP 원격 코드 실행",
        name_ko="F5 BIG-IP APM 원격 코드 실행",
        target_types=("web",), phase="Phase 4", max_depth=4,
        owasp_id="A06:2021",
    ),
    AttackVector(
        id="WEB-INJECT-021", category="injection",
        name_en="LLM Prompt Injection|||LLM 프롬프트 인젝션",
        name_ko="LLM 프롬프트 인젝션",
        target_types=("web",), phase="Phase 5", max_depth=3,
        owasp_id="A03:2021",
    ),
    AttackVector(
        id="WEB-AUTH-010", category="auth",
        name_en="Magic Link Authentication Bypass|||매직 링크 인증 우회",
        name_ko="매직 링크 인증 우회",
        target_types=("web",), phase="Phase 6", max_depth=3,
        owasp_id="A07:2021",
    ),
    AttackVector(
        id="WEB-SUPPLY-001", category="supply_chain",
        name_en="Dependency Supply Chain Attack|||의존성 공급망 공격",
        name_ko="의존성 공급망 공격 (타이포스쿼팅, 악성 패키지)",
        target_types=("web",), phase="Phase 3", max_depth=4,
        owasp_id="A06:2021",
    ),
    AttackVector(
        id="WEB-SUPPLY-002", category="supply_chain",
        name_en="CI/CD Tool Compromise|||CI/CD 도구 공급망 공격",
        name_ko="CI/CD 도구 공급망 공격 (CVE-2026-33634 Trivy 등)",
        target_types=("web",), phase="Phase 3", max_depth=4,
        owasp_id="A06:2021",
    ),
    # ── Business Logic (Multi-step) ──
    AttackVector(
        id="WEB-BIZ-001", category="business_logic",
        name_en="Business Logic — Negative Value Injection",
        name_ko="비즈니스 로직 — 음수 값 주입",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A04:2021",
    ),
    AttackVector(
        id="WEB-BIZ-002", category="business_logic",
        name_en="Business Logic — State Transition Skip",
        name_ko="비즈니스 로직 — 상태 전환 우회",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A04:2021",
    ),
    AttackVector(
        id="WEB-BIZ-003", category="business_logic",
        name_en="Business Logic — Race Condition on Payment",
        name_ko="비즈니스 로직 — 결제 경쟁 상태",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A04:2021",
    ),
    AttackVector(
        id="WEB-BIZ-004", category="business_logic",
        name_en="Business Logic — Transaction Replay",
        name_ko="비즈니스 로직 — 트랜잭션 재전송",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A04:2021",
    ),
    AttackVector(
        id="WEB-BIZ-005", category="business_logic",
        name_en="Business Logic — Privilege Escalation via State",
        name_ko="비즈니스 로직 — 상태 기반 권한 상승",
        target_types=("web",), phase="Phase 5", max_depth=4,
        owasp_id="A04:2021",
    ),
)


# ─────────────────────────────────────────────
# GAME VECTORS (~37개)
# ─────────────────────────────────────────────

GAME_VECTORS: tuple[AttackVector, ...] = (
    # ── Server Validation ──
    AttackVector(
        id="GAME-SV-001", category="server_validation",
        name_en="Negative Currency / Item Count",
        name_ko="음수 재화 / 아이템 수량",
        target_types=("game",), phase="Phase 4", max_depth=4,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-SV-002", category="server_validation",
        name_en="Integer Overflow — Currency / Health",
        name_ko="정수 오버플로우 — 재화 / HP",
        target_types=("game",), phase="Phase 4", max_depth=4,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-SV-003", category="server_validation",
        name_en="Zero-Price Purchase",
        name_ko="0원 구매",
        target_types=("game",), phase="Phase 4", max_depth=3,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-SV-004", category="server_validation",
        name_en="Speed Hack — Movement Validation Bypass",
        name_ko="스피드 핵 — 이동 속도 검증 우회",
        target_types=("game",), phase="Phase 5", max_depth=2,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-SV-005", category="server_validation",
        name_en="Teleport / Position Bypass",
        name_ko="텔레포트 / 위치 우회",
        target_types=("game",), phase="Phase 5", max_depth=2,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-SV-006", category="server_validation",
        name_en="IDOR — Access Other Player Data",
        name_ko="IDOR — 타 플레이어 데이터 접근",
        target_types=("game",), phase="Phase 6", max_depth=4,
        owasp_id="API1:2023",
    ),
    AttackVector(
        id="GAME-SV-007", category="server_validation",
        name_en="Server-Side Input Truncation — Name / Chat",
        name_ko="서버측 입력 잘림 — 이름 / 채팅",
        target_types=("game",), phase="Phase 4", max_depth=2,
        owasp_id="API3:2023",
    ),
    # ── Economy ──
    AttackVector(
        id="GAME-ECON-001", category="economy",
        name_en="Item Duplication Exploit",
        name_ko="아이템 복제 익스플로잇",
        target_types=("game",), phase="Phase 7", max_depth=4,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-ECON-002", category="economy",
        name_en="Currency Manipulation — Transaction Replay",
        name_ko="재화 조작 — 트랜잭션 재전송",
        target_types=("game",), phase="Phase 7", max_depth=4,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-ECON-003", category="economy",
        name_en="Trade Abuse — Rollback Attack",
        name_ko="거래 악용 — 롤백 공격",
        target_types=("game",), phase="Phase 7", max_depth=3,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-ECON-004", category="economy",
        name_en="Gift Abuse — Multiple Redemption",
        name_ko="선물 악용 — 중복 수령",
        target_types=("game",), phase="Phase 7", max_depth=3,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-ECON-005", category="economy",
        name_en="Marketplace Price Manipulation",
        name_ko="마켓플레이스 가격 조작",
        target_types=("game",), phase="Phase 7", max_depth=3,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-ECON-006", category="economy",
        name_en="IAP Bypass — Receipt Forgery",
        name_ko="인앱 결제 우회 — 영수증 위조",
        target_types=("game",), phase="Phase 7", max_depth=4,
        owasp_id="API4:2023",
    ),
    # ── Protocol ──
    AttackVector(
        id="GAME-PROTO-001", category="protocol",
        name_en="Binary Protocol — Weak / No Integrity Check",
        name_ko="바이너리 프로토콜 — 무결성 검사 미흡",
        target_types=("game",), phase="Phase 3", max_depth=3,
        owasp_id="API8:2023",
    ),
    AttackVector(
        id="GAME-PROTO-002", category="protocol",
        name_en="Replay Attack — Packet Replay",
        name_ko="재전송 공격 — 패킷 재전송",
        target_types=("game",), phase="Phase 3", max_depth=3,
        owasp_id="API8:2023",
    ),
    AttackVector(
        id="GAME-PROTO-003", category="protocol",
        name_en="Packet Injection — Crafted Game Packets",
        name_ko="패킷 인젝션 — 조작된 게임 패킷",
        target_types=("game",), phase="Phase 3", max_depth=4,
        owasp_id="API3:2023",
    ),
    AttackVector(
        id="GAME-PROTO-004", category="protocol",
        name_en="State Desync — Client-Server State Manipulation",
        name_ko="상태 비동기화 — 클라이언트-서버 상태 조작",
        target_types=("game",), phase="Phase 3", max_depth=3,
        owasp_id="API4:2023",
    ),
    # ── Client-Side ──
    AttackVector(
        id="GAME-CLIENT-001", category="client",
        name_en="Memory Manipulation — Cheat Engine",
        name_ko="메모리 조작 — 치트 엔진",
        target_types=("game",), phase="Phase 8", max_depth=2,
        owasp_id="API8:2023",
    ),
    AttackVector(
        id="GAME-CLIENT-002", category="client",
        name_en="Binary Reverse Engineering — Asset / Logic Extraction",
        name_ko="바이너리 리버스 엔지니어링 — 에셋 / 로직 추출",
        target_types=("game",), phase="Phase 8", max_depth=2,
        owasp_id="API8:2023",
    ),
    AttackVector(
        id="GAME-CLIENT-003", category="client",
        name_en="Save File Tampering",
        name_ko="세이브 파일 조작",
        target_types=("game",), phase="Phase 8", max_depth=3,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-CLIENT-004", category="client",
        name_en="Config File Tampering — Bypass Restrictions",
        name_ko="설정 파일 조작 — 제한 우회",
        target_types=("game",), phase="Phase 8", max_depth=2,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-CLIENT-005", category="client",
        name_en="Asset Manipulation — Texture / Audio Swap",
        name_ko="에셋 조작 — 텍스처 / 오디오 교체",
        target_types=("game",), phase="Phase 8", max_depth=1,
        owasp_id="API8:2023",
    ),
    # ── Anti-Cheat ──
    AttackVector(
        id="GAME-AC-001", category="anti_cheat",
        name_en="Anti-Cheat Detection Assessment",
        name_ko="안티치트 탐지 평가",
        target_types=("game",), phase="Phase 9", max_depth=1,
        owasp_id="API8:2023",
    ),
    AttackVector(
        id="GAME-AC-002", category="anti_cheat",
        name_en="Anti-Cheat Bypass Feasibility",
        name_ko="안티치트 우회 가능성",
        target_types=("game",), phase="Phase 9", max_depth=2,
        owasp_id="API8:2023",
    ),
    AttackVector(
        id="GAME-AC-003", category="anti_cheat",
        name_en="Kernel-Level Anti-Cheat Analysis",
        name_ko="커널 레벨 안티치트 분석",
        target_types=("game",), phase="Phase 9", max_depth=2,
        owasp_id="API8:2023",
    ),
    # ── Game Logic ──
    AttackVector(
        id="GAME-LOGIC-001", category="game_logic",
        name_en="Leaderboard Manipulation",
        name_ko="리더보드 조작",
        target_types=("game",), phase="Phase 10", max_depth=3,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-LOGIC-002", category="game_logic",
        name_en="Matchmaking Abuse — ELO Manipulation",
        name_ko="매치메이킹 악용 — ELO 조작",
        target_types=("game",), phase="Phase 10", max_depth=2,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-LOGIC-003", category="game_logic",
        name_en="Time Manipulation — Cooldown Bypass",
        name_ko="시간 조작 — 쿨다운 우회",
        target_types=("game",), phase="Phase 10", max_depth=3,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-LOGIC-004", category="game_logic",
        name_en="Gacha / RNG Manipulation",
        name_ko="가챠 / RNG 조작",
        target_types=("game",), phase="Phase 10", max_depth=3,
        owasp_id="API4:2023",
    ),
    AttackVector(
        id="GAME-LOGIC-005", category="game_logic",
        name_en="GM Command Injection — Admin Function Access",
        name_ko="GM 커맨드 인젝션 — 관리자 기능 접근",
        target_types=("game",), phase="Phase 6", max_depth=4,
        owasp_id="API1:2023",
    ),
    AttackVector(
        id="GAME-LOGIC-006", category="game_logic",
        name_en="Referral Code Abuse — Infinite Bonus",
        name_ko="레퍼럴 코드 악용 — 무한 보너스",
        target_types=("game",), phase="Phase 10", max_depth=2,
        owasp_id="API4:2023",
    ),
    # ── Social ──
    AttackVector(
        id="GAME-SOCIAL-001", category="social",
        name_en="Chat Injection — HTML/Script in Messages",
        name_ko="채팅 인젝션 — 메시지 내 HTML/스크립트",
        target_types=("game",), phase="Phase 11", max_depth=2,
        owasp_id="API3:2023",
    ),
    AttackVector(
        id="GAME-SOCIAL-002", category="social",
        name_en="Username XSS — Profile Stored XSS",
        name_ko="사용자명 XSS — 프로필 저장형 XSS",
        target_types=("game",), phase="Phase 11", max_depth=2,
        owasp_id="API3:2023",
    ),
    AttackVector(
        id="GAME-SOCIAL-003", category="social",
        name_en="In-Game Phishing — Fake UI Overlay",
        name_ko="인게임 피싱 — 가짜 UI 오버레이",
        target_types=("game",), phase="Phase 11", max_depth=2,
        owasp_id="API3:2023",
    ),
    AttackVector(
        id="GAME-SOCIAL-004", category="social",
        name_en="Guild / Clan Abuse — Permission Escalation",
        name_ko="길드 / 클랜 악용 — 권한 상승",
        target_types=("game",), phase="Phase 11", max_depth=3,
        owasp_id="API1:2023",
    ),
    # ── DRM ──
    AttackVector(
        id="GAME-DRM-001", category="drm",
        name_en="License Bypass — Offline Activation Spoof",
        name_ko="라이선스 우회 — 오프라인 활성화 위조",
        target_types=("game",), phase="Phase 12", max_depth=2,
        owasp_id="API8:2023",
    ),
    AttackVector(
        id="GAME-DRM-002", category="drm",
        name_en="Cloud Save Manipulation — Cross-Account",
        name_ko="클라우드 세이브 조작 — 계정 간 교차",
        target_types=("game",), phase="Phase 12", max_depth=3,
        owasp_id="API1:2023",
    ),
)


# ─────────────────────────────────────────────
# MOBILE VECTORS (~47개)
# ─────────────────────────────────────────────

MOBILE_VECTORS: tuple[AttackVector, ...] = (
    # ── Static Analysis ──
    AttackVector(
        id="MOB-STATIC-001", category="static",
        name_en="Hardcoded API Keys / Secrets in APK/IPA",
        name_ko="APK/IPA 내 API 키 / 시크릿 하드코딩",
        target_types=("mobile",), phase="Phase 2", max_depth=3,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-STATIC-002", category="static",
        name_en="Weak Cryptography — DES / ECB Mode",
        name_ko="약한 암호화 — DES / ECB 모드",
        target_types=("mobile",), phase="Phase 2", max_depth=2,
        owasp_id="M5",
    ),
    AttackVector(
        id="MOB-STATIC-003", category="static",
        name_en="Over-Privileged Permissions",
        name_ko="과도한 권한 요청",
        target_types=("mobile",), phase="Phase 2", max_depth=1,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-STATIC-004", category="static",
        name_en="Exported Activity / Service / Provider (Android)",
        name_ko="내보내기된 Activity / Service / Provider (Android)",
        target_types=("mobile",), phase="Phase 2", max_depth=3,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-STATIC-005", category="static",
        name_en="Debug Flag Enabled — android:debuggable",
        name_ko="디버그 플래그 활성화 — android:debuggable",
        target_types=("mobile",), phase="Phase 2", max_depth=2,
        owasp_id="M7",
    ),
    AttackVector(
        id="MOB-STATIC-006", category="static",
        name_en="Backup Enabled — android:allowBackup",
        name_ko="백업 활성화 — android:allowBackup",
        target_types=("mobile",), phase="Phase 2", max_depth=2,
        owasp_id="M2",
    ),
    AttackVector(
        id="MOB-STATIC-007", category="static",
        name_en="Embedded Firebase / Google Services Config",
        name_ko="Firebase / Google Services 설정 파일 내장",
        target_types=("mobile",), phase="Phase 2", max_depth=2,
        owasp_id="M1",
    ),
    # ── Binary Analysis ──
    AttackVector(
        id="MOB-BINARY-001", category="binary",
        name_en="No PIE (Position Independent Executable)",
        name_ko="PIE 미적용 (위치 독립 실행파일)",
        target_types=("mobile",), phase="Phase 3", max_depth=2,
        owasp_id="M8",
    ),
    AttackVector(
        id="MOB-BINARY-002", category="binary",
        name_en="No Stack Canary",
        name_ko="스택 카나리 미적용",
        target_types=("mobile",), phase="Phase 3", max_depth=2,
        owasp_id="M8",
    ),
    AttackVector(
        id="MOB-BINARY-003", category="binary",
        name_en="No Code Obfuscation",
        name_ko="코드 난독화 미적용",
        target_types=("mobile",), phase="Phase 3", max_depth=1,
        owasp_id="M8",
    ),
    AttackVector(
        id="MOB-BINARY-004", category="binary",
        name_en="Secrets in Native Library (.so / .dylib)",
        name_ko="네이티브 라이브러리 내 시크릿 (.so / .dylib)",
        target_types=("mobile",), phase="Phase 3", max_depth=3,
        owasp_id="M1",
    ),
    # ── Network ──
    AttackVector(
        id="MOB-NET-001", category="network",
        name_en="SSL Pinning — Not Implemented",
        name_ko="SSL 피닝 — 미구현",
        target_types=("mobile",), phase="Phase 4", max_depth=3,
        owasp_id="M3",
    ),
    AttackVector(
        id="MOB-NET-002", category="network",
        name_en="SSL Pinning — Weak Implementation (Bypassable)",
        name_ko="SSL 피닝 — 미흡한 구현 (우회 가능)",
        target_types=("mobile",), phase="Phase 4", max_depth=3,
        owasp_id="M3",
    ),
    AttackVector(
        id="MOB-NET-003", category="network",
        name_en="Cleartext Traffic — HTTP Endpoints",
        name_ko="평문 전송 — HTTP 엔드포인트",
        target_types=("mobile",), phase="Phase 4", max_depth=2,
        owasp_id="M3",
    ),
    AttackVector(
        id="MOB-NET-004", category="network",
        name_en="Certificate Validation Bypass — Trust All Certs",
        name_ko="인증서 검증 우회 — 전체 인증서 신뢰",
        target_types=("mobile",), phase="Phase 4", max_depth=3,
        owasp_id="M3",
    ),
    # ── API / Backend ──
    AttackVector(
        id="MOB-API-001", category="api",
        name_en="Mobile API — Authentication Flaw",
        name_ko="모바일 API — 인증 결함",
        target_types=("mobile",), phase="Phase 5", max_depth=4,
        owasp_id="M4",
    ),
    AttackVector(
        id="MOB-API-002", category="api",
        name_en="Mobile API — IDOR",
        name_ko="모바일 API — IDOR",
        target_types=("mobile",), phase="Phase 5", max_depth=4,
        owasp_id="M4",
    ),
    AttackVector(
        id="MOB-API-003", category="api",
        name_en="Mobile API — Rate Limiting Bypass",
        name_ko="모바일 API — 레이트 리미팅 우회",
        target_types=("mobile",), phase="Phase 5", max_depth=2,
        owasp_id="M4",
    ),
    AttackVector(
        id="MOB-API-004", category="api",
        name_en="GraphQL — Introspection / Batching Attack",
        name_ko="GraphQL — 인트로스펙션 / 배치 공격",
        target_types=("mobile",), phase="Phase 5", max_depth=2,
        owasp_id="M4",
    ),
    AttackVector(
        id="MOB-API-005", category="api",
        name_en="gRPC — Reflection / Plaintext Proto",
        name_ko="gRPC — 리플렉션 / 평문 Proto",
        target_types=("mobile",), phase="Phase 5", max_depth=2,
        owasp_id="M4",
    ),
    # ── Storage ──
    AttackVector(
        id="MOB-STORE-001", category="storage",
        name_en="SQLite — Unencrypted Sensitive Data",
        name_ko="SQLite — 민감 데이터 평문 저장",
        target_types=("mobile",), phase="Phase 6", max_depth=3,
        owasp_id="M2",
    ),
    AttackVector(
        id="MOB-STORE-002", category="storage",
        name_en="SharedPreferences — Sensitive Data (Android)",
        name_ko="SharedPreferences — 민감 데이터 저장 (Android)",
        target_types=("mobile",), phase="Phase 6", max_depth=3,
        owasp_id="M2",
    ),
    AttackVector(
        id="MOB-STORE-003", category="storage",
        name_en="Keychain — Misconfigured Accessibility (iOS)",
        name_ko="Keychain — 접근성 잘못 설정 (iOS)",
        target_types=("mobile",), phase="Phase 6", max_depth=3,
        owasp_id="M2",
    ),
    AttackVector(
        id="MOB-STORE-004", category="storage",
        name_en="Cache Leakage — HTTP Response / WebView Cache",
        name_ko="캐시 유출 — HTTP 응답 / WebView 캐시",
        target_types=("mobile",), phase="Phase 6", max_depth=2,
        owasp_id="M2",
    ),
    AttackVector(
        id="MOB-STORE-005", category="storage",
        name_en="Clipboard Exposure — Sensitive Copy/Paste",
        name_ko="클립보드 노출 — 민감 복사/붙여넣기",
        target_types=("mobile",), phase="Phase 6", max_depth=1,
        owasp_id="M2",
    ),
    AttackVector(
        id="MOB-STORE-006", category="storage",
        name_en="Screenshot Not Blocked — FLAG_SECURE Missing",
        name_ko="스크린샷 차단 미적용 — FLAG_SECURE 누락",
        target_types=("mobile",), phase="Phase 6", max_depth=1,
        owasp_id="M2",
    ),
    # ── Dynamic Analysis / Anti-Tampering ──
    AttackVector(
        id="MOB-DYN-001", category="dynamic",
        name_en="Root / Jailbreak Detection Bypass",
        name_ko="루팅 / 탈옥 탐지 우회",
        target_types=("mobile",), phase="Phase 7", max_depth=2,
        owasp_id="M8",
    ),
    AttackVector(
        id="MOB-DYN-002", category="dynamic",
        name_en="Emulator Detection Bypass",
        name_ko="에뮬레이터 탐지 우회",
        target_types=("mobile",), phase="Phase 7", max_depth=2,
        owasp_id="M8",
    ),
    AttackVector(
        id="MOB-DYN-003", category="dynamic",
        name_en="Anti-Tamper Bypass — Signature Check",
        name_ko="변조 방지 우회 — 서명 검증",
        target_types=("mobile",), phase="Phase 7", max_depth=2,
        owasp_id="M8",
    ),
    AttackVector(
        id="MOB-DYN-004", category="dynamic",
        name_en="Debugger Detection Bypass — Frida / LLDB",
        name_ko="디버거 탐지 우회 — Frida / LLDB",
        target_types=("mobile",), phase="Phase 7", max_depth=3,
        owasp_id="M8",
    ),
    AttackVector(
        id="MOB-DYN-005", category="dynamic",
        name_en="Dynamic Code Loading — Malicious DEX Injection",
        name_ko="동적 코드 로딩 — 악성 DEX 인젝션",
        target_types=("mobile",), phase="Phase 7", max_depth=3,
        owasp_id="M8",
    ),
    # ── Business Logic ──
    AttackVector(
        id="MOB-BIZ-001", category="business_logic",
        name_en="IAP Bypass — Receipt Validation Flaw",
        name_ko="인앱 결제 우회 — 영수증 검증 결함",
        target_types=("mobile",), phase="Phase 8", max_depth=4,
        owasp_id="M4",
    ),
    AttackVector(
        id="MOB-BIZ-002", category="business_logic",
        name_en="Subscription Spoofing — Premium Feature Unlock",
        name_ko="구독 위조 — 프리미엄 기능 무단 잠금 해제",
        target_types=("mobile",), phase="Phase 8", max_depth=3,
        owasp_id="M4",
    ),
    AttackVector(
        id="MOB-BIZ-003", category="business_logic",
        name_en="Deep Link Hijacking — Intent Scheme",
        name_ko="딥 링크 하이재킹 — Intent 스킴",
        target_types=("mobile",), phase="Phase 8", max_depth=3,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-BIZ-004", category="business_logic",
        name_en="Feature Flag Manipulation — Hidden Features",
        name_ko="기능 플래그 조작 — 숨겨진 기능 활성화",
        target_types=("mobile",), phase="Phase 8", max_depth=2,
        owasp_id="M4",
    ),
    AttackVector(
        id="MOB-BIZ-005", category="business_logic",
        name_en="Offline Mode Abuse — No Server Verification",
        name_ko="오프라인 모드 악용 — 서버 검증 없음",
        target_types=("mobile",), phase="Phase 8", max_depth=2,
        owasp_id="M4",
    ),
    # ── Platform ──
    AttackVector(
        id="MOB-PLAT-001", category="platform",
        name_en="Intent Injection — Implicit Intent Hijack",
        name_ko="Intent 인젝션 — Implicit Intent 하이재킹",
        target_types=("mobile",), phase="Phase 9", max_depth=3,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-PLAT-002", category="platform",
        name_en="Content Provider Exposure — Unprotected URI",
        name_ko="Content Provider 노출 — 비보호 URI",
        target_types=("mobile",), phase="Phase 9", max_depth=3,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-PLAT-003", category="platform",
        name_en="Broadcast Abuse — Sensitive Action Intercept",
        name_ko="Broadcast 악용 — 민감 액션 가로채기",
        target_types=("mobile",), phase="Phase 9", max_depth=2,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-PLAT-004", category="platform",
        name_en="Task Hijacking — StrandHogg Style",
        name_ko="태스크 하이재킹 — StrandHogg 방식",
        target_types=("mobile",), phase="Phase 9", max_depth=3,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-PLAT-005", category="platform",
        name_en="WebView JavaScript Bridge Abuse",
        name_ko="WebView JavaScript 브릿지 악용",
        target_types=("mobile",), phase="Phase 9", max_depth=4,
        owasp_id="M6",
    ),
    AttackVector(
        id="MOB-PLAT-006", category="platform",
        name_en="Universal Links / App Links Hijack",
        name_ko="Universal Links / App Links 하이재킹",
        target_types=("mobile",), phase="Phase 9", max_depth=2,
        owasp_id="M1",
    ),
    # ── Cloud Backend ──
    AttackVector(
        id="MOB-CLOUD-001", category="cloud",
        name_en="Firebase Realtime DB — Unauthenticated Read",
        name_ko="Firebase Realtime DB — 비인증 읽기",
        target_types=("mobile",), phase="Phase 10", max_depth=3,
        owasp_id="M9",
    ),
    AttackVector(
        id="MOB-CLOUD-002", category="cloud",
        name_en="S3 Bucket — Public Read / Write",
        name_ko="S3 버킷 — 공개 읽기 / 쓰기",
        target_types=("mobile",), phase="Phase 10", max_depth=3,
        owasp_id="M9",
    ),
    AttackVector(
        id="MOB-CLOUD-003", category="cloud",
        name_en="Cloud Function — Exposed Unauthenticated Endpoint",
        name_ko="클라우드 함수 — 비인증 엔드포인트 노출",
        target_types=("mobile",), phase="Phase 10", max_depth=3,
        owasp_id="M9",
    ),
    # ── Third-Party / SDK ──
    AttackVector(
        id="MOB-SDK-001", category="third_party",
        name_en="Third-Party SDK — Known CVE Matching",
        name_ko="서드파티 SDK — 알려진 CVE 매칭",
        target_types=("mobile",), phase="Phase 11", max_depth=3,
        owasp_id="M10",
    ),
    AttackVector(
        id="MOB-SDK-002", category="third_party",
        name_en="Analytics SDK — Sensitive Data Leakage",
        name_ko="애널리틱스 SDK — 민감 데이터 유출",
        target_types=("mobile",), phase="Phase 11", max_depth=2,
        owasp_id="M10",
    ),
    AttackVector(
        id="MOB-SDK-003", category="third_party",
        name_en="Push Notification Spoofing",
        name_ko="푸시 알림 위조",
        target_types=("mobile",), phase="Phase 11", max_depth=2,
        owasp_id="M10",
    ),
    # ── Privacy / OWASP Mobile Top 10 ──
    AttackVector(
        id="MOB-PRIV-001", category="privacy",
        name_en="OWASP M1 — Improper Credential Usage",
        name_ko="OWASP M1 — 부적절한 자격증명 사용",
        target_types=("mobile",), phase="Phase 12", max_depth=3,
        owasp_id="M1",
    ),
    AttackVector(
        id="MOB-PRIV-002", category="privacy",
        name_en="OWASP M6 — Inadequate Privacy Controls",
        name_ko="OWASP M6 — 불충분한 개인정보 보호",
        target_types=("mobile",), phase="Phase 12", max_depth=2,
        owasp_id="M6",
    ),
    AttackVector(
        id="MOB-PRIV-003", category="privacy",
        name_en="OWASP M9 — Insecure Data Storage (Comprehensive)",
        name_ko="OWASP M9 — 안전하지 않은 데이터 저장 (종합)",
        target_types=("mobile",), phase="Phase 12", max_depth=3,
        owasp_id="M9",
    ),
)


# ─────────────────────────────────────────────
# DESKTOP VECTORS — minimal slice for macOS e2e (phase-J)
# ─────────────────────────────────────────────
#
# 풀 14개 (DESK-LSS/ELC/IPC/UPD/DLK/PIE/PRV/DEP) 정의는 phase-F (Windows
# 풀 desktop pipeline) 에서 들어옴. 지금은 macOS-only e2e 를 위한 최소
# 1개 (LSS) 만 등록 — 추가 벡터는 phase-J slice 들이 점진적으로 채움.

DESKTOP_VECTORS: tuple[AttackVector, ...] = (
    AttackVector(
        id="DESK-LSS-001", category="information_disclosure",
        name_en="Local Storage — Plaintext Secret in Application Bundle",
        name_ko="로컬 스토리지 — 앱 번들 평문 시크릿",
        target_types=("desktop",), phase="Phase 5", max_depth=3,
        owasp_id="M9",  # OWASP Mobile/Desktop "Insecure Data Storage"
    ),
    # ── Electron Misconfiguration (DESK-ELC-*) ── phase-J slice 2
    AttackVector(
        id="DESK-ELC-001", category="misconfiguration",
        name_en="Electron nodeIntegration enabled",
        name_ko="Electron nodeIntegration 활성화",
        target_types=("desktop",), phase="Phase 5", max_depth=4,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="DESK-ELC-002", category="misconfiguration",
        name_en="Electron contextIsolation disabled",
        name_ko="Electron contextIsolation 비활성화",
        target_types=("desktop",), phase="Phase 5", max_depth=3,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="DESK-ELC-003", category="misconfiguration",
        name_en="Electron webSecurity disabled",
        name_ko="Electron webSecurity 비활성화",
        target_types=("desktop",), phase="Phase 5", max_depth=3,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="DESK-RECON-001", category="recon",
        name_en="Binary Recon — Imports / Entitlements / Signature",
        name_ko="바이너리 정찰 — Imports / Entitlements / Signature",
        target_types=("desktop",), phase="Phase 4", max_depth=1,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="DESK-SIG-001", category="misconfiguration",
        name_en="Code Signature — Missing or Invalid",
        name_ko="코드 서명 — 누락 또는 무효",
        target_types=("desktop",), phase="Phase 4", max_depth=2,
        owasp_id="A08:2021",
    ),
    AttackVector(
        id="DESK-SIG-002", category="misconfiguration",
        name_en="Unsigned binary",
        name_ko="서명 안 된 바이너리",
        target_types=("desktop",), phase="Phase 4", max_depth=2,
        owasp_id="A08:2021",
    ),
    AttackVector(
        id="DESK-SIG-003", category="misconfiguration",
        name_en="Ad-hoc signed (no Developer ID)",
        name_ko="Ad-hoc 서명 (Developer ID 없음)",
        target_types=("desktop",), phase="Phase 4", max_depth=2,
        owasp_id="A08:2021",
    ),
    AttackVector(
        id="DESK-SIG-004", category="misconfiguration",
        name_en="Hardened Runtime disabled",
        name_ko="Hardened Runtime 비활성화",
        target_types=("desktop",), phase="Phase 4", max_depth=2,
        owasp_id="A08:2021",
    ),
    # ── Entitlement Audit (DESK-ENT-*) — phase-J slice 3 ──────────────────────
    AttackVector(
        id="DESK-ENT-001", category="misconfiguration",
        name_en="Disabled Library Validation",
        name_ko="라이브러리 검증 비활성화",
        target_types=("desktop",), phase="Phase 4", max_depth=3,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="DESK-ENT-002", category="misconfiguration",
        name_en="Allows DYLD Environment Variables",
        name_ko="DYLD 환경 변수 허용",
        target_types=("desktop",), phase="Phase 4", max_depth=4,
        owasp_id="A05:2021",
    ),
    AttackVector(
        id="DESK-ENT-003", category="misconfiguration",
        name_en="Allow JIT or Unsigned Executable Memory",
        name_ko="JIT/서명되지 않은 실행 메모리 허용",
        target_types=("desktop",), phase="Phase 4", max_depth=2,
        owasp_id="A05:2021",
    ),
    # ── Dylib Hijack (DESK-DYL-*) — phase-J slice 5 ───────────────────────────
    AttackVector(
        id="DESK-DYL-001", category="misconfiguration",
        name_en="Writable dylib path",
        name_ko="쓰기 가능한 dylib 경로",
        target_types=("desktop",), phase="Phase 5", max_depth=3,
        owasp_id="A06:2021",
    ),
    AttackVector(
        id="DESK-DYL-002", category="misconfiguration",
        name_en="Missing dylib (LC_LOAD_WEAK_DYLIB)",
        name_ko="누락된 dylib (LC_LOAD_WEAK_DYLIB)",
        target_types=("desktop",), phase="Phase 5", max_depth=2,
        owasp_id="A06:2021",
    ),
    AttackVector(
        id="DESK-DYL-003", category="misconfiguration",
        name_en="Multiple RPATH entries",
        name_ko="다중 RPATH 항목",
        target_types=("desktop",), phase="Phase 5", max_depth=2,
        owasp_id="A06:2021",
    ),
)


# ─────────────────────────────────────────────
# Registry helper
# ─────────────────────────────────────────────

_ALL_VECTORS: dict[str, AttackVector] = {
    v.id: v
    for v in (*WEB_VECTORS, *GAME_VECTORS, *MOBILE_VECTORS, *DESKTOP_VECTORS)
}


def get_vectors_for_type(target_type: str) -> tuple[AttackVector, ...]:
    """타겟 타입에 해당하는 공격 벡터 전체를 반환한다."""
    mapping: dict[str, tuple[AttackVector, ...]] = {
        "web": WEB_VECTORS,
        "game": GAME_VECTORS,
        "mobile": MOBILE_VECTORS,
        "desktop": DESKTOP_VECTORS,
    }
    if target_type not in mapping:
        raise ValueError(
            f"Unknown target type: {target_type!r}. "
            f"Valid values: {list(mapping.keys())}"
        )
    return mapping[target_type]


def get_vector_by_id(vector_id: str) -> AttackVector | None:
    """ID로 벡터를 조회한다. 없으면 None을 반환한다."""
    return _ALL_VECTORS.get(vector_id)
