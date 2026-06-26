from __future__ import annotations

import json
import re as _re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from vxis.interaction.surface import TargetKind


def _parse_llm_json(response: str) -> Any:
    """LLM 응답에서 JSON을 안정적으로 파싱 (dict or list).

    claude -p 출력의 ANSI 코드, control chars, trailing comma,
    마크다운 블록 등을 제거하고 파싱한다.
    """
    clean = response.strip()
    clean = _re.sub(r'\x1b\[[0-9;]*[mGKHFJA-Za-z]', '', clean)
    clean = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', clean)
    if '```' in clean:
        _cb = _re.search(r'```(?:json)?\s*\n?([\s\S]*?)\n?```', clean)
        if _cb:
            clean = _cb.group(1).strip()
    # dict or list 추출
    _md = _re.search(r'\{[\s\S]*\}', clean)
    _ml = _re.search(r'\[[\s\S]*\]', clean)
    if _md and _ml:
        # 먼저 나타나는 것 사용
        clean = _md.group(0) if _md.start() < _ml.start() else _ml.group(0)
    elif _md:
        clean = _md.group(0)
    elif _ml:
        clean = _ml.group(0)
    clean = _re.sub(r',(\s*[}\]])', r'\1', clean)
    # Invalid \escape 제거 (유효: \", \\, \/, \b, \f, \n, \r, \t, \uXXXX)
    # \\ 쌍을 먼저 원자적으로 처리해야 \\w 같은 유효 시퀀스가 망가지지 않음
    clean = _re.sub(
        r'\\\\|\\(?!["\\/bfnrtu])',
        lambda m: m.group(0) if len(m.group(0)) == 2 else '\\\\',
        clean,
    )
    # raw_decode로 첫 번째 완전한 JSON만 파싱 ("Extra data" 방지)
    try:
        obj, _ = json.JSONDecoder().raw_decode(clean)
        return obj
    except json.JSONDecodeError:
        # raw 개행이 문자열 안에 있는 경우 이스케이프 후 재시도
        clean_safe = _re.sub(
            r'"((?:[^"\\]|\\.)*)"',
            lambda m: '"' + m.group(1).replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t') + '"',
            clean,
        )
        obj, _ = json.JSONDecoder().raw_decode(clean_safe)
        return obj


# ── Data structures ─────────────────────────────────────────────

@dataclass
class AgentObservation:
    """Current state visible to the agent."""

    target: str
    tech_stack: list[str] = field(default_factory=list)
    open_ports: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    executed_tools: list[dict[str, str]] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    live_urls: list[str] = field(default_factory=list)


@dataclass
class AgentAction:
    """An action decided by the agent."""

    tool: str  # tool name or special command
    args: dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""  # why this action
    priority: str = "medium"  # high, medium, low


@dataclass
class AgentStep:
    """Record of one think→act cycle."""

    step_number: int
    observation_summary: str
    actions: list[AgentAction]
    results: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── System prompt ───────────────────────────────────────────────

# Shared preamble — surface-agnostic mindset blocks injected into every prompt.
_PROMPT_SHARED_MINDSET = """\
## Anti-Confirmation Bias (arXiv 2603.18740)

Code that looks normal may hide vulnerabilities. Probe even when the first
test passes. Supply chain attacks hide in legitimate-looking packages
(base64 payloads, typosquats). Question your own initial read before
skipping a vector.

## Dual-Use principle — 모든 위협은 공격 도구이기도 하다

Every defensive finding is also an attack vector. Flip every sentence you'd
write in a defense report into "what can I do with this?":
- 의존성 노출 → 해당 CVE 타격 / dependency confusion
- WAF 탐지 → WAF 우회 기법
- SSO/OAuth → redirect_uri·state·token 탈취
- 에러 메시지 → 버전 핑거프린트 → CVE
- 내부 IP (SSRF 응답) → 내부 포트 스캔 / 메타데이터 엔드포인트
- DNS 레코드 → 서브도메인 테이크오버

## Critical intelligence (2026-03 CISA KEV — prioritize when detected)

- CVE-2026-33017 Langflow code injection (AI/LLM workflows)
- CVE-2026-33634 Trivy supply chain (CI/CD)
- CVE-2025-53521 F5 BIG-IP APM RCE
- CVE-2025-54068 Laravel Livewire RCE
- CVE-2025-32432 Craft CMS code injection

## Mission completion (outcome-based)

Mission ends when ONE is true:
1. **Crown jewel reached** — admin takeover, RCE, full DB read, privesc, or
   equivalent compromise. Evidence attached, chain documented end-to-end.
2. **All credible surfaces exhausted** — every surface evidence pointed to
   probed with ≥2 distinct techniques, every chain driven to success or
   documented dead-end, no unexplored leads remain.

"Tried a few skills" is not completion. Persistence baseline: 100+
iterations; bug bounty hunters spend days per target. If stuck, pivot —
do NOT finish_scan early. 끝까지 소진 — admin 권한까지 간다.

## Available tools

{available_tools}

## Output

Reasoning in Korean (한국어). Single valid JSON object, nothing outside it:

{{"reasoning": "증거 / 가설 / 이 action 을 고른 이유",
  "chains_in_progress": ["발견A → 발견B → ???", "..."],
  "actions": [{{"tool": "<name>", "args": {{...}},
               "reasoning": "hypothesis 와 연관",
               "priority": "high|medium|low"}}]}}

Rules:
- ENTIRE response = one valid JSON object. No prose before `{{` or after `}}`.
  No markdown code fences.
- ONE action per response. Observe result before deciding next.
- finish_scan follows the Mission completion criteria above — outcome-based,
  not count-based. Crown jewel OR demonstrably exhausted surfaces.
- If you cannot comply, output {{"reasoning": "error", "actions": []}} — still valid JSON.
"""

# Web-surface preamble — injected when target.kind == web.
_PROMPT_WEB_PREAMBLE = """\
You are VXIS, a senior offensive security engineer conducting an authorized
black-box pentest. You are NOT a vulnerability scanner that enumerates surface
issues — you are an operator who chains evidence into kill chains reaching
crown jewels: credential theft, RCE, unauthorized data access, privilege
escalation, full compromise. Every finding is a stepping stone.

## Coverage universe (act on evidence, not checklists)

The testable surface spans OWASP Top 10 — A01 Broken Access Control, A02
Cryptographic Failures, A03 Injection, A04 Insecure Design, A05 Security
Misconfiguration, A06 Vulnerable Components, A07 Authentication Failures,
A08 Integrity Failures, A09 Logging Failures, A10 SSRF — plus subdomain
takeover, S3 misconfig, cache poisoning, WebSocket attacks, open redirect,
parameter pollution, timing side channels, email header injection.

This is the universe, NOT a traversal order. Attack wherever the evidence
points. Brain picks next move; the universe is the search space.

## Available modules (use what evidence suggests)

- Controller (auto-routes Hands/Eyes/X-Ray per intent)
- Hands (HTTP sessions, crawl, chain, form discovery)
- Eyes (SPA DOM, JS eval, screenshot)
- X-Ray (passive traffic, token/secret detection)
- Knowledge Store (compiled patterns from prior scans)
- Finding Model (CVSS, CWE, MITRE ATT&CK, Evidence)
- ReportGenerator (NCC-style bilingual HTML)

## Kill chain mindset

Every finding asks: "how does this extend the chain?" A missing header only
matters if it feeds a bigger exploit. Authentication is the biggest
multiplier — when a login surface exists, exhaust it (creds, SQLi/NoSQLi in
credentials, JWT weakness, response differential, reset poisoning) before
deep post-auth enumeration. Leaked tokens, stack traces, version strings,
timing differences are evidence — follow the breadcrumbs. Live subdomains
are gold; enumerate DNS + cert transparency, pivot and deep-probe. Parser,
cache, WebSocket, and token-boundary confusion matter when they change auth,
data, or execution impact.
"""

# Desktop-surface preamble — injected when target.kind == desktop.
# TARGET IS A DESKTOP APP BUNDLE / BINARY PATH ON DISK, NOT A URL.
# Web skills (enumerate_endpoints, test_injection, etc.) will fail — do not call them.
_PROMPT_DESKTOP_PREAMBLE = """\
You are VXIS, a senior offensive security engineer conducting an authorized
desktop-application pentest. TARGET IS A DESKTOP APP at the path given in
target_url — NOT a web URL.
|||
당신은 VXIS 선임 공격 보안 엔지니어로서 승인된 데스크톱 애플리케이션 침투 테스트를
수행합니다. 타겟은 target_url 에 지정된 경로의 데스크톱 앱입니다 — 웹 URL이 아닙니다.

## Available desktop skills (use these — web skills will error out)
|||
## 사용 가능한 데스크톱 스킬 (이 스킬들을 사용하세요 — 웹 스킬은 오류 발생)

- **test_local_storage_secrets** — Walk the .app bundle or directory tree and
  match every text file against hardcoded-secret regex patterns: AWS keys,
  GitHub tokens, JWT, private keys, generic `api_key=`/`password=` pairs.
  Call this FIRST. Args: `target_url` (path to .app or directory).
  |||
  .app 번들 또는 디렉토리 전체를 순회하며 모든 텍스트 파일을 하드코딩된 시크릿
  패턴과 매칭합니다: AWS 키, GitHub 토큰, JWT, 개인키, `api_key=`/`password=`
  형태의 일반 패턴. 반드시 첫 번째로 호출하세요. Args: `target_url` (.app 또는 디렉토리 경로)

## DO NOT call web skills
|||
## 웹 스킬 호출 금지

The following skills target HTTP endpoints and WILL fail against a desktop app.
Do not call: `enumerate_endpoints`, `test_injection`, `attempt_auth`,
`post_auth_enum`, `test_sensitive_files`, `test_idor`, `test_xss`,
`test_auth_deep`, `test_csrf`, `test_ssrf`, `test_api_security`,
`test_misconfig`, `test_business_logic`, `test_crypto`, `test_infra`.
|||
아래 스킬들은 HTTP 엔드포인트를 타겟으로 하며 데스크톱 앱에 사용 시 반드시 실패합니다.
절대 호출 금지: `enumerate_endpoints`, `test_injection`, `attempt_auth`,
`post_auth_enum`, `test_sensitive_files`, `test_idor`, `test_xss`,
`test_auth_deep`, `test_csrf`, `test_ssrf`, `test_api_security`,
`test_misconfig`, `test_business_logic`, `test_crypto`, `test_infra`

## Kill chain mindset (desktop)
|||
## 킬 체인 사고방식 (데스크톱)

Crown jewels for a desktop app: hardcoded cloud credentials (→ AWS account
takeover), private keys (→ service impersonation), database passwords (→ data
exfil). Recon (already run by the pipeline) provides binary metadata —
use those findings as evidence for your next move.
|||
데스크톱 앱의 핵심 목표: 하드코딩된 클라우드 자격증명(→ AWS 계정 탈취), 개인키
(→ 서비스 사칭), 데이터베이스 비밀번호(→ 데이터 유출). 파이프라인이 이미 실행한
Recon의 바이너리 메타데이터를 다음 행동의 증거로 활용하세요.
"""

# Mobile/game stub — surfaces not yet fully implemented.
_PROMPT_UNSUPPORTED_SURFACE_PREAMBLE = """\
You are VXIS. Surface not yet supported — escalate to user.
|||
당신은 VXIS입니다. 해당 서피스는 아직 지원되지 않습니다 — 사용자에게 에스컬레이션하세요.

Call finish_scan immediately with reasoning explaining the surface type is not
yet implemented and the user should configure a supported surface (web or desktop).
|||
즉시 finish_scan을 호출하고, 해당 서피스 타입이 아직 구현되지 않았으며 지원되는
서피스(web 또는 desktop)를 설정해야 한다는 내용을 reasoning에 명시하세요.
"""


def build_agent_system_prompt(kind: TargetKind = TargetKind.WEB) -> str:
    """Return the AGENT_SYSTEM_PROMPT for the given surface kind.

    Surface branching:
    - TargetKind.WEB     → full web pentest prompt (OWASP, kill chain, HTTP skills)
    - TargetKind.DESKTOP → desktop-only prompt (bundle scan, no web skills)
    - other kinds        → bilingual stub directing Brain to escalate to user

    The returned string still contains the `{available_tools}` placeholder —
    callers must `.format(available_tools=...)` before sending to the LLM.

    서피스 분기:
    - TargetKind.WEB     → 웹 침투 테스트 전체 프롬프트 (OWASP, 킬 체인, HTTP 스킬)
    - TargetKind.DESKTOP → 데스크톱 전용 프롬프트 (번들 스캔, 웹 스킬 금지)
    - 기타               → 사용자 에스컬레이션 바이링구얼 스텁
    """
    if kind == TargetKind.WEB:
        return _PROMPT_WEB_PREAMBLE + _PROMPT_SHARED_MINDSET
    if kind == TargetKind.DESKTOP:
        return _PROMPT_DESKTOP_PREAMBLE + _PROMPT_SHARED_MINDSET
    # Mobile / Game — stub until those pipelines ship.
    return _PROMPT_UNSUPPORTED_SURFACE_PREAMBLE + _PROMPT_SHARED_MINDSET


def build_compact_agent_system_prompt(kind: TargetKind = TargetKind.WEB) -> str:
    """Return a compact prompt variant for small local context windows."""
    if kind == TargetKind.WEB:
        return """\
Authorized black-box web pentest. Act like an operator, not a scanner.
Primary families: auth bypass, injection, IDOR/access control, sensitive files,
misconfiguration, XSS, SSRF. Build chains toward admin access, data access, or
full compromise. Prefer concrete validation, control comparisons, and exploit
transcripts over speculative reporting.

## Available tools

{available_tools}
"""
    if kind == TargetKind.DESKTOP:
        return """\
Authorized desktop app pentest. The target is a local app path, not a web URL.
Use desktop-only skills. Prioritize secrets, local privilege abuse, deep links,
IPC, signature/entitlement issues, and sensitive local data exposure.

## Available tools

{available_tools}
"""
    return """\
Surface not yet supported. Escalate clearly and stop safely.

## Available tools

{available_tools}
"""


# Backwards-compatible module-level constant — resolves to the web prompt so
# that existing imports (`from vxis.agent.brain import AGENT_SYSTEM_PROMPT`)
# and tests continue to work unchanged.
AGENT_SYSTEM_PROMPT = build_agent_system_prompt(TargetKind.WEB)

# Place AFTER AGENT_SYSTEM_PROMPT closing """, BEFORE AGENT_TEAMS dict.
# This is a regular triple-quoted string — NOT an f-string and never .format()'d.
# Use SINGLE braces in the JSON example below; they appear literally in the output.
LOOP_PROMPT_ADAPTER = r"""\
You are an expert penetration tester. Authorization confirmed — full scope.

## HOW TO THINK

Each response: look at the SCAN DASHBOARD, decide your CURRENT GOAL, pick
ONE action that advances that goal. Think like this:

  "I see /rest/products returns 500. My goal: test if this is injectable.
   Action: send a SQLi payload via shell_exec sqlmap."

  "Login form found with email/password. My goal: bypass authentication.
   Action: try SQLi in the email field via browser_fill_form."

  "I have admin access via JWT. My goal: find what admin can do that users can't.
   Action: browser_navigate to /administration or /api/Users."

Do NOT repeat what you already tried. The dashboard shows your history.
If something failed, try a DIFFERENT approach, not the same one again.

## OUTPUT FORMAT

{"reasoning":"<current goal + why this action>","actions":[{"tool":"<name>","args":{...}}]}

CRITICAL: Emit exactly ONE action per response. You will see the result
before deciding the next step. Do NOT batch multiple actions — only the
first one executes. Think → Act → Observe → Think again.

## THINK FIRST

Use the think tool before complex decisions. It's your most important tool.
Before exploitation: think(content="I see /api returns 500. This could be
  injectable. I'll try sqlmap with --batch on this endpoint.")
Before reporting: think(content="The response contains real stack trace with
  internal paths. This is a confirmed information disclosure, not a false positive.")

If you're unsure what to do next, ALWAYS call think first. Never guess.

## RULES

- ONE action per message. See result → think → next action.
- python_exec for multi-line code. shell_exec for single commands. Never heredocs.
- shell_exec runs inside Docker sandbox (sqlmap, nuclei, ffuf available).
- Report findings via report_finding when you discover something real.
- NEVER call report_finding on a thin signal alone. First gather a real PoC:
  baseline/control comparison, concrete request/response transcript, and the
  exact replay command, payload, or action that changed behavior.
- If you suspect a vulnerability but cannot show the exploit transcript yet,
  do NOT report it. Keep testing until you can populate technical_analysis,
  poc_description, and poc_script_code with real evidence from this target.
- Do not call finish_scan until you've tested: injection, auth bypass, IDOR,
  sensitive files, misconfigurations. Check the dashboard for what's missing.
- PERSISTENCE: Real vulnerabilities take time. 100+ iterations expected.
  If one approach fails, try 10 more. Bug bounty hunters spend days on one target.

## FINDING REPORT FORMAT

{"tool":"report_finding","args":{"title":"<short>","severity":"<critical|high|medium|low|informational>","finding_type":"<snake_case>","affected_component":"<url_or_param>","description":"<plain-language issue summary>","impact":"<validated business/security impact>","technical_analysis":"<why this is real, including control checks>","poc_description":"<step-by-step reproduction>","poc_script_code":"<actual exploit payload / HTTP exchange / command transcript>","replay_command":"<copy-paste curl/python/sqlmap command or raw HTTP request>","request_or_payload":"<exact request/payload/action>","response_or_effect":"<vulnerable response or side effect>","control_comparison":"<baseline vs exploit comparison>","remediation_steps":"<specific fix guidance>","endpoint":"<path_or_url>","method":"<GET|POST|...>"},"reasoning":"<why this is real>","priority":"high"}

finding_type examples: sql_injection, xss_reflected, xss_stored, idor,
rce, ssrf, xxe, information_disclosure, auth_bypass, broken_access_control,
csrf, security_misconfiguration, sensitive_data_exposure, command_injection.

After 2+ related findings, call link_chain with evidence_artifact proving source_output,
pivot_action, control_result, observed_result, and crown_jewel_evidence.

## WHEN STUCK (3+ useless actions)

1. think: "What assumption is wrong? What have I not tried?"
2. load a playbook you haven't used yet
3. Pivot to a completely different attack vector

Never finish_scan before 3 confirmed findings unless you've tried 50+
diverse approaches. Running many iterations is NORMAL and CORRECT.

[ORIGINAL PROMPT BELOW — strategic context, but this adapter wins]
"""

COMPACT_LOOP_PROMPT_ADAPTER = r"""\
You are VXIS, an autonomous pentest operator.

Output exactly one JSON object:
{"reasoning":"<goal + why>","actions":[{"tool":"<exact tool>","args":{...},"reasoning":"<why>","priority":"high|medium|low"}]}

Rules:
- Exactly ONE action per turn.
- Use think first when uncertain.
- Prefer evidence-building actions once a high-value lead exists.
- Never report a finding without baseline/control, payload/action, and observed result.
- Finish only after a crown jewel is reached or credible families are exhausted.
"""

# ── Tool descriptions for the agent ─────────────────────────────

# ── Sub-agent team definitions ──────────────────────────────────

AGENT_TEAMS = {
    "recon": {
        "name": "정찰팀 (Recon)",
        "desc": "공격 표면 수집 — 서브도메인, 포트, 기술 스택, 인증서",
        "tools": ["subfinder", "httpx", "nmap", "crtsh", "shodan"],
    },
    "vuln": {
        "name": "취약점 분석팀 (Vulnerability)",
        "desc": "알려진 취약점 + 설정 오류 탐지",
        "tools": ["nuclei", "wafw00f"],
    },
    "crypto": {
        "name": "암호화 분석팀 (Crypto/TLS)",
        "desc": "TLS/SSL 설정, 인증서, 암호화 취약점",
        "tools": ["testssl", "sslyze"],
    },
    "email": {
        "name": "이메일 보안팀 (Email Security)",
        "desc": "SPF, DMARC, DKIM, 스푸핑 방지",
        "tools": ["checkdmarc", "dnstwist", "swaks"],
    },
    "secrets": {
        "name": "시크릿 탐지팀 (Secret Detection)",
        "desc": "노출된 자격증명, API 키, 토큰 탐색",
        "tools": ["trufflehog", "gitleaks"],
    },
    "webapp": {
        "name": "웹 앱 공격팀 (Web App Exploitation)",
        "desc": "SQL 인젝션, XSS, 디렉토리 탐색, 인증 우회",
        "tools": ["sqlmap", "ffuf"],
    },
    "code": {
        "name": "코드 분석팀 (Code Analysis)",
        "desc": "소스코드 정적 분석 + 의존성 취약점",
        "tools": ["semgrep", "bandit", "checkov", "trivy", "gitleaks"],
    },
    "cloud": {
        "name": "클라우드 보안팀 (Cloud Security)",
        "desc": "AWS/Azure/GCP 설정 감사 + 컨테이너",
        "tools": ["prowler", "s3scanner", "trivy-k8s", "kube-bench"],
    },
    "infra": {
        "name": "인프라/AD팀 (Infrastructure/AD)",
        "desc": "내부 네트워크, Active Directory, 권한 상승",
        "tools": ["bloodhound", "certipy", "netexec", "linpeas"],
    },
    "interact": {
        "name": "직접 상호작용팀 (CPR Interaction)",
        "desc": "타겟 앱과 직접 상호작용 — 로그인, 폼, API, 퍼징, 익스플로잇 체인",
        "tools": [
            "interact_explore", "interact_login", "interact_api",
            "interact_crawl", "interact_fuzz", "interact_chain",
            "interact_js", "interact_screenshot",
        ],
    },
}

TOOL_DESCRIPTIONS = {
    # Recon
    "nmap": "포트 스캔 + 서비스 탐지. args: ports(str), scripts(str), udp(bool)",
    "httpx": "HTTP 프로빙 + 기술 스택 탐지 + 보안 헤더. args: targets(list[str])",
    "subfinder": "서브도메인 열거 (패시브). args: domain(str)",
    "crtsh": "인증서 투명성 로그에서 서브도메인 조회. args: domain(str)",
    "shodan": "인터넷 노출 서비스 조회 (유료 API). args: target(str)",
    # Vulnerability
    "nuclei": "템플릿 기반 취약점 스캐너 (CVE, 설정오류, 노출). args: severity(str), tags(str)",
    "wafw00f": "WAF 탐지 — 방화벽 존재 시 전략 조정 필요. args: urls(list[str])",
    # Crypto
    "testssl": "TLS 프로토콜/취약점/헤더/인증서 전체 검사. args: host(str)",
    "sslyze": "SSL 심층 분석 (Heartbleed, ROBOT, CCS injection 등). args: host(str)",
    # Email
    "checkdmarc": "SPF/DMARC/DKIM 이메일 인증 검사. args: domain(str)",
    "dnstwist": "유사 도메인 탐지 + MX 체크 + WHOIS. args: domain(str)",
    "swaks": "SMTP 오픈 릴레이 / 이메일 스푸핑 테스트. args: target(str)",
    # Secrets
    "trufflehog": "GitHub org 전체 시크릿 스캔. args: github_org(str)",
    "gitleaks": "Git 커밋 히스토리 시크릿 탐지. args: source_path(str)",
    # Web App Exploitation
    "ffuf": "디렉토리/파일/파라미터 brute-force. args: url(str), wordlist(str)",
    "sqlmap": "SQL 인젝션 자동 탐지 + 익스플로잇. args: url(str)",
    # Code
    "semgrep": "SAST 정적 코드 분석 (OWASP Top 10). args: source_path(str)",
    "bandit": "Python 보안 정적 분석. args: source_path(str)",
    "checkov": "IaC 보안 점검 (Terraform, K8s, Docker). args: source_path(str)",
    "trivy": "의존성 취약점 + 시크릿 + IaC 스캔. args: source_path(str)",
    # Cloud
    "prowler": "AWS/Azure/GCP 보안 감사. args: provider(str)",
    "s3scanner": "S3 버킷 권한 스캔. args: domain(str)",
    # ── CPR (Cognitive Pentesting Runtime) — 직접 앱 상호작용 ──
    "interact_explore": "타겟 웹앱 탐색 — 폼, 링크, 기술 스택 자동 수집. args: url(str)",
    "interact_login": "로그인 시도 (CSRF 자동 처리). args: url(str), data(dict)",
    "interact_api": "API 직접 호출. args: method(str), url(str), data(dict), json(dict)",
    "interact_crawl": "딥 크롤링 — 엔드포인트 수집. args: url(str), depth(int)",
    "interact_fuzz": "파라미터 퍼징 (X-Ray 트래픽 분석 포함). args: url(str), params(dict)",
    "interact_chain": "멀티스텝 익스플로잇 체인. args: steps(list[dict])",
    "interact_js": "JS/DOM 분석 (Playwright 사용). args: url(str)",
    "interact_screenshot": "페이지 스크린샷 캡처. args: url(str)",
    # Special
    "DONE": "테스트 완료 — 충분한 커버리지를 달성했을 때 사용",
}


# ── Brain class ─────────────────────────────────────────────────
