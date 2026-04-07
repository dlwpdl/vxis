"""VXIS CPR — Hands: HTTP 세션 매니저.

Brain이 타겟 앱과 직접 상호작용하는 "손".
단순 HTTP 클라이언트가 아니라, 인증 상태를 자동 추적하는 지능형 세션 엔진.

핵심 기능:
    1. 세션 자동 관리 — 쿠키, JWT, CSRF 토큰 자동 추적/갱신
    2. 인증 흐름 — 로그인 → 인증된 스캔 → 로그아웃 자동화
    3. 폼 파싱 — HTML에서 폼/입력 필드 자동 추출
    4. 요청 체이닝 — 멀티스텝 익스플로잇 체인 지원
    5. 응답 분석 — 에러 패턴, 리다이렉트, WAF 감지
    6. 속도 제어 — 적응형 Rate Limiting (WAF 우회)

Architecture:
    SessionManager (타겟별 세션 풀)
        └── TargetSession (단일 타겟 세션)
                ├── AuthState (인증 상태 FSM)
                ├── CookieJar (쿠키 자동 관리)
                ├── CSRFTracker (CSRF 토큰 추적)
                └── RequestChain (멀티스텝 체인)

Usage:
    mgr = SessionManager()
    session = await mgr.get_session("https://target.com")

    # 인증 없이 탐색
    resp = await session.get("/api/v1/users")
    forms = await session.discover_forms("/login")

    # 로그인 후 인증된 스캔
    await session.login(url="/login", data={"user": "admin", "pass": "test"})
    resp = await session.get("/admin/dashboard")

    # 멀티스텝 체인
    chain = session.chain()
    chain.get("/api/token")
    chain.post("/api/transfer", json={"amount": -1})
    results = await chain.execute()
"""

from __future__ import annotations

import asyncio
import html.parser
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from vxis.ghost.layer import ghost_layer
from vxis.ghost.transport import GhostTransport

logger = logging.getLogger(__name__)


# ── Auth State Machine ──────────────────────────────────────────


class AuthState(Enum):
    """인증 상태 FSM."""

    ANONYMOUS = "anonymous"          # 인증 안 됨
    AUTHENTICATED = "authenticated"  # 로그인 성공
    EXPIRED = "expired"              # 세션 만료 감지
    BLOCKED = "blocked"              # WAF/Rate limit 차단


# ── Response Analysis ────────────────────────────────────────────


@dataclass
class AnalyzedResponse:
    """HTTP 응답 분석 결과."""

    response: httpx.Response
    status: int
    url: str
    content_type: str = ""
    body_length: int = 0
    is_redirect: bool = False
    is_error: bool = False
    is_waf_block: bool = False
    is_auth_required: bool = False
    is_rate_limited: bool = False
    detected_tech: list[str] = field(default_factory=list)
    forms: list[FormData] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    cookies_set: list[str] = field(default_factory=list)
    security_headers: dict[str, str] = field(default_factory=dict)
    error_patterns: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return self.response.text

    @property
    def headers(self) -> httpx.Headers:
        return self.response.headers


@dataclass
class FormData:
    """HTML 폼 파싱 결과."""

    action: str
    method: str  # GET or POST
    fields: dict[str, str]  # name → value (hidden 포함)
    has_csrf: bool = False
    csrf_field: str = ""
    csrf_value: str = ""
    enctype: str = "application/x-www-form-urlencoded"


@dataclass
class ChainStep:
    """요청 체인의 한 단계."""

    method: str
    path: str
    data: dict[str, Any] | None = None
    json_data: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    extract: dict[str, str] | None = None  # name → regex/jsonpath to extract from response


@dataclass
class ChainResult:
    """체인 실행 결과."""

    steps: list[AnalyzedResponse] = field(default_factory=list)
    extracted: dict[str, str] = field(default_factory=dict)  # extracted values
    success: bool = True
    failed_at: int = -1  # which step failed (-1 = none)


# ── HTML Form Parser ─────────────────────────────────────────────


class _FormParser(html.parser.HTMLParser):
    """HTML에서 <form> 태그와 <input> 필드를 추출."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[FormData] = []
        self.links: list[str] = []
        self._current_form: dict[str, Any] | None = None
        self._current_fields: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)

        if tag == "form":
            self._current_form = {
                "action": attr.get("action", ""),
                "method": (attr.get("method", "GET")).upper(),
                "enctype": attr.get("enctype", "application/x-www-form-urlencoded"),
            }
            self._current_fields = {}

        elif tag == "input" and self._current_form is not None:
            name = attr.get("name", "")
            value = attr.get("value", "")
            if name:
                self._current_fields[name] = value

        elif tag == "select" and self._current_form is not None:
            name = attr.get("name", "")
            if name:
                self._current_fields[name] = ""

        elif tag == "textarea" and self._current_form is not None:
            name = attr.get("name", "")
            if name:
                self._current_fields[name] = ""

        elif tag == "a":
            href = attr.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            # CSRF 토큰 탐지
            csrf_field = ""
            csrf_value = ""
            has_csrf = False
            csrf_patterns = ("csrf", "token", "_token", "xsrf", "authenticity")
            for fname, fval in self._current_fields.items():
                if any(p in fname.lower() for p in csrf_patterns):
                    has_csrf = True
                    csrf_field = fname
                    csrf_value = fval
                    break

            self.forms.append(FormData(
                action=self._current_form["action"],
                method=self._current_form["method"],
                fields=dict(self._current_fields),
                has_csrf=has_csrf,
                csrf_field=csrf_field,
                csrf_value=csrf_value,
                enctype=self._current_form["enctype"],
            ))
            self._current_form = None
            self._current_fields = {}


# ── WAF / Error Detection ────────────────────────────────────────

_WAF_SIGNATURES = [
    (r"cloudflare", "Cloudflare"),
    (r"akamai", "Akamai"),
    (r"mod_security|modsecurity", "ModSecurity"),
    (r"imperva|incapsula", "Imperva"),
    (r"aws[- ]?waf", "AWS WAF"),
    (r"sucuri", "Sucuri"),
    (r"barracuda", "Barracuda"),
    (r"f5[- ]?big[- ]?ip", "F5 BIG-IP"),
    (r"fortiweb|fortigate", "Fortinet"),
    (r"wallarm", "Wallarm"),
]

_AUTH_REQUIRED_PATTERNS = [
    # 인증 필요를 나타내는 명확한 패턴만 (단순 "login" 링크는 제외)
    r"(session.?expired|token.?expired|please.?log.?in|login.?required)",
    r"(unauthorized.?access|authentication.?required|access.?denied)",
    r"(you.?must.?be.?logged|sign.?in.?to.?continue|redirect.*login)",
]

_ERROR_PATTERNS = [
    (r"sql.*syntax|mysql.*error|pg.*error|ora-\d+", "SQL Error"),
    (r"stack.?trace|traceback|exception", "Stack Trace"),
    (r"undefined.?index|undefined.?variable", "PHP Error"),
    (r"internal.?server.?error", "500 Error"),
    (r"null.?pointer|NullReferenceException", "Null Pointer"),
    (r"permission.?denied|access.?denied", "Access Denied"),
]

_SECURITY_HEADERS = [
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "content-security-policy",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]


def _detect_waf(headers: httpx.Headers, body: str) -> tuple[bool, str]:
    """WAF 감지."""
    server = headers.get("server", "").lower()
    all_headers = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
    check_text = f"{server} {all_headers} {body[:5000].lower()}"

    for pattern, name in _WAF_SIGNATURES:
        if re.search(pattern, check_text, re.IGNORECASE):
            return True, name
    return False, ""


def _analyze_response(resp: httpx.Response, base_url: str) -> AnalyzedResponse:
    """HTTP 응답을 분석."""
    ct = resp.headers.get("content-type", "")
    # text, json, xml, javascript 등 텍스트 기반 응답만 분석
    _text_types = ("text/", "application/json", "application/xml", "application/javascript")
    is_text = any(ct.lower().startswith(t) for t in _text_types) or not ct
    try:
        body = resp.text if is_text else ""
    except Exception:
        body = ""
    is_html = "html" in ct.lower()

    # WAF 감지
    is_waf, waf_name = _detect_waf(resp.headers, body)

    # 에러 패턴 탐지
    error_patterns = []
    for pattern, name in _ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            error_patterns.append(name)

    # 보안 헤더 수집
    sec_headers = {}
    for h in _SECURITY_HEADERS:
        val = resp.headers.get(h)
        if val:
            sec_headers[h] = val

    # 폼 + 링크 파싱
    forms: list[FormData] = []
    links: list[str] = []
    if is_html and body:
        try:
            parser = _FormParser()
            parser.feed(body)
            forms = parser.forms
            # 상대 URL → 절대 URL
            links = [urljoin(base_url, href) for href in parser.links]
            for form in forms:
                if form.action and not form.action.startswith("http"):
                    form.action = urljoin(base_url, form.action)
        except Exception:
            pass

    # 기술 스택 감지 (헤더 기반)
    detected_tech = []
    tech_headers = {
        "x-powered-by": None,
        "server": None,
        "x-aspnet-version": "ASP.NET",
        "x-drupal-cache": "Drupal",
        "x-generator": None,
    }
    for header, tech_name in tech_headers.items():
        val = resp.headers.get(header)
        if val:
            detected_tech.append(tech_name or val)

    # 쿠키
    cookies_set = [c.split("=")[0] for c in resp.headers.get_list("set-cookie")]

    # 인증 필요 여부 — 상태 코드 + WWW-Authenticate 헤더 + 명확한 패턴만
    is_auth_required = resp.status_code in (401, 403)
    if not is_auth_required and resp.headers.get("www-authenticate"):
        is_auth_required = True
    if not is_auth_required and body and resp.status_code >= 400:
        # 에러 응답에서만 인증 패턴 검색 (일반 페이지의 "login" 링크 오탐 방지)
        is_auth_required = any(
            re.search(p, body, re.IGNORECASE) for p in _AUTH_REQUIRED_PATTERNS
        )

    # 리다이렉트 감지 — follow_redirects=True라서 resp.history로 판단
    was_redirected = bool(resp.history)

    return AnalyzedResponse(
        response=resp,
        status=resp.status_code,
        url=str(resp.url),
        content_type=ct,
        body_length=len(resp.content) if resp.content else 0,
        is_redirect=was_redirected,
        is_error=resp.status_code >= 400,
        is_waf_block=is_waf,
        is_auth_required=is_auth_required,
        is_rate_limited=resp.status_code == 429,
        detected_tech=detected_tech,
        forms=forms,
        links=links,
        cookies_set=cookies_set,
        security_headers=sec_headers,
        error_patterns=error_patterns,
    )


# ── CSRF Tracker ─────────────────────────────────────────────────


class CSRFTracker:
    """CSRF 토큰 자동 추적 및 갱신."""

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}  # field_name → value
        self._header_token: str = ""
        self._header_name: str = ""

    def update_from_form(self, form: FormData) -> None:
        if form.has_csrf:
            self._tokens[form.csrf_field] = form.csrf_value
            logger.debug("CSRF token updated: %s=%s...", form.csrf_field, form.csrf_value[:8])

    def update_from_headers(self, headers: httpx.Headers) -> None:
        for name in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
            val = headers.get(name)
            if val:
                self._header_name = name
                self._header_token = val
                logger.debug("CSRF header token: %s=%s...", name, val[:8])

    def update_from_cookies(self, cookies: httpx.Cookies) -> None:
        # 쿠키 이름 → 요청 헤더 이름 매핑 (프레임워크별)
        _cookie_header_map = {
            "csrftoken": "X-CSRFToken",        # Django
            "csrf_token": "X-CSRF-Token",       # Rails, general
            "_csrf": "X-CSRF-Token",            # Express
            "XSRF-TOKEN": "X-XSRF-TOKEN",      # Angular, Axios
            "_csrf_token": "X-CSRF-Token",      # Phoenix
        }
        for cookie_name, header_name in _cookie_header_map.items():
            val = cookies.get(cookie_name)
            if val:
                self._header_name = header_name
                self._header_token = val
                break

    def inject_into_data(self, data: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(data, dict):
            return data
        result = dict(data)
        for fname, fval in self._tokens.items():
            if fname not in result:
                result[fname] = fval
        return result

    def inject_into_headers(self, headers: dict[str, str]) -> dict[str, str]:
        result = dict(headers)
        if self._header_name and self._header_token:
            result[self._header_name] = self._header_token
        return result

    @property
    def has_token(self) -> bool:
        return bool(self._tokens) or bool(self._header_token)


# ── Target Session ───────────────────────────────────────────────


class TargetSession:
    """단일 타겟에 대한 지능형 HTTP 세션.

    httpx.AsyncClient를 래핑하며, 인증 상태/CSRF/WAF를 자동 추적.
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        max_redirects: int = 5,
        verify_ssl: bool = False,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        proxy: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_state = AuthState.ANONYMOUS
        self.csrf = CSRFTracker()
        self._request_count = 0
        self._last_request_time = 0.0

        # Profile에 따른 기본 딜레이 설정
        import os as _os
        _profile = _os.environ.get("VXIS_SCAN_PROFILE", "standard")
        _profile_delays = {"stealth": 2.0, "standard": 0.1, "aggressive": 0.0}
        self._min_delay = _profile_delays.get(_profile, 0.1)

        self._history: list[AnalyzedResponse] = []
        self._max_history = 500  # OOM 방지
        self._discovered_endpoints: set[str] = set()
        self._consecutive_timeouts = 0
        self._base_timeout = timeout
        self._effective_timeout = timeout  # 적응형: 느린 타겟이면 자동 증가

        client_kwargs: dict[str, Any] = {
            "base_url": self.base_url,
            "timeout": httpx.Timeout(timeout),
            "follow_redirects": True,
            "max_redirects": max_redirects,
            "verify": verify_ssl,
            "headers": {
                "User-Agent": user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9,ko;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
            },
        }
        if transport is not None:
            client_kwargs["transport"] = transport
        elif proxy:
            client_kwargs["proxy"] = proxy
        self._client = httpx.AsyncClient(**client_kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    # ── Core HTTP Methods ──────────────────────────────────────

    async def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> AnalyzedResponse:
        """HTTP 요청 + 자동 분석."""
        # Rate limiting (적응형)
        await self._throttle()

        # CSRF 토큰 자동 주입
        extra_headers = dict(headers or {})
        if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            extra_headers = self.csrf.inject_into_headers(extra_headers)
            if data is not None:
                data = self.csrf.inject_into_data(data)

        # 적응형 타임아웃: 연속 타임아웃 시 서버가 느린 거 → 타임아웃 증가
        # 상한 1.5x (base=30 → max=45). 이전엔 3x=90이라 time-based SQLi
        # 한 번이 전체 스캔을 마비시켰음. 45초 넘어가면 그 엔드포인트가
        # 진짜 죽은 거니 Pipeline executor가 다음 벡터로 넘어가게 둔다.
        _ADAPTIVE_CAP = 1.5
        if self._consecutive_timeouts >= 2 and self._effective_timeout < self._base_timeout * _ADAPTIVE_CAP:
            new_timeout = min(self._effective_timeout * 1.5, self._base_timeout * _ADAPTIVE_CAP)
            if new_timeout > self._effective_timeout:
                self._effective_timeout = new_timeout
                self._client.timeout = httpx.Timeout(self._effective_timeout)
                logger.info("  [ADAPTIVE] Slow target detected — timeout → %.0fs", self._effective_timeout)

        try:
            resp = await self._client.request(
                method=method.upper(),
                url=path,
                data=data,
                json=json_data,
                headers=extra_headers if extra_headers else None,
                params=params,
            )
            self._consecutive_timeouts = 0
        except httpx.TimeoutException:
            self._consecutive_timeouts += 1
            _display_url = path if path.startswith("http") else f"{self.base_url}{path}"
            logger.warning("Timeout (%ds): %s %s", int(self._effective_timeout), method, _display_url)
            raise
        except httpx.ConnectError as e:
            _display_url = path if path.startswith("http") else f"{self.base_url}{path}"
            logger.warning("Connection failed: %s %s: %s", method, _display_url, e)
            raise

        self._request_count += 1
        self._last_request_time = time.monotonic()

        # 응답 분석
        analyzed = _analyze_response(resp, self.base_url)
        self._history.append(analyzed)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        # CSRF 토큰 갱신
        for form in analyzed.forms:
            self.csrf.update_from_form(form)
        self.csrf.update_from_headers(resp.headers)
        self.csrf.update_from_cookies(self._client.cookies)

        # 인증 상태 업데이트
        self._update_auth_state(analyzed)

        # WAF 감지 시 딜레이 증가
        if analyzed.is_waf_block or analyzed.is_rate_limited:
            self._min_delay = min(self._min_delay + 1.0, 10.0)
            logger.warning("WAF/Rate limit detected — delay increased to %.1fs", self._min_delay)

        # 엔드포인트 수집
        for link in analyzed.links:
            parsed = urlparse(link)
            if parsed.netloc == "" or parsed.netloc == urlparse(self.base_url).netloc:
                self._discovered_endpoints.add(parsed.path)

        logger.debug(
            "%s %s → %d (%d bytes, %d forms, %d links)",
            method, path, analyzed.status, analyzed.body_length,
            len(analyzed.forms), len(analyzed.links),
        )

        return analyzed

    async def get(self, path: str, **kwargs: Any) -> AnalyzedResponse:
        return await self.request("GET", path, **kwargs)

    async def post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AnalyzedResponse:
        return await self.request("POST", path, data=data, json_data=json_data, **kwargs)

    async def put(self, path: str, **kwargs: Any) -> AnalyzedResponse:
        return await self.request("PUT", path, **kwargs)

    async def delete(self, path: str, **kwargs: Any) -> AnalyzedResponse:
        return await self.request("DELETE", path, **kwargs)

    # ── High-Level Actions ──────────────────────────────────────

    async def login(
        self,
        url: str = "/login",
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
    ) -> AnalyzedResponse:
        """로그인 시도.

        1. 로그인 페이지 GET → CSRF 토큰 수집
        2. POST 로그인 데이터
        3. 결과 분석 (성공/실패/차단)
        """
        # Step 1: GET 로그인 페이지 (CSRF 토큰 수집)
        get_resp = await self.get(url)
        logger.info("Login page: %d, %d forms found", get_resp.status, len(get_resp.forms))

        # 로그인 폼의 hidden 필드 자동 포함
        if get_resp.forms and data is not None:
            login_form = get_resp.forms[0]
            merged = dict(login_form.fields)
            merged.update(data)
            data = merged
            if login_form.action:
                url = login_form.action

        # Step 2: POST 로그인
        resp = await self.post(url, data=data, json_data=json_data)

        if resp.status < 400 and not resp.is_auth_required:
            self.auth_state = AuthState.AUTHENTICATED
            logger.info("Login successful: %s → %d", url, resp.status)
        else:
            logger.warning("Login failed: %s → %d", url, resp.status)

        return resp

    async def discover_forms(self, path: str = "/") -> list[FormData]:
        """페이지의 모든 폼 발견."""
        resp = await self.get(path)
        return resp.forms

    async def crawl_links(self, path: str = "/", depth: int = 1) -> set[str]:
        """링크 크롤링 — 엔드포인트 수집."""
        visited: set[str] = set()
        to_visit: set[str] = {path}

        for _ in range(depth):
            next_batch: set[str] = set()
            for url in to_visit:
                if url in visited:
                    continue
                visited.add(url)
                try:
                    resp = await self.get(url)
                    for link in resp.links:
                        parsed = urlparse(link)
                        if parsed.netloc == "" or parsed.netloc == urlparse(self.base_url).netloc:
                            if parsed.path not in visited:
                                next_batch.add(parsed.path)
                except Exception:
                    continue
            to_visit = next_batch

        self._discovered_endpoints.update(visited)
        return visited

    # ── Request Chain (멀티스텝 익스플로잇) ───────────────────────

    def chain(self) -> RequestChain:
        """멀티스텝 요청 체인 생성."""
        return RequestChain(self)

    # ── Introspection ─────────────────────────────────────────────

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def discovered_endpoints(self) -> set[str]:
        return set(self._discovered_endpoints)

    @property
    def history(self) -> list[AnalyzedResponse]:
        return list(self._history)

    @property
    def cookies(self) -> dict[str, str]:
        return dict(self._client.cookies)

    def get_fingerprint(self) -> dict[str, Any]:
        """타겟 핑거프린트 요약."""
        all_tech: set[str] = set()
        all_sec_headers: dict[str, str] = {}
        all_errors: set[str] = set()
        waf_detected = False

        for resp in self._history:
            all_tech.update(resp.detected_tech)
            all_sec_headers.update(resp.security_headers)
            all_errors.update(resp.error_patterns)
            if resp.is_waf_block:
                waf_detected = True

        return {
            "base_url": self.base_url,
            "auth_state": self.auth_state.value,
            "requests_made": self._request_count,
            "endpoints_discovered": len(self._discovered_endpoints),
            "tech_stack": sorted(all_tech),
            "security_headers": all_sec_headers,
            "missing_security_headers": [
                h for h in _SECURITY_HEADERS if h not in all_sec_headers
            ],
            "error_patterns": sorted(all_errors),
            "waf_detected": waf_detected,
            "has_csrf": self.csrf.has_token,
        }

    # ── Internal ─────────────────────────────────────────────────

    def _update_auth_state(self, resp: AnalyzedResponse) -> None:
        if self.auth_state == AuthState.AUTHENTICATED:
            if resp.is_auth_required:
                self.auth_state = AuthState.EXPIRED
                logger.warning("Session expired detected")
        elif self.auth_state == AuthState.BLOCKED:
            # WAF 차단 후 정상 응답이면 복구
            if not resp.is_waf_block and not resp.is_rate_limited and resp.status < 400:
                self.auth_state = AuthState.ANONYMOUS
                self._min_delay = max(self._min_delay - 0.5, 0.0)
                logger.info("WAF block recovered — session unblocked")

        if resp.is_waf_block and self.auth_state != AuthState.BLOCKED:
            self.auth_state = AuthState.BLOCKED
            logger.warning("WAF block detected — session marked as blocked")

    async def _throttle(self) -> None:
        if ghost_layer.is_active():
            effective = max(ghost_layer.next_delay(), self._min_delay)
        else:
            effective = self._min_delay

        if effective > 0:
            elapsed = time.monotonic() - self._last_request_time
            if elapsed < effective:
                await asyncio.sleep(effective - elapsed)
            elif not ghost_layer.is_active() and self._min_delay > 0 and elapsed > self._min_delay * 3:
                self._min_delay = max(self._min_delay - 0.2, 0.0)


# ── Request Chain ────────────────────────────────────────────────


class RequestChain:
    """멀티스텝 요청 체인.

    Usage:
        chain = session.chain()
        chain.get("/api/token")
        chain.post("/api/transfer", json={"amount": -1})
        chain.post("/api/confirm", extract={"txn_id": r'"id":\\s*"([^"]+)"'})
        result = await chain.execute()

        print(result.extracted["txn_id"])
    """

    def __init__(self, session: TargetSession) -> None:
        self._session = session
        self._steps: list[ChainStep] = []

    def get(self, path: str, **kwargs: Any) -> RequestChain:
        self._steps.append(ChainStep(method="GET", path=path, **kwargs))
        return self

    def post(
        self,
        path: str,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> RequestChain:
        self._steps.append(ChainStep(
            method="POST", path=path, data=data, json_data=json_data, **kwargs,
        ))
        return self

    def put(self, path: str, **kwargs: Any) -> RequestChain:
        self._steps.append(ChainStep(method="PUT", path=path, **kwargs))
        return self

    def delete(self, path: str, **kwargs: Any) -> RequestChain:
        self._steps.append(ChainStep(method="DELETE", path=path, **kwargs))
        return self

    async def execute(self, stop_on_error: bool = True) -> ChainResult:
        """체인의 모든 스텝을 순차 실행."""
        result = ChainResult()

        for i, step in enumerate(self._steps):
            try:
                # 이전 스텝에서 추출한 값을 현재 스텝에 주입
                path = self._interpolate(step.path, result.extracted)
                data = self._interpolate_dict(step.data, result.extracted) if step.data else None
                json_data = (
                    self._interpolate_dict(step.json_data, result.extracted)
                    if step.json_data else None
                )

                resp = await self._session.request(
                    method=step.method,
                    path=path,
                    data=data,
                    json_data=json_data,
                    headers=step.headers,
                )
                result.steps.append(resp)

                # 값 추출
                if step.extract:
                    for name, pattern in step.extract.items():
                        match = re.search(pattern, resp.text)
                        if match:
                            result.extracted[name] = match.group(1) if match.groups() else match.group(0)
                            logger.debug("Extracted %s=%s", name, result.extracted[name][:50])

                # 에러 체크
                if resp.is_error and stop_on_error:
                    result.success = False
                    result.failed_at = i
                    logger.warning("Chain failed at step %d: %s %s → %d", i, step.method, path, resp.status)
                    break

            except Exception as exc:
                result.success = False
                result.failed_at = i
                logger.warning("Chain exception at step %d: %s", i, exc)
                break

        return result

    @staticmethod
    def _interpolate(text: str, values: dict[str, str]) -> str:
        """{{name}} 플레이스홀더를 추출된 값으로 치환."""
        for name, val in values.items():
            text = text.replace(f"{{{{{name}}}}}", val)
        return text

    @staticmethod
    def _interpolate_dict(
        data: dict[str, Any] | None,
        values: dict[str, str],
    ) -> dict[str, Any] | None:
        if data is None:
            return None
        result: dict[str, Any] = {}
        for k, v in data.items():
            if isinstance(v, str):
                for name, val in values.items():
                    v = v.replace(f"{{{{{name}}}}}", val)
            result[k] = v
        return result


# ── Session Manager (타겟별 세션 풀) ─────────────────────────────


class SessionManager:
    """타겟별 세션을 관리하는 풀.

    Usage:
        mgr = SessionManager()
        session = await mgr.get_session("https://target.com")
        await session.get("/")
        await mgr.close_all()
    """

    def __init__(self) -> None:
        self._sessions: dict[str, TargetSession] = {}

    async def get_session(
        self,
        base_url: str,
        **kwargs: Any,
    ) -> TargetSession:
        """타겟 URL에 대한 세션 반환 (없으면 생성)."""
        key = urlparse(base_url).netloc
        if key not in self._sessions:
            # GhostLayer 활성 시 GhostTransport 주입
            if ghost_layer.is_active() and "transport" not in kwargs:
                kwargs["transport"] = GhostTransport(ghost_layer)
            session = TargetSession(base_url, **kwargs)
            self._sessions[key] = session
            logger.info("New session created: %s (ghost=%s)", base_url, ghost_layer.is_active())
        return self._sessions[key]

    async def close_session(self, base_url: str) -> None:
        key = urlparse(base_url).netloc
        session = self._sessions.pop(key, None)
        if session:
            await session.close()

    async def close_all(self) -> None:
        for session in self._sessions.values():
            await session.close()
        self._sessions.clear()

    @property
    def active_sessions(self) -> dict[str, AuthState]:
        return {url: s.auth_state for url, s in self._sessions.items()}
