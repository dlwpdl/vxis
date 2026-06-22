"""VXIS CPR — Interaction Controller: Brain이 감각을 선택하는 통합 컨트롤러.

핵심 역할:
    Brain이 "이 상황에서 어떤 감각(Eyes/Hands/X-Ray)을 쓸지" 자동 결정.
    상황에 따라 최적의 인터랙션 방법을 동적으로 선택.

결정 로직:
    ┌─────────────────────────────────────────────┐
    │  Brain: "로그인 페이지 테스트해야 한다"         │
    │                                               │
    │  Controller 판단:                             │
    │  1. SPA 앱인가? → Eyes (브라우저 필요)         │
    │  2. 단순 HTML 폼? → Hands (httpx로 충분)      │
    │  3. 토큰 분석 필요? → X-Ray + Hands           │
    │  4. JS 기반 인증? → Eyes + X-Ray (동시)       │
    └─────────────────────────────────────────────┘

Usage:
    controller = InteractionController(target="https://target.com")
    await controller.start()

    # Brain이 액션 요청 → Controller가 최적의 감각 선택
    result = await controller.execute(InteractionAction(
        intent="login_test",
        url="/login",
        data={"username": "admin", "password": "admin"},
    ))

    # 타겟 핑거프린트 (기술 스택, 보안 헤더, WAF 등)
    fingerprint = controller.get_target_profile()

    await controller.stop()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from vxis.interaction.hands import (
    AnalyzedResponse,
    AuthState,
    ScopeBlockedError,
    SessionManager,
    TargetSession,
)
from vxis.interaction.surface import Surface, Target, TargetKind
from vxis.interaction.xray import (
    FlowAnalyzer,
    MitmProxyManager,
    TrafficSummary,
)

logger = logging.getLogger(__name__)

# Eyes는 선택적 — Playwright 없으면 Hands만 사용
try:
    from vxis.interaction.eyes import (
        BrowserEngine,
        BrowserPage,
        DOMAnalysis,
        is_available as eyes_available,
    )

    EYES_AVAILABLE = eyes_available()
except ImportError:
    EYES_AVAILABLE = False


# ── Interaction Mode ─────────────────────────────────────────────


class InteractionMode(Enum):
    """인터랙션 모드 — Brain이 상황에 따라 선택."""

    HANDS_ONLY = "hands"  # httpx만 (가볍고 빠름)
    EYES_ONLY = "eyes"  # 브라우저만 (JS 필수)
    HANDS_XRAY = "hands+xray"  # httpx + 프록시 (토큰 분석)
    EYES_XRAY = "eyes+xray"  # 브라우저 + 프록시 (풀 스택)
    FULL = "full"  # 전부 활성화


class InteractionIntent(Enum):
    """Brain이 요청하는 인터랙션 의도."""

    EXPLORE = "explore"  # 사이트 탐색 (링크/폼 발견)
    LOGIN = "login"  # 로그인 시도
    FORM_SUBMIT = "form_submit"  # 폼 제출 (payload 주입)
    API_CALL = "api_call"  # API 직접 호출
    FILE_UPLOAD = "file_upload"  # 파일 업로드
    CRAWL = "crawl"  # 딥 크롤링
    FUZZ = "fuzz"  # 퍼징 (파라미터 변조)
    EXPLOIT_CHAIN = "exploit_chain"  # 멀티스텝 익스플로잇
    TOKEN_ANALYSIS = "token_analysis"  # 토큰/세션 분석
    JS_ANALYSIS = "js_analysis"  # JS 코드 분석
    SCREENSHOT = "screenshot"  # 스크린샷 캡처


# ── Interaction Action (Brain → Controller) ──────────────────────


@dataclass
class InteractionAction:
    """Brain이 Controller에게 요청하는 액션."""

    intent: InteractionIntent | str
    url: str = ""
    method: str = "GET"
    data: dict[str, Any] | None = None
    json_data: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    # Chain steps (멀티스텝)
    chain_steps: list[dict[str, Any]] | None = None
    # Options
    follow_redirects: bool = True
    extract_patterns: dict[str, str] | None = None  # name → regex

    @property
    def resolved_intent(self) -> InteractionIntent:
        if isinstance(self.intent, InteractionIntent):
            return self.intent
        try:
            return InteractionIntent(self.intent)
        except ValueError:
            return InteractionIntent.EXPLORE


# ── Interaction Result (Controller → Brain) ──────────────────────


@dataclass
class InteractionFinding:
    """Lightweight finding emitted by the controller mid-loop.

    Distinct from the heavyweight `vxis.models.finding.Finding` (which needs
    scan_id / source_plugin / cvss). Brain consumes these via
    `InteractionResult.findings` to keep its observation stream coherent
    when the controller surfaces a non-fatal signal — e.g. an unsupported
    surface implementation or a degraded mode fallback.
    """

    severity: str
    title: str
    description: str = ""
    surface: str = "web"  # web|desktop|mobile|game


@dataclass
class InteractionResult:
    """Controller가 Brain에게 반환하는 결과."""

    success: bool = True
    mode_used: InteractionMode = InteractionMode.HANDS_ONLY

    # HTTP 결과 (Hands)
    status_code: int = 0
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    forms_found: list[dict[str, Any]] = field(default_factory=list)
    links_found: list[str] = field(default_factory=list)

    # 브라우저 결과 (Eyes)
    dom_analysis: DOMAnalysis | None = None
    page_title: str = ""
    js_errors: list[str] = field(default_factory=list)
    screenshot_path: str = ""

    # 트래픽 분석 (X-Ray)
    traffic_summary: TrafficSummary | None = None
    auth_tokens: list[dict[str, str]] = field(default_factory=list)
    secrets_found: list[dict[str, str]] = field(default_factory=list)
    vulnerabilities: list[dict[str, str]] = field(default_factory=list)

    # In-flight findings emitted during execute() — used by the
    # unsupported-surface informational signal so Brain knows the gap.
    findings: list[InteractionFinding] = field(default_factory=list)

    # Chain 결과
    chain_results: list[dict[str, Any]] = field(default_factory=list)
    extracted_values: dict[str, str] = field(default_factory=dict)

    # 에러
    error: str = ""

    def to_observation(self) -> dict[str, Any]:
        """Brain의 AgentObservation에 주입할 수 있는 딕셔너리."""
        obs: dict[str, Any] = {
            "interaction_mode": self.mode_used.value,
            "status_code": self.status_code,
            "success": self.success,
        }
        if self.forms_found:
            obs["forms"] = self.forms_found
        if self.links_found:
            obs["links_count"] = len(self.links_found)
        if self.dom_analysis:
            obs["login_forms"] = len(self.dom_analysis.login_forms)
            obs["file_uploads"] = len(self.dom_analysis.file_uploads)
            obs["api_endpoints"] = self.dom_analysis.api_endpoints
        if self.auth_tokens:
            obs["auth_tokens_found"] = len(self.auth_tokens)
        if self.vulnerabilities:
            obs["passive_vulns"] = self.vulnerabilities
        if self.error:
            obs["error"] = self.error
        return obs


# ── Mode Selection Logic ─────────────────────────────────────────

# Intent → 추천 모드 매핑
_INTENT_MODE_MAP: dict[InteractionIntent, InteractionMode] = {
    # Brain-First: visual context is mandatory whenever Eyes is available.
    # Hands-only is the fallback when no browser engine is installed.
    InteractionIntent.EXPLORE: InteractionMode.EYES_ONLY,
    InteractionIntent.LOGIN: InteractionMode.EYES_ONLY,
    InteractionIntent.FORM_SUBMIT: InteractionMode.EYES_ONLY,
    InteractionIntent.CRAWL: InteractionMode.EYES_ONLY,
    InteractionIntent.API_CALL: InteractionMode.HANDS_ONLY,  # raw API call → Hands faster
    InteractionIntent.FILE_UPLOAD: InteractionMode.EYES_ONLY,
    InteractionIntent.FUZZ: InteractionMode.HANDS_XRAY,
    InteractionIntent.EXPLOIT_CHAIN: InteractionMode.EYES_XRAY,
    InteractionIntent.TOKEN_ANALYSIS: InteractionMode.HANDS_XRAY,
    InteractionIntent.JS_ANALYSIS: InteractionMode.EYES_ONLY,
    InteractionIntent.SCREENSHOT: InteractionMode.EYES_ONLY,
}

# Frameworks that REQUIRE a real browser to render meaningful content.
# Raw HTTP only sees a tiny loader page (<1KB) for these — useless to the Brain.
_SPA_INDICATORS = [
    # Classic SPAs
    "react",
    "angular",
    "vue",
    "next.js",
    "nuxt",
    "svelte",
    "ember",
    "backbone",
    "polymer",
    "__NEXT_DATA__",
    "ng-app",
    "v-app",
    # Python data-app frameworks (Streamlit/Gradio/Dash/Panel/Solara)
    "streamlit",
    "stApp",
    "gradio",
    "/gradio_api/",
    "dash-renderer",
    "panel",
    "bokeh",
    "solara",
    # Interactive notebooks
    "jupyter",
    "voila",
    # Server-side frameworks that often serve JS-heavy UIs
    "tornadoserver",  # Streamlit/Bokeh/Jupyter all use Tornado
    # Modern meta-frameworks
    "remix",
    "solidjs",
    "qwik",
    "astro",
    "fresh",
    # Mobile-first web (PWA hints)
    "service-worker",
    "workbox",
]


def _select_mode(
    intent: InteractionIntent,
    target_profile: dict[str, Any],
    eyes_available: bool,
    xray_available: bool,
) -> InteractionMode:
    """상황에 맞는 최적의 인터랙션 모드 선택."""
    base_mode = _INTENT_MODE_MAP.get(intent, InteractionMode.HANDS_ONLY)

    # SPA / JS-heavy app detection: tech_stack + server header + body sample
    tech_stack = target_profile.get("tech_stack", [])
    server_hdr = (target_profile.get("server", "") or "").lower()
    body_sample = (target_profile.get("body_sample", "") or "").lower()
    framework_hints = [h.lower() for h in target_profile.get("framework_hints", []) or []]

    haystack = " ".join(tech_stack).lower() + " " + server_hdr + " " + body_sample
    is_spa = any(ind in haystack for ind in _SPA_INDICATORS) or any(
        ind in " ".join(framework_hints) for ind in _SPA_INDICATORS
    )

    if is_spa and eyes_available:
        if base_mode == InteractionMode.HANDS_ONLY:
            base_mode = InteractionMode.EYES_ONLY
        elif base_mode == InteractionMode.HANDS_XRAY:
            base_mode = InteractionMode.EYES_XRAY

    # Eyes 필요하지만 없으면 Hands로 폴백
    if base_mode in (InteractionMode.EYES_ONLY, InteractionMode.EYES_XRAY) and not eyes_available:
        if base_mode == InteractionMode.EYES_ONLY:
            base_mode = InteractionMode.HANDS_ONLY
        else:
            base_mode = InteractionMode.HANDS_XRAY

    # X-Ray 필요하지만 없으면 제거
    if base_mode in (InteractionMode.HANDS_XRAY, InteractionMode.EYES_XRAY) and not xray_available:
        if base_mode == InteractionMode.HANDS_XRAY:
            base_mode = InteractionMode.HANDS_ONLY
        else:
            base_mode = InteractionMode.EYES_ONLY

    return base_mode


# ── Interaction Controller ───────────────────────────────────────


class InteractionController:
    """Brain이 사용하는 통합 인터랙션 인터페이스.

    Usage:
        ctrl = InteractionController("https://target.com")
        await ctrl.start()

        result = await ctrl.execute(InteractionAction(
            intent=InteractionIntent.EXPLORE,
            url="/",
        ))

        profile = ctrl.get_target_profile()
        await ctrl.stop()
    """

    def __init__(
        self,
        target: str,
        enable_eyes: bool = True,
        enable_xray: bool = True,
        proxy_port: int = 8080,
        surface: Surface | None = None,
    ) -> None:
        self._target = target.rstrip("/")
        self._enable_eyes = enable_eyes and EYES_AVAILABLE
        self._enable_xray = enable_xray

        # Hands (항상 활성화)
        self._session_mgr = SessionManager()
        self._session: TargetSession | None = None

        # phase-B.6: Surface dispatch keystone. If the caller injected one
        # (e.g. a test or a non-web Brain harness), reuse it; otherwise the
        # WEB surface is built lazily in start() so the existing public
        # ctor signature stays unchanged.
        self._surface: Surface | None = surface

        # Eyes (선택적)
        self._browser: BrowserEngine | None = None
        self._page: BrowserPage | None = None

        # X-Ray (선택적)
        self._analyzer = FlowAnalyzer()
        self._mitm: MitmProxyManager | None = None
        self._proxy_port = proxy_port

        # Target profile (초기 탐색 후 갱신)
        self._target_profile: dict[str, Any] = {"tech_stack": []}
        self._started = False

    async def start(self) -> None:
        """모든 컴포넌트 초기화."""
        # X-Ray — mitmproxy 있으면 먼저 시작 (Hands/Eyes의 프록시로 사용)
        proxy_url: str | None = None
        if self._enable_xray and MitmProxyManager.is_available():
            self._mitm = MitmProxyManager(port=self._proxy_port)
            try:
                proxy_url = await self._mitm.start()
                logger.info("X-Ray ready: %s", proxy_url)
            except Exception as exc:
                logger.warning("X-Ray failed to start: %s", exc)
                self._mitm = None

        # Hands — 항상 시작 (mitmproxy가 있으면 프록시 경유)
        # INT-C6 fix: Hands 트래픽도 프록시를 통과하도록
        session_kwargs: dict[str, Any] = {}
        if proxy_url:
            session_kwargs["proxy"] = proxy_url
        self._session = await self._session_mgr.get_session(self._target, **session_kwargs)
        logger.info("Hands ready: %s (proxy: %s)", self._target, proxy_url)

        # phase-B.6: ensure a Surface is bound before execute() runs. The
        # WEB factory branch reuses self._session_mgr so cookies / CSRF /
        # auth state stay coherent between surface-routed and direct calls.
        if self._surface is None:
            from vxis.interaction.factory import SurfaceFactory

            self._surface = SurfaceFactory.build(
                Target(kind=TargetKind.WEB, entry=self._target),
                session_mgr=self._session_mgr,
            )
        try:
            await self._surface.hands.start()
        except Exception as exc:
            logger.debug("Surface hands.start() skipped: %s", exc)

        # Eyes — Playwright 있으면 시작 (같은 프록시 사용)
        if self._enable_eyes and EYES_AVAILABLE:
            try:
                self._browser = BrowserEngine(proxy=proxy_url)
                await self._browser.start()
                self._page = await self._browser.new_page()
                logger.info("Eyes ready (proxy: %s)", proxy_url)
            except Exception as exc:
                logger.warning("Eyes failed to start: %s", exc)
                self._browser = None
                self._page = None

        # 초기 탐색 — 타겟 프로필 수집
        await self._initial_probe()

        self._started = True
        logger.info(
            "CPR started: target=%s, eyes=%s, xray=%s",
            self._target,
            self._browser is not None,
            self._mitm is not None,
        )

    async def stop(self) -> None:
        # 각 컴포넌트 개별 정리 — 하나 실패해도 나머지 정리 보장
        # phase-B.6: stop the surface first so kind-specific teardown runs;
        # the surface's hands share self._session_mgr so we still close the
        # SessionManager once at the end.
        for name, cleanup in [
            ("Surface", lambda: self._surface.hands.stop() if self._surface else None),
            ("Eyes", lambda: self._browser.stop() if self._browser else None),
            ("X-Ray", lambda: self._mitm.stop() if self._mitm else None),
            ("Hands", lambda: self._session_mgr.close_all()),
        ]:
            try:
                coro = cleanup()
                if coro:
                    await coro
            except Exception as exc:
                logger.warning("CPR %s cleanup failed: %s", name, exc)
        self._browser = None
        self._page = None
        self._mitm = None
        self._started = False
        logger.info("CPR stopped")

    async def __aenter__(self) -> InteractionController:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()

    # ── Main Execute ─────────────────────────────────────────────

    async def execute(self, action: InteractionAction) -> InteractionResult:
        """Brain의 액션 요청을 실행.

        1. Intent에 맞는 최적의 모드 선택
        2. 선택된 감각(Eyes/Hands/X-Ray)으로 실행
        3. 결과를 Brain이 이해할 수 있는 형태로 반환
        """
        if not self._started:
            await self.start()

        intent = action.resolved_intent
        mode = _select_mode(
            intent=intent,
            target_profile=self._target_profile,
            eyes_available=self._browser is not None,
            xray_available=self._mitm is not None,
        )

        logger.info("Execute: intent=%s, mode=%s, url=%s", intent.value, mode.value, action.url)

        try:
            if intent == InteractionIntent.EXPLOIT_CHAIN and action.chain_steps:
                return await self._execute_chain(action, mode)
            elif intent == InteractionIntent.LOGIN:
                return await self._execute_login(action, mode)
            elif intent == InteractionIntent.JS_ANALYSIS:
                return await self._execute_js_analysis(action, mode)
            elif intent == InteractionIntent.SCREENSHOT:
                return await self._execute_screenshot(action, mode)
            elif intent == InteractionIntent.CRAWL:
                return await self._execute_crawl(action, mode)
            else:
                return await self._execute_http(action, mode)
        except Exception as exc:
            logger.error("Execute failed: %s", exc)
            return InteractionResult(success=False, error=str(exc), mode_used=mode)

    # ── Scope-gated Browser Navigation ──────────────────────────

    async def _navigate_checked(self, url: str):
        """Scope-gate a browser navigation before driving the page there."""
        from vxis.scope.runtime_gate import enforce_scope_invocation

        decision = enforce_scope_invocation("browser_navigate", {"url": url})
        if decision is not None and not decision.allowed:
            from vxis.interaction.hands import ScopeBlockedError  # reuse the shared exception

            raise ScopeBlockedError(f"browser navigation to {url} blocked by scope gate: {decision.reason}")
        return await self._page.navigate(url)

    # ── X-Ray Flow Recording ────────────────────────────────────

    def _record_flow(self, resp: AnalyzedResponse, request_body: str = "") -> None:
        """모든 HTTP 인터랙션을 X-Ray FlowAnalyzer에 기록."""
        flow = self._analyzer.create_flow_from_request(
            method=resp.response.request.method,
            url=str(resp.response.request.url),
            headers=dict(resp.response.request.headers),
            body=request_body,
        )
        self._analyzer.update_flow_response(
            flow,
            status_code=resp.status,
            headers=dict(resp.headers),
            body=resp.text[:10000] if resp.text else "",
        )
        self._analyzer.add_flow(flow)

    # ── Execution Strategies ─────────────────────────────────────

    async def _execute_http(
        self,
        action: InteractionAction,
        mode: InteractionMode,
    ) -> InteractionResult:
        """기본 HTTP 요청 실행.

        phase-B.6: dispatched through `self._surface.hands.request(...)` so
        kind-aware routing (web/desktop/mobile/game) flows through the same
        keystone. The WEB surface shares our SessionManager — no double
        request, cookies/CSRF stay coherent. The underlying AnalyzedResponse
        is exposed via `WebHands.last_response` so the existing rich
        InteractionResult (forms/links/error_patterns) keeps building.
        """
        if self._surface is None or not self._session:
            return InteractionResult(success=False, error="No session")

        try:
            envelope = await self._surface.hands.request(
                action.method or "GET",
                path=action.url or "/",
                data=action.data,
                json_data=action.json_data,
                headers=action.headers,
            )
        except NotImplementedError as exc:
            # Unsupported surface implementations raise here. Surface the gap as
            # an informational finding instead of crashing the Brain loop.
            kind = self._surface.target.kind.value
            return InteractionResult(
                success=False,
                mode_used=mode,
                error=str(exc),
                findings=[
                    InteractionFinding(
                        severity="informational",
                        title=(f"surface_unsupported|||서피스 미지원 ({kind})"),
                        description=str(exc),
                        surface=kind,
                    )
                ],
            )

        resp = getattr(self._surface.hands, "last_response", None)
        if resp is None:
            # surface.hands.request failed (envelope.success == False) —
            # surface non-web variants don't expose AnalyzedResponse
            return InteractionResult(
                success=envelope.success,
                mode_used=mode,
                error=envelope.error,
            )

        # X-Ray에 플로우 기록
        self._record_flow(resp, str(action.data or action.json_data or ""))

        result = InteractionResult(
            success=not resp.is_error,
            mode_used=mode,
            status_code=resp.status,
            response_body=resp.text[:5000],
            response_headers=dict(resp.headers),
            forms_found=[
                {"action": f.action, "method": f.method, "fields": f.fields, "has_csrf": f.has_csrf}
                for f in resp.forms
            ],
            links_found=resp.links[:100],
            vulnerabilities=[{"type": p, "url": str(resp.url)} for p in resp.error_patterns],
        )

        # Eyes 보강 (SPA 앱일 때)
        if mode in (InteractionMode.EYES_ONLY, InteractionMode.EYES_XRAY) and self._page:
            try:
                snapshot = await self._navigate_checked(f"{self._target}{action.url}")
                dom = await self._page.analyze_dom()
                result.dom_analysis = dom
                result.page_title = snapshot.title
                result.js_errors = snapshot.js_errors
                if dom.api_endpoints:
                    result.links_found.extend(dom.api_endpoints)
            except ScopeBlockedError as exc:
                logger.warning("Eyes navigation blocked by scope gate: %s", exc)
            except Exception as exc:
                logger.warning("Eyes analysis failed: %s", exc)

        return result

    async def _execute_login(
        self,
        action: InteractionAction,
        mode: InteractionMode,
    ) -> InteractionResult:
        """로그인 실행."""
        session = self._session
        if not session:
            return InteractionResult(success=False, error="No session")

        resp = await session.login(
            url=action.url or "/login",
            data=action.data,
            json_data=action.json_data,
        )

        # 로그인 트래픽을 X-Ray에 기록 (인증 토큰 분석용)
        self._record_flow(resp, str(action.data or ""))

        return InteractionResult(
            success=session.auth_state == AuthState.AUTHENTICATED,
            mode_used=mode,
            status_code=resp.status,
            response_body=resp.text[:3000],
            forms_found=[
                {"action": f.action, "method": f.method, "fields": f.fields} for f in resp.forms
            ],
        )

    async def _execute_chain(
        self,
        action: InteractionAction,
        mode: InteractionMode,
    ) -> InteractionResult:
        """멀티스텝 익스플로잇 체인 실행."""
        session = self._session
        if not session or not action.chain_steps:
            return InteractionResult(success=False, error="No session or chain steps")

        chain = session.chain()
        for step in action.chain_steps:
            method = step.get("method", "GET").upper()
            path = step.get("url", step.get("path", "/"))
            if method == "GET":
                chain.get(path, extract=step.get("extract"))
            elif method == "POST":
                chain.post(
                    path,
                    data=step.get("data"),
                    json_data=step.get("json"),
                    extract=step.get("extract"),
                )
            elif method == "PUT":
                chain.put(path, extract=step.get("extract"))
            elif method == "DELETE":
                chain.delete(path, extract=step.get("extract"))

        chain_result = await chain.execute()

        return InteractionResult(
            success=chain_result.success,
            mode_used=mode,
            chain_results=[
                {"status": r.status, "url": r.url, "body_length": r.body_length}
                for r in chain_result.steps
            ],
            extracted_values=chain_result.extracted,
            status_code=chain_result.steps[-1].status if chain_result.steps else 0,
        )

    async def _execute_js_analysis(
        self,
        action: InteractionAction,
        mode: InteractionMode,
    ) -> InteractionResult:
        """JavaScript / DOM 분석."""
        if not self._page:
            # Eyes 없으면 Hands로 HTML만 분석
            session = self._session
            if not session:
                return InteractionResult(success=False, error="No session")
            resp = await session.get(action.url)
            return InteractionResult(
                success=True,
                mode_used=InteractionMode.HANDS_ONLY,
                status_code=resp.status,
                response_body=resp.text[:5000],
                forms_found=[
                    {"action": f.action, "method": f.method, "fields": f.fields} for f in resp.forms
                ],
            )

        snapshot = await self._navigate_checked(f"{self._target}{action.url}")
        dom = await self._page.analyze_dom()

        return InteractionResult(
            success=True,
            mode_used=mode,
            page_title=snapshot.title,
            dom_analysis=dom,
            js_errors=snapshot.js_errors,
            links_found=snapshot.links[:100],
            forms_found=snapshot.forms[:20],
        )

    async def _execute_screenshot(
        self,
        action: InteractionAction,
        mode: InteractionMode,
    ) -> InteractionResult:
        """스크린샷 캡처."""
        if not self._page:
            return InteractionResult(success=False, error="Eyes not available", mode_used=mode)

        await self._navigate_checked(f"{self._target}{action.url}")
        path = f"/tmp/vxis_screenshot_{action.url.replace('/', '_')}.png"
        await self._page.screenshot(path=path)

        return InteractionResult(
            success=True,
            mode_used=mode,
            screenshot_path=path,
        )

    async def _execute_crawl(
        self,
        action: InteractionAction,
        mode: InteractionMode,
    ) -> InteractionResult:
        """딥 크롤링."""
        session = self._session
        if not session:
            return InteractionResult(success=False, error="No session")

        endpoints = await session.crawl_links(action.url or "/", depth=2)

        return InteractionResult(
            success=True,
            mode_used=mode,
            links_found=sorted(endpoints),
        )

    # ── Target Profile ───────────────────────────────────────────

    async def _initial_probe(self) -> None:
        """초기 탐색 — 타겟 기술 스택, WAF, 보안 헤더 파악."""
        if not self._session:
            return

        try:
            await self._session.get("/")
            self._target_profile = self._session.get_fingerprint()
            logger.info(
                "Target profile: tech=%s, waf=%s, csrf=%s, endpoints=%d",
                self._target_profile.get("tech_stack", []),
                self._target_profile.get("waf_detected", False),
                self._target_profile.get("has_csrf", False),
                self._target_profile.get("endpoints_discovered", 0),
            )
        except Exception as exc:
            logger.warning("Initial probe failed: %s", exc)

    def get_target_profile(self) -> dict[str, Any]:
        """Brain에게 타겟 프로필 반환."""
        profile = dict(self._target_profile)

        # X-Ray 분석 추가
        if self._analyzer.flows:
            summary = self._analyzer.get_summary()
            profile["traffic_analysis"] = {
                "total_flows": summary.total_flows,
                "api_endpoints": sorted(summary.api_endpoints),
                "auth_tokens_found": len(summary.auth_tokens_found),
                "secrets_found": len(summary.secrets_found),
                "passive_vulns": summary.vulnerabilities,
            }

        # 사용 가능한 감각
        profile["available_senses"] = {
            "hands": True,
            "eyes": self._browser is not None,
            "xray": self._mitm is not None,
        }

        return profile

    # ── Auth State ───────────────────────────────────────────────

    @property
    def auth_state(self) -> AuthState:
        if self._session:
            return self._session.auth_state
        return AuthState.ANONYMOUS

    @property
    def is_authenticated(self) -> bool:
        return self.auth_state == AuthState.AUTHENTICATED
