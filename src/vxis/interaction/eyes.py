"""VXIS CPR — Eyes: Playwright + CDP 브라우저 엔진.

Brain이 타겟 웹 앱을 "보는" 눈.
JavaScript 실행, DOM 분석, SPA 앱 대응, 스크린샷 등.

핵심 기능:
    1. 브라우저 라이프사이클 — Docker 안에서 Chromium 관리
    2. 페이지 탐색 — URL 이동, 클릭, 폼 입력, JS 실행
    3. DOM 분석 — 요소 추출, 가시성 확인, 접근성 트리
    4. 네트워크 감시 — 브라우저가 보내는 모든 요청/응답 캡처
    5. 스크린샷 — 시각적 분석용 페이지 캡처
    6. 쿠키/스토리지 — localStorage, sessionStorage, 쿠키 접근

Architecture:
    BrowserEngine (Playwright 래퍼)
        ├── BrowserContext (격리된 브라우저 세션)
        │       ├── Page (단일 탭)
        │       ├── NetworkLog (요청/응답 기록)
        │       └── ConsoleLog (JS 콘솔 출력)
        └── DockerBrowserManager (컨테이너 안에서 Chromium 실행)

Requirements:
    pip install playwright
    playwright install chromium

    Docker mode:
        이미지에 Playwright + Chromium 사전 설치 필요
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Playwright는 선택적 의존성 — 없으면 graceful degradation
try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext as PWContext,
        Page as PWPage,
        Playwright,
        Request as PWRequest,
        Response as PWResponse,
    )

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.debug("Playwright not installed — Eyes module disabled")


# ── Data Types ───────────────────────────────────────────────────


@dataclass
class NetworkEntry:
    """브라우저가 보낸/받은 네트워크 요청."""

    url: str
    method: str
    status: int = 0
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    resource_type: str = ""  # document, script, xhr, fetch, image, etc.
    post_data: str = ""
    response_body: str = ""  # 캡처된 경우만
    timing_ms: float = 0.0


@dataclass
class PageSnapshot:
    """페이지 상태 스냅샷."""

    url: str
    title: str
    html: str = ""
    text_content: str = ""  # 렌더링된 텍스트만
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    inputs: list[dict[str, str]] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    local_storage: dict[str, str] = field(default_factory=dict)
    console_messages: list[str] = field(default_factory=list)
    network_log: list[NetworkEntry] = field(default_factory=list)
    screenshot_path: str = ""  # 스크린샷 저장 경로
    js_errors: list[str] = field(default_factory=list)


@dataclass
class ElementInfo:
    """DOM 요소 정보."""

    tag: str
    text: str = ""
    attributes: dict[str, str] = field(default_factory=dict)
    is_visible: bool = True
    bounding_box: dict[str, float] | None = None


@dataclass
class DOMAnalysis:
    """DOM 분석 결과 — Brain이 이해하기 쉬운 형태로 요약."""

    forms: list[dict[str, Any]]          # 폼 목록 (action, method, fields)
    login_forms: list[dict[str, Any]]    # 로그인으로 추정되는 폼
    file_uploads: list[dict[str, Any]]   # 파일 업로드 폼
    api_endpoints: list[str]             # JS/XHR에서 발견된 API 엔드포인트
    hidden_inputs: list[dict[str, str]]  # hidden input 필드
    comments: list[str]                  # HTML 주석
    inline_scripts: list[str]            # <script> 태그 내용
    meta_info: dict[str, str]            # <meta> 태그 정보


# ── Browser Engine ───────────────────────────────────────────────


def is_available() -> bool:
    """Playwright + Chromium 사용 가능 여부."""
    return PLAYWRIGHT_AVAILABLE


class BrowserEngine:
    """Playwright 기반 브라우저 엔진.

    Usage:
        async with BrowserEngine() as engine:
            page = await engine.new_page()
            snapshot = await page.navigate("https://target.com")
            forms = await page.analyze_dom()
            await page.fill_form("form#login", {"username": "admin", "password": "test"})
            await page.click("button[type=submit]")
    """

    def __init__(
        self,
        headless: bool = True,
        proxy: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError(
                "Playwright not installed. Run: pip install playwright && playwright install chromium"
            )
        self._headless = headless
        self._proxy = proxy
        self._user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        )
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._pages: list[BrowserPage] = []

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        launch_args = {
            "headless": self._headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
            ],
        }
        if self._proxy:
            launch_args["proxy"] = {"server": self._proxy}

        self._browser = await self._playwright.chromium.launch(**launch_args)
        logger.info("Browser started (headless=%s, proxy=%s)", self._headless, self._proxy)

    async def stop(self) -> None:
        for page in self._pages:
            await page.close()
        self._pages.clear()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("Browser stopped")

    async def __aenter__(self) -> BrowserEngine:
        await self.start()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.stop()

    async def new_page(self, isolated: bool = True) -> BrowserPage:
        """새 페이지(탭) 생성.

        isolated=True: 별도 컨텍스트 (쿠키 격리)
        isolated=False: 기본 컨텍스트 공유 (쿠키 공유)
        """
        if not self._browser:
            raise RuntimeError("Browser not started")

        if isolated:
            ctx = await self._browser.new_context(
                user_agent=self._user_agent,
                ignore_https_errors=True,
                java_script_enabled=True,
            )
        else:
            ctx = self._browser.contexts[0] if self._browser.contexts else (
                await self._browser.new_context(
                    user_agent=self._user_agent,
                    ignore_https_errors=True,
                )
            )

        pw_page = await ctx.new_page()
        page = BrowserPage(pw_page, ctx)
        self._pages.append(page)
        return page

    @property
    def page_count(self) -> int:
        return len(self._pages)


# ── Browser Page (단일 탭) ───────────────────────────────────────


class BrowserPage:
    """단일 브라우저 탭 — Brain이 제어하는 실제 인터페이스."""

    def __init__(self, page: PWPage, context: PWContext) -> None:
        self._page = page
        self._context = context
        self._network_log: list[NetworkEntry] = []
        self._console_log: list[str] = []
        self._js_errors: list[str] = []

        # 이벤트 핸들러 등록
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        self._page.on("console", self._on_console)
        self._page.on("pageerror", self._on_page_error)

    async def close(self) -> None:
        await self._page.close()
        await self._context.close()

    # ── Navigation ─────────────────────────────────────────────

    async def navigate(
        self,
        url: str,
        wait_until: str = "domcontentloaded",
        timeout: float = 30000,
    ) -> PageSnapshot:
        """페이지 이동 + 상태 스냅샷 반환."""
        self._network_log.clear()
        self._console_log.clear()
        self._js_errors.clear()

        await self._page.goto(url, wait_until=wait_until, timeout=timeout)
        # SPA 앱 대비 — JS 실행 대기
        await self._page.wait_for_load_state("networkidle", timeout=10000)

        return await self.snapshot()

    async def snapshot(self) -> PageSnapshot:
        """현재 페이지 상태 스냅샷."""
        title = await self._page.title()
        url = self._page.url

        # HTML + 텍스트
        html_content = await self._page.content()
        text_content = await self._page.inner_text("body") if await self._page.query_selector("body") else ""

        # 폼 추출
        forms = await self._extract_forms()

        # 링크 추출
        links = await self._page.eval_on_selector_all(
            "a[href]",
            "elements => elements.map(e => e.href).filter(h => h && !h.startswith('javascript:'))",
        )

        # Input 필드
        inputs = await self._page.eval_on_selector_all(
            "input, textarea, select",
            """elements => elements.map(e => ({
                tag: e.tagName.toLowerCase(),
                name: e.name || '',
                type: e.type || '',
                id: e.id || '',
                value: e.value || '',
                placeholder: e.placeholder || '',
            }))""",
        )

        # 쿠키
        cookies = await self._context.cookies()

        # localStorage
        local_storage = await self._page.evaluate(
            "() => Object.fromEntries(Object.entries(localStorage))"
        )

        return PageSnapshot(
            url=url,
            title=title,
            html=html_content,
            text_content=text_content[:10000],
            forms=forms,
            links=links,
            inputs=inputs,
            cookies=cookies,
            local_storage=local_storage,
            console_messages=list(self._console_log),
            network_log=list(self._network_log),
            js_errors=list(self._js_errors),
        )

    # ── DOM Interaction ────────────────────────────────────────

    async def click(self, selector: str, timeout: float = 5000) -> None:
        """요소 클릭."""
        await self._page.click(selector, timeout=timeout)
        await self._page.wait_for_load_state("networkidle", timeout=5000)

    async def fill(self, selector: str, value: str) -> None:
        """입력 필드에 값 입력."""
        await self._page.fill(selector, value)

    async def fill_form(self, form_selector: str, data: dict[str, str]) -> None:
        """폼 필드를 일괄 입력."""
        for field_name, value in data.items():
            selectors = [
                f"{form_selector} [name='{field_name}']",
                f"{form_selector} #{field_name}",
                f"{form_selector} input[placeholder*='{field_name}' i]",
            ]
            filled = False
            for sel in selectors:
                try:
                    el = await self._page.query_selector(sel)
                    if el:
                        await el.fill(value)
                        filled = True
                        break
                except Exception:
                    continue
            if not filled:
                logger.warning("Could not fill field: %s", field_name)

    async def select(self, selector: str, value: str) -> None:
        """드롭다운 선택."""
        await self._page.select_option(selector, value=value)

    async def type_text(self, selector: str, text: str, delay: float = 50) -> None:
        """키보드 타이핑 (keystroke 이벤트 발생)."""
        await self._page.type(selector, text, delay=delay)

    async def press(self, key: str) -> None:
        """키 누르기 (Enter, Tab, Escape 등)."""
        await self._page.keyboard.press(key)

    # ── JavaScript Execution ───────────────────────────────────

    async def evaluate(self, expression: str) -> Any:
        """JavaScript 실행."""
        return await self._page.evaluate(expression)

    async def inject_script(self, script: str) -> Any:
        """페이지에 스크립트 주입."""
        return await self._page.evaluate(script)

    # ── DOM Analysis ───────────────────────────────────────────

    async def analyze_dom(self) -> DOMAnalysis:
        """DOM 심층 분석 — Brain에게 유용한 정보 추출."""
        analysis = await self._page.evaluate("""() => {
            const result = {
                forms: [],
                login_forms: [],
                file_uploads: [],
                api_endpoints: [],
                hidden_inputs: [],
                comments: [],
                inline_scripts: [],
                meta_info: {},
            };

            // 폼 분석
            document.querySelectorAll('form').forEach(form => {
                const fields = {};
                form.querySelectorAll('input, textarea, select').forEach(el => {
                    if (el.name) fields[el.name] = {type: el.type || 'text', value: el.value || ''};
                });
                const formData = {
                    action: form.action || '',
                    method: (form.method || 'GET').toUpperCase(),
                    id: form.id || '',
                    fields: fields,
                };
                result.forms.push(formData);

                // 로그인 폼 탐지
                const html = form.innerHTML.toLowerCase();
                if (html.includes('password') || html.includes('login') || html.includes('sign')) {
                    result.login_forms.push(formData);
                }

                // 파일 업로드 탐지
                if (form.querySelector('input[type=file]')) {
                    result.file_uploads.push(formData);
                }
            });

            // Hidden input 수집
            document.querySelectorAll('input[type=hidden]').forEach(el => {
                result.hidden_inputs.push({name: el.name, value: el.value});
            });

            // 인라인 스크립트에서 API 엔드포인트 추출
            document.querySelectorAll('script:not([src])').forEach(script => {
                const text = script.textContent || '';
                if (text.length < 50000) {
                    result.inline_scripts.push(text.substring(0, 2000));
                    // API 패턴 추출
                    const apiPattern = /['"](\\/api\\/[^'"\\s]+)['"]/g;
                    let match;
                    while ((match = apiPattern.exec(text)) !== null) {
                        result.api_endpoints.push(match[1]);
                    }
                    // fetch/axios URL 추출
                    const fetchPattern = /(?:fetch|axios|\\$\\.(?:get|post|ajax))\\s*\\(\\s*['"]([^'"]+)['"]/g;
                    while ((match = fetchPattern.exec(text)) !== null) {
                        result.api_endpoints.push(match[1]);
                    }
                }
            });

            // HTML 주석 추출
            const walker = document.createTreeWalker(
                document, NodeFilter.SHOW_COMMENT, null
            );
            while (walker.nextNode()) {
                const text = walker.currentNode.textContent.trim();
                if (text.length > 3 && text.length < 1000) {
                    result.comments.push(text);
                }
            }

            // Meta 태그
            document.querySelectorAll('meta').forEach(meta => {
                const name = meta.getAttribute('name') || meta.getAttribute('property') || '';
                const content = meta.getAttribute('content') || '';
                if (name && content) result.meta_info[name] = content;
            });

            // API 엔드포인트 중복 제거
            result.api_endpoints = [...new Set(result.api_endpoints)];

            return result;
        }""")

        return DOMAnalysis(**analysis)

    async def find_elements(self, selector: str) -> list[ElementInfo]:
        """CSS 선택자로 요소 검색."""
        elements = await self._page.eval_on_selector_all(
            selector,
            """elements => elements.map(e => ({
                tag: e.tagName.toLowerCase(),
                text: (e.textContent || '').substring(0, 200).trim(),
                attributes: Object.fromEntries(
                    Array.from(e.attributes).map(a => [a.name, a.value])
                ),
                is_visible: e.offsetParent !== null,
            }))""",
        )
        return [ElementInfo(**el) for el in elements]

    # ── Screenshots ────────────────────────────────────────────

    async def screenshot(self, path: str | None = None, full_page: bool = True) -> bytes:
        """페이지 스크린샷."""
        kwargs: dict[str, Any] = {"full_page": full_page}
        if path:
            kwargs["path"] = path
        return await self._page.screenshot(**kwargs)

    # ── Network / Cookie Access ────────────────────────────────

    @property
    def network_log(self) -> list[NetworkEntry]:
        return list(self._network_log)

    async def get_cookies(self) -> list[dict[str, Any]]:
        return await self._context.cookies()

    async def set_cookie(self, name: str, value: str, domain: str, path: str = "/") -> None:
        await self._context.add_cookies([{
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
        }])

    async def clear_cookies(self) -> None:
        await self._context.clear_cookies()

    async def get_local_storage(self) -> dict[str, str]:
        return await self._page.evaluate(
            "() => Object.fromEntries(Object.entries(localStorage))"
        )

    async def get_session_storage(self) -> dict[str, str]:
        return await self._page.evaluate(
            "() => Object.fromEntries(Object.entries(sessionStorage))"
        )

    # ── Waiting ────────────────────────────────────────────────

    async def wait_for_selector(self, selector: str, timeout: float = 5000) -> None:
        await self._page.wait_for_selector(selector, timeout=timeout)

    async def wait_for_navigation(self, timeout: float = 10000) -> None:
        await self._page.wait_for_load_state("networkidle", timeout=timeout)

    # ── Internal Event Handlers ────────────────────────────────

    def _on_request(self, request: PWRequest) -> None:
        entry = NetworkEntry(
            url=request.url,
            method=request.method,
            request_headers=dict(request.headers),
            resource_type=request.resource_type,
            post_data=request.post_data or "",
        )
        self._network_log.append(entry)

    async def _on_response(self, response: PWResponse) -> None:
        # 해당 요청의 NetworkEntry 찾아서 업데이트
        url = response.url
        for entry in reversed(self._network_log):
            if entry.url == url and entry.status == 0:
                entry.status = response.status
                entry.response_headers = dict(response.headers)
                break

    def _on_console(self, msg: Any) -> None:
        self._console_log.append(f"[{msg.type}] {msg.text}")

    def _on_page_error(self, error: Any) -> None:
        self._js_errors.append(str(error))

    # ── Form Extraction ────────────────────────────────────────

    async def _extract_forms(self) -> list[dict[str, Any]]:
        return await self._page.eval_on_selector_all(
            "form",
            """forms => forms.map(form => {
                const fields = {};
                form.querySelectorAll('input, textarea, select').forEach(el => {
                    const name = el.name || el.id || '';
                    if (name) {
                        fields[name] = {
                            type: el.type || el.tagName.toLowerCase(),
                            value: el.value || '',
                            required: el.required || false,
                        };
                    }
                });
                return {
                    action: form.action || '',
                    method: (form.method || 'GET').toUpperCase(),
                    id: form.id || '',
                    fields: fields,
                };
            })""",
        )


# ── Docker Browser Manager ───────────────────────────────────────


class DockerBrowserManager:
    """Docker 컨테이너 안에서 Playwright + Chromium을 실행.

    VXIS sandbox와 통합 — 별도 컨테이너에서 브라우저를 격리 실행하고
    CDP (Chrome DevTools Protocol)로 연결.

    Usage:
        mgr = DockerBrowserManager()
        cdp_url = await mgr.start()  # Docker 안에서 Chromium 시작
        # cdp_url로 외부에서 Playwright 연결 가능
        await mgr.stop()
    """

    _IMAGE = "mcr.microsoft.com/playwright:v1.49.0-jammy"
    _CONTAINER_NAME = "vxis-browser"

    def __init__(self) -> None:
        self._container_id: str | None = None
        self._cdp_port: int = 9222

    @staticmethod
    def is_available() -> bool:
        if not shutil.which("docker"):
            return False
        try:
            proc = subprocess.run(
                ["docker", "info"],
                capture_output=True, timeout=10,
            )
            return proc.returncode == 0
        except Exception:
            return False

    async def start(self) -> str:
        """Docker 안에서 Chromium 시작, CDP endpoint URL 반환."""
        cmd = [
            "docker", "run", "-d",
            "--name", self._CONTAINER_NAME,
            "-p", f"{self._cdp_port}:9222",
            "--shm-size=2g",
            "--cap-add=SYS_ADMIN",
            self._IMAGE,
            "chromium",
            "--headless",
            "--disable-gpu",
            "--remote-debugging-address=0.0.0.0",
            f"--remote-debugging-port=9222",
            "--no-sandbox",
            "--disable-dev-shm-usage",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(f"Failed to start browser container: {stderr.decode()}")

        self._container_id = stdout.decode().strip()[:12]
        cdp_url = f"http://localhost:{self._cdp_port}"

        # 브라우저 시작 대기
        await asyncio.sleep(2)
        logger.info("Docker browser started: %s (CDP: %s)", self._container_id, cdp_url)

        return cdp_url

    async def stop(self) -> None:
        if self._container_id:
            proc = await asyncio.create_subprocess_exec(
                "docker", "rm", "-f", self._CONTAINER_NAME,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
            logger.info("Docker browser stopped: %s", self._container_id)
            self._container_id = None

    async def connect(self) -> BrowserEngine:
        """CDP를 통해 Docker 안의 브라우저에 연결하는 BrowserEngine 생성.

        Note: 이 메서드는 Playwright의 connect_over_cdp 사용.
        현재 BrowserEngine은 launch 기반이므로, CDP 연결용 별도 팩토리 제공.
        """
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright not installed")

        pw = await async_playwright().start()
        browser = await pw.chromium.connect_over_cdp(f"http://localhost:{self._cdp_port}")

        engine = BrowserEngine.__new__(BrowserEngine)
        engine._headless = True
        engine._proxy = None
        engine._user_agent = None
        engine._playwright = pw
        engine._browser = browser
        engine._pages = []

        return engine
