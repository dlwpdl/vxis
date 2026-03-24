"""VXIS Agent Evidence Collector — Playwright 기반 PoC 증거 수집.

취약점 발견 시 자동으로:
1. 취약 페이지 스크린샷 캡처
2. HTTP 요청/응답 기록
3. 콘솔 에러 수집

Playwright가 설치되지 않은 환경에서는 urllib 기반 헤더 체크만 수행하며,
절대 ImportError로 인해 크래시하지 않는다.
"""

from __future__ import annotations

import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 보안 헤더 정책 테이블
# ---------------------------------------------------------------------------

_SECURITY_HEADERS: list[dict[str, Any]] = [
    {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Clickjacking 공격 방어. 누락 시 페이지가 iframe에 삽입 가능.",
        "recommendation": "X-Frame-Options: DENY 또는 SAMEORIGIN 설정",
    },
    {
        "name": "Content-Security-Policy",
        "severity": "high",
        "description": "XSS 및 데이터 인젝션 공격 방어를 위한 리소스 로딩 정책.",
        "recommendation": "적절한 CSP 지시어 설정 (default-src 'self' 등)",
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "description": "MIME 스니핑 방어. 누락 시 브라우저가 Content-Type을 무시할 수 있음.",
        "recommendation": "X-Content-Type-Options: nosniff 설정",
    },
    {
        "name": "Strict-Transport-Security",
        "severity": "high",
        "description": "HTTPS 강제 적용 (HSTS). HTTP 다운그레이드 공격 방어.",
        "recommendation": "Strict-Transport-Security: max-age=31536000; includeSubDomains 설정",
    },
    {
        "name": "X-XSS-Protection",
        "severity": "low",
        "description": "구형 브라우저의 반사형 XSS 필터 활성화.",
        "recommendation": "X-XSS-Protection: 1; mode=block 설정",
    },
    {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Referer 헤더 노출 범위 제어. 민감 URL 유출 방지.",
        "recommendation": "Referrer-Policy: strict-origin-when-cross-origin 설정",
    },
]

# ---------------------------------------------------------------------------
# EvidenceBundle 데이터클래스
# ---------------------------------------------------------------------------


@dataclass
class EvidenceBundle:
    """취약점 증거 묶음 — 스크린샷, HTTP 정보, 콘솔 에러를 하나로 통합.

    Playwright 없이 urllib만으로 수집된 경우 screenshot_path는 빈 문자열이며
    console_errors는 비어 있다.
    """

    url: str
    """캡처 대상 URL."""

    status_code: int
    """HTTP 응답 상태 코드. 요청 실패 시 0."""

    headers: dict[str, str]
    """HTTP 응답 헤더 (모두 소문자 키로 정규화)."""

    screenshot_path: str = ""
    """저장된 스크린샷 파일의 절대 경로. Playwright 미설치 시 빈 문자열."""

    console_errors: list[str] = field(default_factory=list)
    """브라우저 콘솔에서 수집한 오류 메시지 목록."""

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    """ISO-8601 형식의 캡처 시각 (UTC)."""

    missing_security_headers: list[str] = field(default_factory=list)
    """응답에서 누락된 보안 헤더 이름 목록."""


# ---------------------------------------------------------------------------
# 공개 함수 — check_security_headers (Playwright 불필요)
# ---------------------------------------------------------------------------


def check_security_headers(url: str) -> list[dict[str, Any]]:
    """보안 헤더 누락 여부를 urllib만으로 점검하고 findings 목록을 반환한다.

    Playwright 없이 표준 라이브러리만 사용하므로 어떤 환경에서도 동작한다.

    Args:
        url: 점검할 대상 URL (http:// 또는 https://).

    Returns:
        누락된 보안 헤더 각각에 대한 finding dict 목록.
        각 항목 구조::

            {
                "header":          str,   # 누락된 헤더 이름
                "severity":        str,   # "low" | "medium" | "high"
                "description":     str,   # 취약점 설명
                "recommendation":  str,   # 수정 권고
                "url":             str,   # 점검한 URL
            }
    """
    findings: list[dict[str, Any]] = []

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "VXIS-SecurityScanner/1.0"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310
            response_headers = {
                k.lower(): v for k, v in response.headers.items()
            }
    except urllib.error.URLError as exc:
        logger.warning("check_security_headers: URL 접근 실패 (%s): %s", url, exc)
        return findings
    except Exception as exc:  # noqa: BLE001
        logger.warning("check_security_headers: 예상치 못한 오류 (%s): %s", url, exc)
        return findings

    for policy in _SECURITY_HEADERS:
        header_lower = policy["name"].lower()
        if header_lower not in response_headers:
            findings.append(
                {
                    "header": policy["name"],
                    "severity": policy["severity"],
                    "description": policy["description"],
                    "recommendation": policy["recommendation"],
                    "url": url,
                }
            )
            logger.debug("누락된 보안 헤더: %s (%s)", policy["name"], url)

    return findings


# ---------------------------------------------------------------------------
# EvidenceCollector 클래스
# ---------------------------------------------------------------------------


class EvidenceCollector:
    """Playwright 기반 PoC 증거 수집기.

    Playwright가 설치되어 있으면 스크린샷·콘솔 에러를 포함한 완전한 증거를
    수집하고, 미설치 시에는 urllib을 통한 헤더 점검만 수행한다.

    사용 예::

        collector = EvidenceCollector(output_dir="~/.vxis/evidence")
        if collector.is_available():
            bundle = await collector.capture_with_payload(
                url="https://example.com/search?q=test",
                payload="<script>alert(1)</script>",
            )
        else:
            findings = check_security_headers("https://example.com")
    """

    def __init__(self, output_dir: str = "~/.vxis/evidence") -> None:
        self._output_dir = Path(output_dir).expanduser().resolve()
        self._playwright_available: bool | None = None  # lazy-checked

    # ------------------------------------------------------------------
    # 공개 프로퍼티 / 유틸
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Playwright 패키지 및 브라우저 바이너리 사용 가능 여부를 반환한다.

        결과는 첫 호출 이후 캐시된다(프로세스 내에서 재설치되지 않는다는 가정).
        """
        if self._playwright_available is None:
            self._playwright_available = self._check_playwright()
        return self._playwright_available

    # ------------------------------------------------------------------
    # 스크린샷 캡처
    # ------------------------------------------------------------------

    async def capture_screenshot(
        self,
        url: str,
        filename: str | None = None,
    ) -> str:
        """URL 페이지의 전체 화면 스크린샷을 캡처하여 파일 경로를 반환한다.

        Args:
            url: 캡처할 대상 URL.
            filename: 저장할 파일 이름. None이면 타임스탬프 기반으로 자동 생성.

        Returns:
            저장된 스크린샷의 절대 파일 경로.
            Playwright 미설치 시 빈 문자열을 반환한다.
        """
        if not self.is_available():
            logger.warning(
                "capture_screenshot: Playwright 미설치 — 스크린샷 건너뜀 (%s)", url
            )
            return ""

        dest = self._resolve_screenshot_path(url, filename)
        self._ensure_output_dir()

        try:
            return await self._playwright_screenshot(url, dest)
        except Exception as exc:  # noqa: BLE001
            logger.error("capture_screenshot 실패 (%s): %s", url, exc)
            return ""

    # ------------------------------------------------------------------
    # 종합 증거 수집
    # ------------------------------------------------------------------

    async def capture_with_payload(
        self,
        url: str,
        payload: str | None = None,
    ) -> EvidenceBundle:
        """URL에 접속(필요 시 페이로드 주입)하여 EvidenceBundle을 반환한다.

        수집 항목:
        - HTTP 응답 상태 코드 및 헤더
        - 누락된 보안 헤더 분석
        - 전체 화면 스크린샷 (Playwright 필요)
        - 브라우저 콘솔 에러 (Playwright 필요)

        Args:
            url: 캡처할 대상 URL.
            payload: 검색 폼 또는 입력 필드에 주입할 문자열.
                     None이면 페이로드 주입 없이 페이지만 로드한다.

        Returns:
            수집된 증거를 담은 EvidenceBundle.
        """
        self._ensure_output_dir()

        # 1단계: urllib으로 헤더 수집 (Playwright 불필요)
        raw_headers, status_code = self._fetch_headers_urllib(url)
        missing = self._compute_missing_headers(raw_headers)

        bundle = EvidenceBundle(
            url=url,
            status_code=status_code,
            headers=raw_headers,
            missing_security_headers=missing,
        )

        # 2단계: Playwright로 스크린샷·콘솔 에러 수집
        if self.is_available():
            try:
                screenshot_path, console_errors = (
                    await self._playwright_full_capture(url, payload)
                )
                bundle.screenshot_path = screenshot_path
                bundle.console_errors = console_errors
            except Exception as exc:  # noqa: BLE001
                logger.error("Playwright 캡처 실패 (%s): %s", url, exc)
        else:
            logger.info(
                "capture_with_payload: Playwright 미설치 — 헤더 전용 모드로 동작"
            )

        return bundle

    # ------------------------------------------------------------------
    # 헤더 전용 조회
    # ------------------------------------------------------------------

    async def check_headers(self, url: str) -> dict[str, str]:
        """URL의 HTTP 응답 헤더를 소문자 키로 정규화하여 반환한다.

        urllib만 사용하므로 Playwright 없이도 동작한다.

        Args:
            url: 헤더를 조회할 대상 URL.

        Returns:
            ``{"content-type": "text/html", ...}`` 형태의 헤더 딕셔너리.
            요청 실패 시 빈 딕셔너리를 반환한다.
        """
        headers, _ = self._fetch_headers_urllib(url)
        return headers

    # ------------------------------------------------------------------
    # 내부 헬퍼 — urllib
    # ------------------------------------------------------------------

    def _fetch_headers_urllib(self, url: str) -> tuple[dict[str, str], int]:
        """urllib로 HEAD/GET 요청을 보내 응답 헤더와 상태 코드를 반환한다.

        HEAD 요청을 먼저 시도하고 실패 시 GET으로 폴백한다.

        Returns:
            (소문자 정규화 헤더 딕셔너리, 상태 코드) 튜플.
            요청 자체가 실패하면 ({}, 0) 반환.
        """
        for method in ("HEAD", "GET"):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "VXIS-SecurityScanner/1.0"},
                    method=method,
                )
                with urllib.request.urlopen(req, timeout=10) as response:  # noqa: S310
                    headers = {
                        k.lower(): v for k, v in response.headers.items()
                    }
                    return headers, response.status
            except urllib.error.HTTPError as exc:
                # 4xx/5xx 도 응답 헤더를 포함하므로 수집 후 반환
                headers = {k.lower(): v for k, v in exc.headers.items()}
                return headers, exc.code
            except urllib.error.URLError as exc:
                logger.debug(
                    "_fetch_headers_urllib %s 실패 (%s): %s", method, url, exc
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug(
                    "_fetch_headers_urllib 예상 외 오류 (%s): %s", url, exc
                )

        return {}, 0

    @staticmethod
    def _compute_missing_headers(headers: dict[str, str]) -> list[str]:
        """응답 헤더에서 누락된 보안 헤더 이름 목록을 반환한다."""
        return [
            policy["name"]
            for policy in _SECURITY_HEADERS
            if policy["name"].lower() not in headers
        ]

    # ------------------------------------------------------------------
    # 내부 헬퍼 — Playwright 가용성 확인
    # ------------------------------------------------------------------

    @staticmethod
    def _check_playwright() -> bool:
        """playwright 패키지 import 가능 여부를 조용히 확인한다."""
        try:
            import importlib

            spec = importlib.util.find_spec("playwright")
            if spec is None:
                logger.debug("Playwright 패키지를 찾을 수 없음")
                return False
            logger.debug("Playwright 패키지 확인됨")
            return True
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # 내부 헬퍼 — Playwright 실제 캡처
    # ------------------------------------------------------------------

    async def _playwright_screenshot(self, url: str, dest: Path) -> str:
        """Playwright를 사용해 단순 스크린샷만 캡처한다.

        Returns:
            저장된 파일의 절대 경로 문자열. 실패 시 빈 문자열.
        """
        try:
            from playwright.async_api import async_playwright  # type: ignore[import]
        except ImportError:
            logger.warning("playwright 패키지를 import할 수 없음")
            return ""

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.goto(url, wait_until="networkidle", timeout=30_000)
                await page.screenshot(path=str(dest), full_page=True)
                logger.info("스크린샷 저장: %s", dest)
                return str(dest)
            finally:
                await browser.close()

    async def _playwright_full_capture(
        self,
        url: str,
        payload: str | None,
    ) -> tuple[str, list[str]]:
        """Playwright로 페이지 접속, 페이로드 주입(선택), 스크린샷·콘솔 에러를 수집한다.

        페이로드 주입 전략:
        1. 페이지 내 텍스트 입력 필드(input[type=text], input:not([type]),
           textarea, [contenteditable])를 탐색한다.
        2. 발견된 첫 번째 필드에 페이로드를 입력하고 Enter를 눌러 제출한다.
        3. 입력 필드가 없으면 URL 파라미터에 페이로드가 이미 포함된 것으로 간주한다.

        Returns:
            (screenshot_path, console_errors) 튜플.
        """
        try:
            from playwright.async_api import async_playwright  # type: ignore[import]
        except ImportError:
            logger.warning("playwright 패키지를 import할 수 없음")
            return "", []

        console_errors: list[str] = []
        dest = self._resolve_screenshot_path(url, filename=None)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    user_agent="VXIS-SecurityScanner/1.0"
                )
                page = await context.new_page()

                # 콘솔 에러 리스너 등록
                page.on(
                    "console",
                    lambda msg: console_errors.append(msg.text)
                    if msg.type == "error"
                    else None,
                )

                await page.goto(url, wait_until="networkidle", timeout=30_000)

                # 페이로드 주입
                if payload:
                    await self._inject_payload(page, payload)

                await page.screenshot(path=str(dest), full_page=True)
                logger.info(
                    "전체 캡처 완료 — 스크린샷: %s, 콘솔 에러: %d건",
                    dest,
                    len(console_errors),
                )
                return str(dest), console_errors
            finally:
                await browser.close()

    @staticmethod
    async def _inject_payload(page: Any, payload: str) -> None:
        """페이지 내 첫 번째 입력 필드에 페이로드를 주입한다.

        입력 가능한 선택자를 순서대로 시도하여 발견되면 fill + Enter 전송.
        없으면 조용히 건너뛴다.
        """
        # type: ignore annotations — Playwright Page 타입을 직접 import하지 않음
        input_selectors = [
            'input[type="text"]',
            'input[type="search"]',
            "input:not([type])",
            "textarea",
            "[contenteditable='true']",
        ]

        for selector in input_selectors:
            try:
                element = page.locator(selector).first
                count = await page.locator(selector).count()
                if count == 0:
                    continue
                await element.fill(payload)
                await element.press("Enter")
                logger.debug("페이로드 주입 완료 (selector: %s)", selector)
                # 제출 후 페이지 로딩 대기
                try:
                    await page.wait_for_load_state("networkidle", timeout=5_000)
                except Exception:  # noqa: BLE001
                    pass
                return
            except Exception as exc:  # noqa: BLE001
                logger.debug("페이로드 주입 시도 실패 (selector: %s): %s", selector, exc)

        logger.debug("입력 필드를 찾을 수 없어 페이로드 주입 건너뜀")

    # ------------------------------------------------------------------
    # 내부 헬퍼 — 파일 시스템
    # ------------------------------------------------------------------

    def _ensure_output_dir(self) -> None:
        """출력 디렉터리가 없으면 생성한다."""
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_screenshot_path(self, url: str, filename: str | None) -> Path:
        """스크린샷 저장 경로를 결정한다.

        filename이 None이면 URL과 타임스탬프를 조합하여 유일한 파일명을 생성한다.
        """
        if filename:
            # 사용자 제공 파일명에 확장자가 없으면 .png 추가
            name = filename if filename.endswith(".png") else f"{filename}.png"
        else:
            # URL에서 도메인·경로 부분을 추출하여 파일명으로 사용
            safe_url = (
                url.replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
                .replace("?", "_")
                .replace("&", "_")
                .replace("=", "_")
                .replace(":", "_")
            )
            # 파일 시스템 제한을 고려해 길이 제한
            safe_url = safe_url[:80]
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            name = f"{safe_url}__{ts}.png"

        return self._output_dir / name
