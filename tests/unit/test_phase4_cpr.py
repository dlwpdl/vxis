"""Phase 4 CPR (Cognitive Pentesting Runtime) 단위 테스트."""

from __future__ import annotations

import pytest


class TestHandsImport:
    """Hands 모듈 import 및 기본 동작 검증."""

    def test_import_session_manager(self):
        from vxis.interaction.hands import SessionManager
        mgr = SessionManager()
        assert mgr.active_sessions == {}

    def test_import_auth_state(self):
        from vxis.interaction.hands import AuthState
        assert AuthState.ANONYMOUS.value == "anonymous"
        assert AuthState.AUTHENTICATED.value == "authenticated"
        assert AuthState.EXPIRED.value == "expired"
        assert AuthState.BLOCKED.value == "blocked"

    def test_csrf_tracker(self):
        from vxis.interaction.hands import CSRFTracker, FormData
        tracker = CSRFTracker()
        assert not tracker.has_token

        form = FormData(
            action="/login",
            method="POST",
            fields={"csrf_token": "abc123", "username": "", "password": ""},
            has_csrf=True,
            csrf_field="csrf_token",
            csrf_value="abc123",
        )
        tracker.update_from_form(form)
        assert tracker.has_token

        data = tracker.inject_into_data({"username": "admin"})
        assert data["csrf_token"] == "abc123"
        assert data["username"] == "admin"

    def test_form_parser(self):
        from vxis.interaction.hands import _FormParser
        parser = _FormParser()
        parser.feed("""
        <html>
        <form action="/login" method="POST">
            <input type="hidden" name="csrf_token" value="tok123">
            <input type="text" name="username">
            <input type="password" name="password">
            <button type="submit">Login</button>
        </form>
        <a href="/about">About</a>
        <a href="/contact">Contact</a>
        </html>
        """)
        assert len(parser.forms) == 1
        form = parser.forms[0]
        assert form.action == "/login"
        assert form.method == "POST"
        assert form.has_csrf is True
        assert form.csrf_field == "csrf_token"
        assert form.csrf_value == "tok123"
        assert "username" in form.fields
        assert "password" in form.fields
        assert len(parser.links) == 2

    def test_waf_detection(self):
        from vxis.interaction.hands import _detect_waf
        import httpx
        headers = httpx.Headers({"server": "cloudflare", "content-type": "text/html"})
        is_waf, name = _detect_waf(headers, "")
        assert is_waf is True
        assert name == "Cloudflare"

        headers = httpx.Headers({"server": "nginx", "content-type": "text/html"})
        is_waf, name = _detect_waf(headers, "")
        assert is_waf is False

    def test_chain_interpolation(self):
        from vxis.interaction.hands import RequestChain
        result = RequestChain._interpolate(
            "/api/users/{{user_id}}/profile",
            {"user_id": "12345"},
        )
        assert result == "/api/users/12345/profile"


class TestXRayImport:
    """X-Ray 모듈 import 및 기본 동작 검증."""

    def test_import_flow_analyzer(self):
        from vxis.interaction.xray import FlowAnalyzer
        analyzer = FlowAnalyzer()
        assert analyzer.flows == []

    def test_flow_analysis_auth_detection(self):
        from vxis.interaction.xray import FlowAnalyzer, CapturedFlow
        analyzer = FlowAnalyzer()

        flow = CapturedFlow(
            id="test-001",
            timestamp=0,
            method="GET",
            url="https://api.example.com/users",
            request_headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.test.sig"},
        )
        analyzer.add_flow(flow)

        assert flow.has_auth_token is True
        assert flow.auth_type == "bearer"

    def test_flow_analysis_secret_detection(self):
        from vxis.interaction.xray import FlowAnalyzer, CapturedFlow
        analyzer = FlowAnalyzer()

        flow = CapturedFlow(
            id="test-002",
            timestamp=0,
            method="POST",
            url="https://example.com/config",
            request_body='{"password": "supersecret123", "api_key": "sk-1234567890abcdef1234567890abcdef"}',
            request_headers={"content-type": "application/json"},
        )
        analyzer.add_flow(flow)

        assert len(flow.detected_secrets) > 0

    def test_flow_analysis_vuln_detection(self):
        from vxis.interaction.xray import FlowAnalyzer, CapturedFlow
        analyzer = FlowAnalyzer()

        flow = CapturedFlow(
            id="test-003",
            timestamp=0,
            method="GET",
            url="https://example.com/search?q=test",
            response_body="MySQL error: You have an error in your SQL syntax",
            response_headers={"content-type": "text/html"},
        )
        analyzer.update_flow_response(
            flow, 500,
            {"content-type": "text/html"},
            "MySQL error: You have an error in your SQL syntax",
        )
        analyzer.add_flow(flow)

        assert "SQL Error Disclosure" in flow.vulnerabilities

    def test_traffic_summary(self):
        from vxis.interaction.xray import FlowAnalyzer, CapturedFlow
        analyzer = FlowAnalyzer()

        for i in range(3):
            flow = CapturedFlow(
                id=f"test-{i:03d}",
                timestamp=float(i),
                method="GET",
                url=f"https://api.example.com/endpoint{i}",
                request_headers={"content-type": "application/json"},
                status_code=200,
            )
            flow.is_api_call = True
            analyzer.add_flow(flow)

        summary = analyzer.get_summary()
        assert summary.total_flows == 3
        assert "api.example.com" in summary.unique_hosts

    def test_intercept_rules(self):
        from vxis.interaction.xray import FlowAnalyzer, FlowDirection, InterceptRule
        analyzer = FlowAnalyzer()

        rule = InterceptRule(
            name="inject-header",
            direction=FlowDirection.REQUEST,
            url_pattern=r"example\.com",
            modify_headers={"X-Custom": "injected"},
        )
        analyzer.add_rule(rule)

        headers = {"User-Agent": "test"}
        headers, body = analyzer.apply_request_rules(
            "https://example.com/api", headers, "",
        )
        assert headers["X-Custom"] == "injected"


class TestControllerImport:
    """Controller 모듈 import 검증."""

    def test_import_controller(self):
        from vxis.interaction.controller import InteractionController, InteractionMode
        assert InteractionMode.HANDS_ONLY.value == "hands"
        assert InteractionMode.EYES_XRAY.value == "eyes+xray"
        assert InteractionMode.FULL.value == "full"

    def test_import_action_types(self):
        from vxis.interaction.controller import InteractionAction, InteractionIntent
        action = InteractionAction(
            intent=InteractionIntent.LOGIN,
            url="/login",
            data={"username": "admin", "password": "admin"},
        )
        assert action.resolved_intent == InteractionIntent.LOGIN
        assert action.url == "/login"

    def test_mode_selection(self):
        from vxis.interaction.controller import _select_mode, InteractionIntent, InteractionMode
        # 기본: EXPLORE → HANDS_ONLY
        mode = _select_mode(
            InteractionIntent.EXPLORE,
            {"tech_stack": []},
            eyes_available=False,
            xray_available=False,
        )
        assert mode == InteractionMode.HANDS_ONLY

        # SPA + Eyes 가능 → Eyes로 업그레이드
        mode = _select_mode(
            InteractionIntent.EXPLORE,
            {"tech_stack": ["React"]},
            eyes_available=True,
            xray_available=False,
        )
        assert mode == InteractionMode.EYES_ONLY

        # JS 분석 필요하지만 Eyes 없음 → Hands 폴백
        mode = _select_mode(
            InteractionIntent.JS_ANALYSIS,
            {"tech_stack": []},
            eyes_available=False,
            xray_available=False,
        )
        assert mode == InteractionMode.HANDS_ONLY

    def test_result_to_observation(self):
        from vxis.interaction.controller import InteractionResult, InteractionMode
        result = InteractionResult(
            success=True,
            mode_used=InteractionMode.HANDS_ONLY,
            status_code=200,
            forms_found=[{"action": "/login", "method": "POST"}],
            links_found=["/about", "/contact"],
            vulnerabilities=[{"type": "SQL Error", "url": "/search"}],
        )
        obs = result.to_observation()
        assert obs["status_code"] == 200
        assert obs["forms"] == [{"action": "/login", "method": "POST"}]
        assert obs["passive_vulns"] == [{"type": "SQL Error", "url": "/search"}]


class TestEyesImport:
    """Eyes 모듈 import 검증 (Playwright 없어도 크래시 안 남)."""

    def test_import_without_playwright(self):
        from vxis.interaction.eyes import is_available
        # Playwright 없으면 False, 있으면 True — 둘 다 OK
        result = is_available()
        assert isinstance(result, bool)


class TestPackageInit:
    """패키지 __init__ import 검증."""

    def test_import_all(self):
        from vxis.interaction import (
            SessionManager,
            AuthState,
            TargetSession,
            FlowAnalyzer,
            TrafficSummary,
            InteractionController,
            InteractionMode,
            InteractionAction,
            InteractionIntent,
            InteractionResult,
        )
        assert SessionManager is not None
        assert InteractionController is not None
