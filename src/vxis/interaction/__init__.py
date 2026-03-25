"""VXIS Cognitive Pentesting Runtime (CPR) — Interaction Layer.

Phase 4 Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │            Interaction Controller                        │
    │  Brain이 상황에 따라 최적의 "감각"을 동적 선택            │
    │                                                         │
    │  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐  │
    │  │ 👁 Eyes  │  │ 🤚 Hands │  │  🔬 X-Ray             │  │
    │  │Playwright│  │  httpx   │  │  mitmproxy             │  │
    │  │  + CDP   │  │ +session │  │  (intercept)           │  │
    │  └──────────┘  └──────────┘  └───────────────────────┘  │
    └─────────────────────────────────────────────────────────┘

Modules:
    hands   — HTTP 세션 매니저 (쿠키/JWT/CSRF 자동 관리)
    eyes    — Playwright + CDP 브라우저 엔진
    xray    — mitmproxy 트래픽 인터셉트 엔진
    controller — 통합 컨트롤러 (Brain 연동)
"""

from vxis.interaction.hands import SessionManager, AuthState
from vxis.interaction.controller import InteractionController, InteractionMode

__all__ = [
    "SessionManager",
    "AuthState",
    "InteractionController",
    "InteractionMode",
]
