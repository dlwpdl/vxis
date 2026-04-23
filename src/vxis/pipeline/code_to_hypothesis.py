"""Code → Hypothesis adapter (P3 queue feed).

Converts a CodeRecon ReconReport into a list of unverified Hypothesis
objects. These hypotheses are fed into the P3 Hypothesis queue where
a dynamic surface (web/desktop) must confirm or refute them before
any finding is reported or any score credit is awarded.

INVARIANTS (enforced by callers, not by this module):
  - report_finding MUST NOT be called from this module.
  - Hypothesis.status is always "unverified" when this module produces it.
  - _compute_vxis_score MUST NOT include a CODE branch.

Tech → vulnerability pattern mapping strategy:
  The mapping is intentionally simple and human-readable. Each tech
  keyword maps to one or more vulnerability hypothesis templates.
  Hypotheses carry a confidence_hint (0.0–1.0) that signals rough
  prior probability, helping the P3 Brain prioritise which dynamic
  checks to schedule first.
"""
from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, Field

from vxis.interaction.surface import ReconReport, TargetKind


# ---------------------------------------------------------------------------
# Hypothesis model (Pydantic, separate from graph.hypothesis.Hypothesis)
# ---------------------------------------------------------------------------

class CodeHypothesis(BaseModel):
    """Unverified code-surface hypothesis awaiting dynamic confirmation.

    This model is Pydantic-based (not a dataclass) so it can be
    JSON-serialised, validated at runtime, and stored in the P3 queue.

    Fields:
        id                — unique ID (UUIDv4 as string)
        description_en    — English description of the attack hypothesis
        description_ko    — Korean description (same detail level)
        target_endpoint   — optional URL/path relevant to the hypothesis
        vector_id_candidate — optional VXIS vector ID hint for the dynamic skill
        status            — always "unverified" when emitted from this module
        source            — always TargetKind.CODE
        confidence_hint   — 0.0–1.0 prior probability estimate (not a score)
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    description_en: str
    description_ko: str
    target_endpoint: str | None = None
    vector_id_candidate: str | None = None
    status: Literal["unverified", "confirmed", "refuted"] = "unverified"
    source: TargetKind = TargetKind.CODE
    confidence_hint: float = Field(default=0.5, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Tech keyword → hypothesis template mapping
# ---------------------------------------------------------------------------

_TEMPLATE = dict[str, str | float | None]

# Each entry: (description_en, description_ko, vector_id_candidate, confidence_hint)
_TECH_HYPOTHESIS_MAP: dict[str, list[_TEMPLATE]] = {
    # Python + raw SQL
    "clojure+korma": [
        {
            "description_en": (
                "korma 0.x detected — library uses raw SQL construction; "
                "dynamic check for SQL injection on all exposed endpoints required"
            ),
            "description_ko": (
                "korma 0.x 감지 — 해당 라이브러리는 원시 SQL 조합을 사용함; "
                "노출된 모든 엔드포인트에 대해 SQL 인젝션 동적 검증 필요"
            ),
            "vector_id_candidate": "sqli",
            "confidence_hint": 0.65,
        }
    ],
    # LiteLLM — prompt injection + cost amplification
    "python+litellm": [
        {
            "description_en": (
                "litellm detected — check for prompt injection and cost-amplification "
                "attacks on LLM-proxied endpoints"
            ),
            "description_ko": (
                "litellm 감지 — LLM 프록시 엔드포인트에서 프롬프트 인젝션 및 "
                "비용 증폭 공격 동적 검증 필요"
            ),
            "vector_id_candidate": "prompt_injection",
            "confidence_hint": 0.70,
        }
    ],
    # python-jose + pyjwt — algorithm confusion
    "python+python-jose": [
        {
            "description_en": (
                "python-jose detected — check for JWT algorithm confusion "
                "(RS256→HS256 none-alg) on authentication endpoints"
            ),
            "description_ko": (
                "python-jose 감지 — 인증 엔드포인트에서 JWT 알고리즘 혼동 공격 "
                "(RS256→HS256, none 알고리즘) 동적 검증 필요"
            ),
            "vector_id_candidate": "jwt_alg_confusion",
            "confidence_hint": 0.75,
        }
    ],
    "python+pyjwt": [
        {
            "description_en": (
                "pyjwt detected — check for JWT algorithm confusion and "
                "weak-secret brute-force on authentication endpoints"
            ),
            "description_ko": (
                "pyjwt 감지 — 인증 엔드포인트에서 JWT 알고리즘 혼동 및 "
                "약한 시크릿 브루트포스 동적 검증 필요"
            ),
            "vector_id_candidate": "jwt_alg_confusion",
            "confidence_hint": 0.70,
        }
    ],
    # SQLAlchemy ORM misuse
    "python+sqlalchemy": [
        {
            "description_en": (
                "SQLAlchemy detected — dynamic check for raw text() queries "
                "and ORM filter injection on all data endpoints"
            ),
            "description_ko": (
                "SQLAlchemy 감지 — 모든 데이터 엔드포인트에서 raw text() 쿼리 및 "
                "ORM 필터 인젝션 동적 검증 필요"
            ),
            "vector_id_candidate": "sqli",
            "confidence_hint": 0.55,
        }
    ],
    # FastAPI — path-param IDOR, docs exposure
    "python+fastapi": [
        {
            "description_en": (
                "FastAPI detected — check for IDOR on path-parameter endpoints "
                "and unauthenticated /docs /redoc /openapi.json exposure"
            ),
            "description_ko": (
                "FastAPI 감지 — 경로 파라미터 엔드포인트 IDOR 및 "
                "/docs /redoc /openapi.json 미인증 노출 동적 검증 필요"
            ),
            "vector_id_candidate": "idor",
            "confidence_hint": 0.60,
        }
    ],
    # Django
    "python+django": [
        {
            "description_en": (
                "Django detected — check for Django admin exposure, "
                "debug mode leakage, and CSRF bypass on API endpoints"
            ),
            "description_ko": (
                "Django 감지 — Django 어드민 노출, 디버그 모드 정보 유출, "
                "API 엔드포인트 CSRF 우회 동적 검증 필요"
            ),
            "vector_id_candidate": "auth_bypass",
            "confidence_hint": 0.60,
        }
    ],
    # Node.js / Express
    "nodejs+express": [
        {
            "description_en": (
                "Express.js detected — check for prototype pollution, "
                "path traversal, and missing security headers"
            ),
            "description_ko": (
                "Express.js 감지 — 프로토타입 오염, 경로 탐색 취약점, "
                "보안 헤더 미설정 동적 검증 필요"
            ),
            "vector_id_candidate": "prototype_pollution",
            "confidence_hint": 0.55,
        }
    ],
    # Next.js
    "nodejs+nextjs": [
        {
            "description_en": (
                "Next.js detected — check for SSRF via Server Actions, "
                "exposed API routes without auth, and open redirects"
            ),
            "description_ko": (
                "Next.js 감지 — Server Actions를 통한 SSRF, "
                "인증 없는 API 라우트 노출, 오픈 리다이렉트 동적 검증 필요"
            ),
            "vector_id_candidate": "ssrf",
            "confidence_hint": 0.60,
        }
    ],
    # Java Spring
    "java+spring": [
        {
            "description_en": (
                "Spring Framework detected — check for Spring Actuator "
                "unauthenticated exposure and SpEL injection"
            ),
            "description_ko": (
                "Spring Framework 감지 — Spring Actuator 미인증 노출 및 "
                "SpEL 인젝션 동적 검증 필요"
            ),
            "vector_id_candidate": "rce",
            "confidence_hint": 0.65,
        }
    ],
    # Rust — generally safer but check deserialisation
    "rust": [
        {
            "description_en": (
                "Rust project detected — check for unsafe deserialization "
                "via serde and memory corruption in FFI boundary"
            ),
            "description_ko": (
                "Rust 프로젝트 감지 — serde를 통한 역직렬화 취약점 및 "
                "FFI 경계에서의 메모리 손상 동적 검증 필요"
            ),
            "vector_id_candidate": "deserialization",
            "confidence_hint": 0.35,
        }
    ],
    # Go
    "go": [
        {
            "description_en": (
                "Go project detected — check for SSRF via http.Get with "
                "user-controlled URLs and open redirect vulnerabilities"
            ),
            "description_ko": (
                "Go 프로젝트 감지 — 사용자 제어 URL을 통한 SSRF 및 "
                "오픈 리다이렉트 취약점 동적 검증 필요"
            ),
            "vector_id_candidate": "ssrf",
            "confidence_hint": 0.45,
        }
    ],
}

# OpenAPI endpoint hypothesis template (populated per-endpoint)
_OPENAPI_ENDPOINT_TEMPLATES: list[_TEMPLATE] = [
    {
        "description_en": (
            "OpenAPI endpoint {endpoint} — dynamic IDOR/auth/SSRF check required"
        ),
        "description_ko": (
            "OpenAPI 엔드포인트 {endpoint} — IDOR/인증/SSRF 동적 검증 필요"
        ),
        "vector_id_candidate": "idor",
        "confidence_hint": 0.50,
    }
]

# Secret template hypothesis (one per .env.example file)
_SECRET_LEAK_TEMPLATE: _TEMPLATE = {
    "description_en": (
        "Secret template {value} found — dynamic git-history secret-leak check required "
        "for keys: {keys}"
    ),
    "description_ko": (
        "시크릿 템플릿 {value} 발견 — 키 ({keys})에 대한 "
        "git 히스토리 시크릿 유출 동적 검증 필요"
    ),
    "vector_id_candidate": "secret_in_git",
    "confidence_hint": 0.80,
}


# ---------------------------------------------------------------------------
# Public adapter function
# ---------------------------------------------------------------------------

def code_recon_to_hypotheses(report: ReconReport) -> list[CodeHypothesis]:
    """Convert a CODE-surface ReconReport into unverified CodeHypothesis objects.

    Rules:
      - Each manifest component triggers tech-based vulnerability hypotheses.
      - Each openapi component triggers per-endpoint IDOR/auth/SSRF hypotheses.
      - Each secret_template component triggers a git-history secret-leak hypothesis.
      - Dockerfile / compose components do NOT produce hypotheses here — the
        dynamic SSRF/container-escape skills handle those independently.
      - All produced hypotheses have status="unverified".
      - Duplicate descriptions are deduplicated (same description_en → skip).

    Args:
        report: ReconReport with surface_kind=CODE produced by CodeRecon.

    Returns:
        list[CodeHypothesis] — may be empty if no recognisable tech is detected.
    """
    hypotheses: list[CodeHypothesis] = []
    seen_descriptions: set[str] = set()

    def _add(desc_en: str, desc_ko: str, endpoint: str | None, vector: str | None, hint: float) -> None:
        if desc_en in seen_descriptions:
            return
        seen_descriptions.add(desc_en)
        hypotheses.append(
            CodeHypothesis(
                description_en=desc_en,
                description_ko=desc_ko,
                target_endpoint=endpoint,
                vector_id_candidate=vector,
                status="unverified",
                source=TargetKind.CODE,
                confidence_hint=hint,
            )
        )

    for component in report.components:
        c_type = component.get("type", "")
        c_value = component.get("value", "")

        # -----------------------------------------------------------------
        # Manifest: tech-based vulnerability hypotheses
        # -----------------------------------------------------------------
        if c_type == "manifest":
            tech = component.get("tech", "")
            for keyword, templates in _TECH_HYPOTHESIS_MAP.items():
                # Match exact tech label or substring (e.g. "python+fastapi" → "fastapi")
                if keyword == tech or keyword in tech or tech.startswith(keyword):
                    for tmpl in templates:
                        _add(
                            desc_en=str(tmpl["description_en"]),
                            desc_ko=str(tmpl["description_ko"]),
                            endpoint=None,
                            vector=str(tmpl["vector_id_candidate"]) if tmpl.get("vector_id_candidate") else None,
                            hint=float(tmpl["confidence_hint"]),  # type: ignore[arg-type]
                        )

        # -----------------------------------------------------------------
        # OpenAPI: per-endpoint dynamic check hypotheses
        # -----------------------------------------------------------------
        elif c_type == "openapi":
            endpoints_raw = component.get("endpoints", "")
            endpoints = [e.strip() for e in endpoints_raw.split(",") if e.strip()]
            for endpoint in endpoints:
                for tmpl in _OPENAPI_ENDPOINT_TEMPLATES:
                    desc_en = str(tmpl["description_en"]).format(endpoint=endpoint)
                    desc_ko = str(tmpl["description_ko"]).format(endpoint=endpoint)
                    _add(
                        desc_en=desc_en,
                        desc_ko=desc_ko,
                        endpoint=endpoint,
                        vector=str(tmpl["vector_id_candidate"]) if tmpl.get("vector_id_candidate") else None,
                        hint=float(tmpl["confidence_hint"]),  # type: ignore[arg-type]
                    )

        # -----------------------------------------------------------------
        # Secret template: git-history secret-leak hypothesis
        # -----------------------------------------------------------------
        elif c_type == "secret_template":
            keys = component.get("keys", "")
            tmpl = _SECRET_LEAK_TEMPLATE
            desc_en = str(tmpl["description_en"]).format(value=c_value, keys=keys)
            desc_ko = str(tmpl["description_ko"]).format(value=c_value, keys=keys)
            _add(
                desc_en=desc_en,
                desc_ko=desc_ko,
                endpoint=None,
                vector=str(tmpl["vector_id_candidate"]) if tmpl.get("vector_id_candidate") else None,
                hint=float(tmpl["confidence_hint"]),  # type: ignore[arg-type]
            )

        # Dockerfile and compose: no direct hypothesis — skip intentionally
        # Container-escape / SSRF skills discover these through dynamic scan.

    return hypotheses
