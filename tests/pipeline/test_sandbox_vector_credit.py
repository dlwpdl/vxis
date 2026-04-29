"""Phase 4: shell_exec / python_exec 사용도 VC 에 반영 (Sandbox Vector Credit).

문제: VXIS 의 VC (Vector Coverage, max 250pt) 는 `_skill_to_vectors` 매핑에
의존. Brain 이 `run_skill` 대신 `shell_exec(sqlmap ...)` 을 쓰면 VC 가
credit 안 됨 → Brain 이 sandbox 사용할수록 점수 떨어지는 역-인센티브.
(Phase 3 에서 sandbox 를 primary 로 만들었는데 Phase 4 에서 scoring 은
여전히 run_skill 중심이면 모순.)

해결: `_sandbox_cmd_to_vectors(cmd)` 헬퍼 — 커맨드 문자열에서 pentest
도구 키워드 (sqlmap, nuclei, ffuf, gobuster, nikto, wapiti, hydra) 를
탐지해 해당 벡터 ID 리스트 반환. `_compute_vxis_score` 가 ctx.
sandbox_invocations 를 순회해 `tracker.record_vector_attempt` 호출.

See: wiki/sources/incidents/2026_04_20_brain_prompt_prison.md
"""
from __future__ import annotations

from unittest.mock import MagicMock


# ─── Unit: keyword mapping helper ───────────────────────────────────────────


def test_sqlmap_maps_to_sqli_vector() -> None:
    """shell_exec 에서 sqlmap 실행 시 WEB-SQLI-001 vector attempted."""
    from vxis.pipeline.scan_pipeline_v2 import _sandbox_cmd_to_vectors
    vectors = _sandbox_cmd_to_vectors("sqlmap -u http://localhost:3000/api/users --batch")
    assert "WEB-SQLI-001" in vectors


def test_nuclei_maps_to_broad_coverage() -> None:
    """nuclei 는 광범위 템플릿 스캐너 → 여러 vector 에 credit."""
    from vxis.pipeline.scan_pipeline_v2 import _sandbox_cmd_to_vectors
    vectors = _sandbox_cmd_to_vectors("nuclei -u http://target -t exposures/")
    # 최소 INFO + MISC 두 개 이상 커버
    assert len(vectors) >= 2, f"nuclei should credit >=2 vectors, got: {vectors}"


def test_ffuf_maps_to_info_disclosure() -> None:
    """ffuf / gobuster — 디렉토리 브루트포스 → INFO 발견 벡터."""
    from vxis.pipeline.scan_pipeline_v2 import _sandbox_cmd_to_vectors
    assert "WEB-INFO-001" in _sandbox_cmd_to_vectors("ffuf -u http://t/FUZZ -w wordlist.txt")
    assert "WEB-INFO-001" in _sandbox_cmd_to_vectors("gobuster dir -u http://t")


def test_nikto_maps_to_misconfig() -> None:
    """nikto — 웹 서버 misconfig 탐지."""
    from vxis.pipeline.scan_pipeline_v2 import _sandbox_cmd_to_vectors
    assert "WEB-MISC-001" in _sandbox_cmd_to_vectors("nikto -h http://target")


def test_unknown_command_returns_empty() -> None:
    """매핑 없는 커맨드는 빈 리스트 — VC 부풀리기 방지."""
    from vxis.pipeline.scan_pipeline_v2 import _sandbox_cmd_to_vectors
    assert _sandbox_cmd_to_vectors("echo hello") == []
    assert _sandbox_cmd_to_vectors("ls /workspace") == []
    assert _sandbox_cmd_to_vectors("") == []


def test_sqlmap_fingerprint_case_insensitive_and_partial() -> None:
    """실전 Brain 커맨드는 다양한 변형 — 대소문자·경로 차이 내성."""
    from vxis.pipeline.scan_pipeline_v2 import _sandbox_cmd_to_vectors
    # 절대 경로, 따옴표, 대소문자 등 실제 변형
    assert "WEB-SQLI-001" in _sandbox_cmd_to_vectors("/usr/bin/sqlmap --url=http://t")


def test_jwt_python_code_maps_to_jwt_vector() -> None:
    """python_exec 에서 jwt 라이브러리 사용 → JWT 벡터 credit."""
    from vxis.pipeline.scan_pipeline_v2 import _sandbox_cmd_to_vectors
    code = "import jwt\ntoken = jwt.encode({'alg': 'none'}, '', algorithm='none')"
    assert "WEB-JWT-001" in _sandbox_cmd_to_vectors(code)


# ─── Integration: _compute_vxis_score reads sandbox_invocations ────────────


def _make_mock_ctx(sandbox_invocations: list[dict] | None = None) -> MagicMock:
    ctx = MagicMock()
    ctx.findings = []
    ctx.skills_completed = []
    ctx.confirmed_findings = []
    ctx.refuted_findings = []
    ctx.attack_chains = []
    ctx.scan_id = "test-phase-4"
    ctx.sandbox_invocations = sandbox_invocations or []
    ctx.attempt_outcomes = []
    # ScoringEngine 이 읽을 수 있도록 score_detail 을 MagicMock 으로
    ctx.score_detail = None
    # Phase Q5: _compute_vxis_score reads ctx.kind.value (was hardcoded "web"
    # before). MagicMock returns a MagicMock for unset attrs, which fails
    # ScoringEngine's str-validation. Set explicitly.
    ctx.kind.value = "web"
    return ctx


def test_sandbox_usage_increases_vector_coverage() -> None:
    """동일 findings=0 상태에서 sandbox 사용 있는 ctx 가 VC 점수 더 높아야.

    Brain-First + Phase 3 sandbox primacy 와 일치: Brain 이 shell_exec 를
    쓰면 VC 가 오르는 인센티브 구조.
    """
    from vxis.pipeline.scan_pipeline_v2 import _compute_vxis_score

    # 샌드박스 미사용 vs sqlmap+nuclei 사용
    ctx_none = _make_mock_ctx([])
    ctx_sandbox = _make_mock_ctx([
        {"tool": "shell_exec", "cmd": "sqlmap -u http://t/api --batch"},
        {"tool": "shell_exec", "cmd": "nuclei -u http://t -t exposures/"},
        {"tool": "shell_exec", "cmd": "ffuf -u http://t/FUZZ -w w.txt"},
    ])

    score_none, _ = _compute_vxis_score(ctx_none)
    score_sandbox, _ = _compute_vxis_score(ctx_sandbox)

    assert score_sandbox > score_none, (
        f"sandbox usage did not improve VC: "
        f"no-sandbox={score_none}, with-sandbox={score_sandbox}. "
        f"Brain is penalized for using primary tools."
    )


def test_attempt_outcomes_increase_vector_coverage() -> None:
    """First-class vector attempts must count even without sandbox text parsing."""
    from vxis.pipeline.scan_pipeline_v2 import _compute_vxis_score

    ctx_none = _make_mock_ctx([])
    ctx_attempt = _make_mock_ctx([])
    ctx_attempt.attempt_outcomes = [
        {
            "candidate_id": "web:sqli",
            "vector_id": "WEB-SQLI-001",
            "status": "attempted",
            "tool": "http_request",
        }
    ]

    score_none, _ = _compute_vxis_score(ctx_none)
    score_attempt, _ = _compute_vxis_score(ctx_attempt)

    assert score_attempt > score_none
    assert "WEB-SQLI-001" in ctx_attempt.score_detail.vector_coverage.details["vectors_attempted_ids"]


def test_missing_sandbox_invocations_field_does_not_crash() -> None:
    """Legacy ctx (sandbox_invocations 필드 없음) 이어도 크래시 금지.

    `_compute_vxis_score` 는 getattr 폴백으로 방어.
    """
    from vxis.pipeline.scan_pipeline_v2 import _compute_vxis_score

    ctx = MagicMock(spec=["findings", "skills_completed", "confirmed_findings",
                          "refuted_findings", "attack_chains", "scan_id"])
    ctx.findings = []
    ctx.skills_completed = []
    ctx.confirmed_findings = []
    ctx.refuted_findings = []
    ctx.attack_chains = []
    ctx.scan_id = "legacy"

    # 크래시 없이 점수 반환 (fallback OK)
    score, grade = _compute_vxis_score(ctx)
    assert isinstance(score, float)
    assert grade in ("A", "B", "C", "D", "F")


def test_incomplete_scan_loop_penalizes_completeness() -> None:
    """A max-iter timeout must not score as a completed scan loop."""
    from vxis.pipeline.scan_pipeline_v2 import _compute_vxis_score

    ctx = _make_mock_ctx([])
    ctx.scan_loop_completed = False

    _compute_vxis_score(ctx)

    assert ctx.score_detail.completeness.score == 0.0
    assert ctx.score_detail.completeness.details["failed"] == 1
