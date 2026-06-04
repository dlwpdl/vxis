from __future__ import annotations

from vxis.agent.coverage.matrix import (
    CoverageMatrix,
    SurfaceUnitRef,
    evaluate_finish_gate,
    high_value_surfaces,
    is_high_value_surface,
)


def test_mark_updates_cell_and_coverage_percent() -> None:
    surface = SurfaceUnitRef(
        surface_id="s-users",
        path="/api/users",
        method="GET",
        auth_role="anon",
    )
    matrix = CoverageMatrix.for_surfaces([surface], vector_classes=["sqli", "xss"])

    assert matrix.coverage_percent() == 0.0

    matrix.mark("s-users", "sqli", "tested-clean", iter=3, hypothesis_id="h-sqli")

    assert matrix.coverage_percent() == 50.0
    assert matrix.cells[("s-users", "sqli")].hypothesis_ids == ["h-sqli"]
    gaps = matrix.gaps()
    assert [(gap.surface_id, gap.vector_class) for gap in gaps] == [("s-users", "xss")]

    matrix.mark("s-users", "sqli", "found", iter=4, hypothesis_id="h-found")

    cell = matrix.cells[("s-users", "sqli")]
    assert cell.status == "found"
    assert cell.last_iter == 4
    assert cell.hypothesis_ids == ["h-sqli", "h-found"]


def test_gaps_respect_prior_threshold() -> None:
    matrix = CoverageMatrix()
    matrix.mark("s-low", "xss", "untested", iter=0, prior=0.2)
    matrix.mark("s-high", "idor", "untested", iter=0, prior=0.8)
    matrix.mark("s-clean", "sqli", "tested-clean", iter=1, prior=0.9)

    assert [(cell.surface_id, cell.vector_class) for cell in matrix.gaps()] == [("s-high", "idor")]
    assert matrix.gaps(prior_threshold=0.9) == []


def test_high_value_surface_helper_flags_paths_and_admin_role() -> None:
    admin = SurfaceUnitRef(
        surface_id="admin",
        path="/admin/users",
        method="GET",
        auth_role="user",
    )
    login = {"surface_id": "login", "path": "/login", "method": "POST", "auth_role": "anon"}
    payment = SurfaceUnitRef(
        surface_id="pay",
        path="/api/payment-methods",
        method="POST",
        auth_role="user",
    )
    admin_role = SurfaceUnitRef(
        surface_id="settings",
        path="/settings",
        method="GET",
        auth_role="admin",
    )
    public = SurfaceUnitRef(
        surface_id="public",
        path="/docs",
        method="GET",
        auth_role="anon",
    )

    assert is_high_value_surface(admin)
    assert is_high_value_surface(login)
    assert is_high_value_surface(payment)
    assert is_high_value_surface(admin_role)
    assert not is_high_value_surface(public)
    assert [surface["surface_id"] for surface in high_value_surfaces([login])] == ["login"]


def test_finish_gate_blocks_high_value_gaps_and_unresolved_hypotheses() -> None:
    surfaces = [
        SurfaceUnitRef(
            surface_id="admin",
            path="/admin",
            method="GET",
            auth_role="admin",
        ),
        SurfaceUnitRef(
            surface_id="public",
            path="/status",
            method="GET",
            auth_role="anon",
        ),
    ]
    matrix = CoverageMatrix.for_surfaces(surfaces, vector_classes=["sqli", "xss"])
    matrix.mark("admin", "sqli", "tested-clean", iter=1)
    matrix.mark("public", "sqli", "tested-clean", iter=1)
    matrix.mark("public", "xss", "tested-clean", iter=1)

    report = matrix.finish_gate_report(
        surfaces=surfaces,
        hypotheses=[{"node_id": "h-admin-idor", "prior": 0.7, "status": "testing"}],
        required_coverage_percent=70.0,
        vector_classes=["sqli", "xss"],
    )

    assert report.blocks_finish
    assert report.coverage_percent == 75.0
    assert [(cell.surface_id, cell.vector_class) for cell in report.high_value_gaps] == [
        ("admin", "xss")
    ]
    assert report.unresolved_hypothesis_ids == ["h-admin-idor"]
    assert "high-value coverage gaps remain" in report.reasons
    assert "high-prior hypotheses unresolved" in report.reasons
    assert "overall coverage below threshold" not in report.reasons


def test_finish_gate_allows_when_coverage_and_hypotheses_are_complete() -> None:
    surfaces = [
        SurfaceUnitRef(
            surface_id="admin",
            path="/admin/login",
            method="POST",
            auth_role="anon",
        )
    ]
    matrix = CoverageMatrix.for_surfaces(surfaces, vector_classes=["sqli", "xss"])
    matrix.mark("admin", "sqli", "tested-clean", iter=2)
    matrix.mark("admin", "xss", "tested-blocked", iter=3)

    report = evaluate_finish_gate(
        matrix,
        surfaces=surfaces,
        hypotheses=[
            {"node_id": "h-confirmed", "prior": 0.9, "status": "confirmed"},
            {"node_id": "h-low", "prior": 0.1, "status": "untested"},
        ],
        required_coverage_percent=70.0,
        vector_classes=["sqli", "xss"],
    )

    assert report.allowed
    assert not report.blocks_finish
    assert report.high_value_gaps == []
    assert report.unresolved_hypothesis_ids == []
    assert report.reasons == []


def test_summary_is_budgeted_and_includes_top_gaps() -> None:
    surface = SurfaceUnitRef(
        surface_id="admin",
        path="/admin",
        method="GET",
        auth_role="admin",
    )
    matrix = CoverageMatrix.for_surfaces([surface], vector_classes=["sqli", "xss"])
    matrix.mark("admin", "sqli", "found", iter=4)

    summary = matrix.to_summary(token_budget=30)

    assert "coverage: 50.0%" in summary
    assert "admin:xss" in summary
    assert len(summary) <= 120
