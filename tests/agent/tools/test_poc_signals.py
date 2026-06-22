"""Fix 3 — PoC/evidence marker sets must be single-sourced.

Both finding_tools and verifier_tools used to define near-identical marker
tuples/sets independently, and they diverged (verifier_tools was missing
'observed_delta', 'Location:', 'sql error'; finding_tools was missing
HTTP status strings and several control markers).

After Fix 3, both modules must import from _poc_signals.py, which holds
the canonical union of all markers.
"""

from __future__ import annotations


def test_poc_signals_module_exists() -> None:
    """_poc_signals module must be importable from vxis.agent.tools."""
    from vxis.agent.tools import _poc_signals

    assert hasattr(_poc_signals, "POC_RESULT_MARKERS")
    assert hasattr(_poc_signals, "CONTROL_MARKERS")


def test_canonical_result_markers_includes_observed_delta() -> None:
    """The canonical result-marker set must include 'observed_delta'
    (was missing from verifier_tools._RESULT_MARKERS before the fix)."""
    from vxis.agent.tools._poc_signals import POC_RESULT_MARKERS

    lower = [m.lower() for m in POC_RESULT_MARKERS]
    assert "observed_delta" in lower, (
        "POC_RESULT_MARKERS must include 'observed_delta' — it was present in "
        "finding_tools but missing from verifier_tools before the fix"
    )


def test_canonical_result_markers_includes_http_status_strings() -> None:
    """The canonical result-marker set must include the HTTP status strings
    that were in verifier_tools._RESULT_MARKERS."""
    from vxis.agent.tools._poc_signals import POC_RESULT_MARKERS

    assert "200 OK" in POC_RESULT_MARKERS
    assert "500 Internal Server Error" in POC_RESULT_MARKERS


def test_canonical_control_markers_includes_observed_delta() -> None:
    """The canonical control-marker set must include 'observed_delta'
    (was missing from verifier_tools._CONTROL_MARKERS before the fix)."""
    from vxis.agent.tools._poc_signals import CONTROL_MARKERS

    lower = [m.lower() for m in CONTROL_MARKERS]
    assert "observed_delta" in lower, (
        "CONTROL_MARKERS must include 'observed_delta' — present in finding_tools "
        "but missing from verifier_tools._CONTROL_MARKERS before the fix"
    )


def test_canonical_control_markers_includes_verifier_extras() -> None:
    """Union must include markers that were unique to verifier_tools."""
    from vxis.agent.tools._poc_signals import CONTROL_MARKERS

    for marker in ("token:null", 'token=""', "id=1", "id=2"):
        assert marker in CONTROL_MARKERS, (
            f"CONTROL_MARKERS must include {marker!r} (was in verifier_tools only)"
        )


def test_finding_tools_imports_from_poc_signals() -> None:
    """finding_tools must consume the canonical sets, not its own copies."""
    import vxis.agent.tools.finding_tools as ft
    from vxis.agent.tools._poc_signals import POC_RESULT_MARKERS, CONTROL_MARKERS

    assert ft._POC_RESULT_MARKERS is POC_RESULT_MARKERS, (
        "finding_tools._POC_RESULT_MARKERS must be the same object as "
        "_poc_signals.POC_RESULT_MARKERS (imported, not redefined)"
    )
    assert ft._CONTROL_MARKERS is CONTROL_MARKERS, (
        "finding_tools._CONTROL_MARKERS must be the same object as "
        "_poc_signals.CONTROL_MARKERS (imported, not redefined)"
    )


def test_verifier_tools_imports_from_poc_signals() -> None:
    """verifier_tools must consume the canonical sets, not its own copies."""
    import vxis.agent.tools.verifier_tools as vt
    from vxis.agent.tools._poc_signals import POC_RESULT_MARKERS, CONTROL_MARKERS

    assert vt._RESULT_MARKERS is POC_RESULT_MARKERS, (
        "verifier_tools._RESULT_MARKERS must be the same object as "
        "_poc_signals.POC_RESULT_MARKERS (imported, not redefined)"
    )
    assert vt._CONTROL_MARKERS is CONTROL_MARKERS, (
        "verifier_tools._CONTROL_MARKERS must be the same object as "
        "_poc_signals.CONTROL_MARKERS (imported, not redefined)"
    )


def test_finding_type_needs_control_single_sourced() -> None:
    """Both modules must use the same _finding_type_needs_control function."""
    import vxis.agent.tools.finding_tools as ft
    import vxis.agent.tools.verifier_tools as vt
    from vxis.agent.tools._poc_signals import finding_type_needs_control

    assert ft._finding_type_needs_control is finding_type_needs_control, (
        "finding_tools._finding_type_needs_control must be imported from _poc_signals"
    )
    assert vt._finding_type_needs_control is finding_type_needs_control, (
        "verifier_tools._finding_type_needs_control must be imported from _poc_signals"
    )


def test_finding_type_needs_control_union_semantics() -> None:
    """The canonical helper must cover the union of both original sets:
    - finding_tools added: business_logic
    - verifier_tools added: sql, xss, ssrf
    """
    from vxis.agent.tools._poc_signals import finding_type_needs_control

    # From verifier_tools only
    assert finding_type_needs_control("sql_injection") is True
    assert finding_type_needs_control("xss_reflected") is True
    assert finding_type_needs_control("ssrf") is True
    # From finding_tools only
    assert finding_type_needs_control("business_logic") is True
    # Present in both
    assert finding_type_needs_control("auth_bypass") is True
    assert finding_type_needs_control("idor") is True
    # Should NOT need control
    assert finding_type_needs_control("misconfiguration") is False
    assert finding_type_needs_control("information_disclosure") is False
