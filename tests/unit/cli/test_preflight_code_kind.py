"""preflight reachability must treat a CODE target as a path, not a URL.

Regression: with kind='code', check_target_reachable fell through to the web
branch and ran an HTTP HEAD against the filesystem path, always failing — the
confusing error a user hit when feeding a repo path into Agent Mode. A code
target is "reachable" iff the path exists (same contract as desktop).
"""

from __future__ import annotations

from vxis.cli.preflight import check_target_reachable


def test_code_target_existing_path_is_reachable(tmp_path):
    ok, _latency = check_target_reachable(str(tmp_path), kind="code")
    assert ok is True


def test_code_target_missing_path_is_unreachable():
    ok, _latency = check_target_reachable("/no/such/path/xyz123", kind="code")
    assert ok is False
