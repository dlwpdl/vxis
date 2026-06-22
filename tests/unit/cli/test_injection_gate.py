"""Tests for the CLI injection auto-approve gate helper.

Fix 1: The original predicate relied on implicit operator precedence
(``and`` before ``or``) which was accidentally correct.  A future
``or`` clause could silently auto-approve injection against PROD.
These tests lock down the exact semantics via the extracted helper.
"""

from __future__ import annotations

from vxis.cli.main import _is_local_benchmark


class TestIsLocalBenchmark:
    """Matrix: host × port × scheme."""

    # ── localhost / 127.0.0.1 with benchmark ports ──────────────────────────

    def test_localhost_port_3000_is_benchmark(self) -> None:
        assert _is_local_benchmark("http://localhost:3000") is True

    def test_localhost_port_8082_is_benchmark(self) -> None:
        assert _is_local_benchmark("http://localhost:8082") is True

    def test_127_0_0_1_port_3000_is_benchmark(self) -> None:
        assert _is_local_benchmark("http://127.0.0.1:3000") is True

    def test_127_0_0_1_port_8081_is_benchmark(self) -> None:
        assert _is_local_benchmark("http://127.0.0.1:8081") is True

    def test_localhost_port_8888_is_benchmark(self) -> None:
        assert _is_local_benchmark("http://localhost:8888") is True

    # ── localhost but NOT a benchmark port — must NOT auto-approve ──────────

    def test_localhost_port_443_is_not_benchmark(self) -> None:
        assert _is_local_benchmark("https://localhost:443") is False

    def test_localhost_port_80_is_not_benchmark(self) -> None:
        assert _is_local_benchmark("http://localhost:80") is False

    def test_localhost_no_port_is_not_benchmark(self) -> None:
        assert _is_local_benchmark("http://localhost") is False

    # ── remote host with benchmark port — MUST NOT auto-approve ────────────

    def test_remote_host_port_3000_is_NOT_benchmark(self) -> None:
        """Remote host + benchmark port must NEVER be auto-approved."""
        assert _is_local_benchmark("http://prod.example.com:3000") is False

    def test_remote_host_port_8082_is_NOT_benchmark(self) -> None:
        assert _is_local_benchmark("http://192.168.1.100:8082") is False

    def test_remote_host_port_8081_is_NOT_benchmark(self) -> None:
        assert _is_local_benchmark("http://staging.corp.internal:8081") is False

    def test_remote_host_port_3000_with_path_is_NOT_benchmark(self) -> None:
        assert _is_local_benchmark("http://api.prod.io:3000/admin") is False

    # ── ghost:// scheme — always auto-approved regardless of host ───────────

    def test_ghost_scheme_local_is_benchmark(self) -> None:
        assert _is_local_benchmark("ghost://localhost:3000") is True

    def test_ghost_scheme_remote_is_benchmark(self) -> None:
        """ghost:// is a VXIS-internal scheme — always safe to auto-approve."""
        assert _is_local_benchmark("ghost://remote.host.com:9999") is True

    # ── edge cases ───────────────────────────────────────────────────────────

    def test_empty_string_is_not_benchmark(self) -> None:
        assert _is_local_benchmark("") is False

    def test_case_insensitive_localhost(self) -> None:
        assert _is_local_benchmark("http://LOCALHOST:3000") is True

    def test_case_insensitive_127(self) -> None:
        assert _is_local_benchmark("HTTP://127.0.0.1:8082") is True
