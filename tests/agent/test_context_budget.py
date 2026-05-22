from __future__ import annotations

from pathlib import Path

from vxis.agent.context_budget import (
    estimate_context_tokens,
    fit_lines_to_token_budget,
    resolve_context_budget,
    trim_text_to_token_budget,
)
from vxis.dev.context_audit import audit_repo_context, format_context_audit


def test_local_worker_budget_is_tighter_than_frontier_director() -> None:
    director = resolve_context_budget("director", provider="openai", model="gpt-5.4")
    worker = resolve_context_budget("worker", provider="llamacpp", model="local-30b")

    assert director.max_prompt_tokens <= 300_000
    assert worker.max_prompt_tokens < director.max_prompt_tokens
    assert worker.history_tokens < 1_500
    assert worker.max_skill_chars <= 700


def test_fit_lines_to_token_budget_prefers_recent_signal() -> None:
    lines = [f"old {i} " + ("A" * 900) for i in range(30)]
    lines.append("latest confirmed SQL injection evidence")

    fitted = fit_lines_to_token_budget(lines, 220)

    rendered = "\n".join(fitted)
    assert "PROMPT-BUDGET COMPACTION" in rendered
    assert "latest confirmed SQL injection evidence" in rendered
    assert estimate_context_tokens(rendered) <= 260


def test_trim_text_to_token_budget_keeps_marker() -> None:
    trimmed = trim_text_to_token_budget("A" * 10_000, 120)

    assert "...truncated..." in trimmed
    assert estimate_context_tokens(trimmed) <= 120


def test_context_audit_reports_large_file(tmp_path: Path) -> None:
    large = tmp_path / "large.py"
    large.write_text(("print('x')\n" * 3000), encoding="utf-8")
    small = tmp_path / "small.py"
    small.write_text("print('ok')\n", encoding="utf-8")

    report = audit_repo_context([tmp_path], max_file_lines=100, max_file_tokens=1_000)
    rendered = format_context_audit(report, limit=5)

    assert report.warning_count >= 1
    assert any(item.path.endswith("large.py") for item in report.offenders)
    assert "Top offenders" in rendered
