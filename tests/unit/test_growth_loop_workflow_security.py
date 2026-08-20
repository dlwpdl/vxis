from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def _growth_inline_source() -> str:
    workflow = yaml.safe_load((WORKFLOWS / "growth-loop.yml").read_text(encoding="utf-8"))
    step = next(
        step for step in workflow["jobs"]["growth-loop"]["steps"] if step.get("id") == "growth"
    )
    lines = step["run"].splitlines()
    assert lines[0] == "uv run --frozen python - <<'PYEOF'"
    assert lines[-1] == "PYEOF"
    return "\n".join(lines[1:-1]) + "\n"


def test_third_party_actions_are_pinned_to_commit_sha() -> None:
    pattern = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s]+)@([^\s#]+)", re.MULTILINE)
    mutable: list[str] = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        for action, ref in pattern.findall(workflow.read_text(encoding="utf-8")):
            if action.startswith("./"):
                continue
            if re.fullmatch(r"[0-9a-f]{40}", ref) is None:
                mutable.append(f"{workflow.name}: {action}@{ref}")
    assert mutable == []


def test_growth_loop_is_manual_measurement_and_proposal_only() -> None:
    workflow = (WORKFLOWS / "growth-loop.yml").read_text(encoding="utf-8")
    assert "repository_dispatch:" not in workflow
    assert "confirm_isolated_eval:" in workflow
    assert "training_targets = [" in workflow
    assert "holdout_targets = [" in workflow
    assert "MAX_ITERATIONS = 3" in workflow
    assert "compare_with_baseline" not in workflow
    assert 'iter_log["proposals"] = safe_proposals' in workflow
    assert "secret_free_env()" in workflow
    assert "_BENCHMARK_CHILD" in workflow
    assert 'VXIS_ALLOW_ARBITRARY_EXEC: "0"' in workflow
    assert 'VXIS_EGRESS_STRICT: "1"' in workflow
    assert "apply_patches(" not in workflow
    assert "git commit" not in workflow
    assert "git push" not in workflow
    assert "gh pr create" not in workflow
    assert "Rollback on regression (signal-driven changes)" not in workflow
    assert "git pull --rebase" not in workflow


def test_growth_job_does_not_persist_checkout_credentials() -> None:
    workflow = (WORKFLOWS / "growth-loop.yml").read_text(encoding="utf-8")
    checkout_block = workflow.split("- name: Checkout", 1)[1].split("- name: Setup Python", 1)[0]
    assert "persist-credentials: false" in checkout_block
    assert "gh auth setup-git" not in workflow


def test_growth_job_has_no_code_write_token_or_mutable_cache() -> None:
    workflow = yaml.safe_load((WORKFLOWS / "growth-loop.yml").read_text(encoding="utf-8"))
    assert workflow["permissions"] == {"contents": "read", "issues": "write"}
    steps = workflow["jobs"]["growth-loop"]["steps"]
    assert all(not str(step.get("uses", "")).startswith("actions/cache@") for step in steps)
    archive = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    )
    assert set(archive["with"]["path"].splitlines()) == {
        "tools/benchmark/score_history.json",
        "tools/benchmark/iteration_log.json",
    }


def test_growth_inline_python_and_fresh_benchmark_child_compile() -> None:
    source = _growth_inline_source()
    tree = ast.parse(source, filename="growth-loop-inline.py")
    child = next(
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_BENCHMARK_CHILD"
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
    )
    assert compile(child, "growth-loop-benchmark-child.py", "exec") is not None


def test_growth_proposals_reject_malformed_json_without_crashing() -> None:
    tree = ast.parse(_growth_inline_source(), filename="growth-loop-inline.py")
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "sanitize_proposals"
    )
    namespace = {"Path": Path}
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), "sanitize-proposals.py", "exec"),
        namespace,
    )
    sanitize = namespace["sanitize_proposals"]
    allowed = "src/vxis/agent/brain.py"

    for malformed in (None, {}, "not-a-list", 42):
        assert sanitize(malformed, [allowed]) == []
    assert sanitize(
        [None, "not-an-object", {"file": allowed, "search": "old", "replace": "new"}],
        [allowed],
    ) == [{"file": allowed, "search": "old", "replace": "new"}]


def test_growth_summary_issue_has_no_label_dependency_or_silent_failure() -> None:
    workflow = yaml.safe_load((WORKFLOWS / "growth-loop.yml").read_text(encoding="utf-8"))
    step = next(
        step
        for step in workflow["jobs"]["growth-loop"]["steps"]
        if step.get("name") == "Create growth summary issue"
    )
    command = step["run"]
    assert "gh issue create" in command
    assert "--label" not in command
    assert "2>/dev/null" not in command
    assert "|| true" not in command


def test_workflow_service_images_are_immutable() -> None:
    images: list[str] = []
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        images.extend(
            re.findall(
                r"^\s*image:\s*(\S+)",
                workflow.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
    assert images
    assert all("@sha256:" in image for image in images)
