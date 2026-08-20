"""Security regressions for the privileged auto-implementation workflow."""

from pathlib import Path


WORKFLOW = Path(__file__).parents[2] / ".github/workflows/auto-implement.yml"


def test_untrusted_github_values_are_not_interpolated_into_shell() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert 'TITLE="${{ steps.issue.outputs.title }}"' not in workflow
    assert 'ISSUE_NUM="${{ steps.issue.outputs.number }}"' not in workflow
    assert 'ISSUE_NUM="${{ github.event.inputs.issue_number }}"' not in workflow
    assert "ISSUE_NUMBER: ${{ steps.issue.outputs.number }}" in workflow


def test_generated_files_and_security_scan_fail_closed() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "ALLOWED_OUTPUT_ROOTS" in workflow
    assert "Unsafe generated path" in workflow
    assert "git add -A" in workflow
    assert 'endswith(".py")' not in workflow
    assert '"--diff-filter=ACMR"' in workflow
    assert "check=True" in workflow
    assert "sys.exit(1)" in workflow
    assert "if: always()\n        env:\n          GH_TOKEN" not in workflow
