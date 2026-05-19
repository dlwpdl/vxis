import pytest

from vxis.agent.tools.verifier_tools import VerifyFindingTool


@pytest.mark.asyncio
async def test_verify_finding_refutes_binary_git_blob_disclosure_without_llm() -> None:
    tool = VerifyFindingTool(brain=None)
    result = await tool.run(
        title="Infrastructure exposure: git_exposed",
        severity="medium",
        finding_type="misconfiguration",
        affected_component="http://localhost:3000/.git/description",
        evidence=(
            "HTTP/1.1 200\n\n"
            "\\x1b\\x00\\x7f\\x9a\\xab\\xcd\\xef\\x10\\x22\\x33\\x44\\x55\\x66\\x77"
            "\\x88\\x99\\xaa\\xbb .git/description git_exposed zlib compressed blob"
        ),
    )
    assert result.ok is True
    assert result.data["verdict"] == "REFUTED"
    assert "binary blob" in result.summary.lower()
