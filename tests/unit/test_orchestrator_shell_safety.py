from __future__ import annotations

import shlex
from unittest.mock import AsyncMock

import pytest

from vxis.config.schema import VXISConfig
from vxis.core.context import DAGContext, PluginOutput
from vxis.core.orchestrator import ScanOrchestrator
from vxis.core.scanner import ToolResult
from vxis.plugins.cloud.s3scanner_plugin import S3ScannerPlugin
from vxis.plugins.osint.shodan_plugin import ShodanPlugin


class _Plugin:
    def build_command(self, **_kwargs) -> str:  # type: ignore[no-untyped-def]
        return "printf '%s\\n' 'safe target'"

    def get_timeout(self, _profile: str) -> int:
        return 1

    def parse_output(self, stdout: str, _stderr: str) -> PluginOutput:
        return PluginOutput(plugin_name="safe", raw_output=stdout)


@pytest.mark.asyncio
async def test_orchestrator_never_runs_plugin_commands_through_a_shell(
    tmp_path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    executed = AsyncMock(
        return_value=ToolResult(
            stdout="safe target\n",
            stderr="",
            return_code=0,
            command="printf %s\\n safe target",
            elapsed_seconds=0.01,
        )
    )
    monkeypatch.setattr("vxis.core.orchestrator.run_tool", executed)
    orchestrator = ScanOrchestrator(VXISConfig(data_dir=tmp_path))
    context = DAGContext(target="https://example.com", scan_profile="standard")
    run = orchestrator._make_run_func(
        registry={"safe": _Plugin()},
        dag_context=context,
        target="https://example.com",
        profile="standard",
        scan_id="scan-test",
    )

    await run("safe")

    assert executed.await_args.kwargs["shell"] is False


def test_s3scanner_passes_bucket_names_as_bash_arguments() -> None:
    malicious_bucket = 'safe\n$(touch /tmp/vxis-injected)\"; echo owned'
    context = DAGContext(target="https://example.com", scan_profile="standard")

    command = S3ScannerPlugin().build_command(
        target=context.target,
        scan_profile=context.scan_profile,
        ctx=context,
        tool_config={"buckets": [malicious_bucket]},
    )
    argv = shlex.split(command)

    assert argv[:2] == ["bash", "-c"]
    assert malicious_bucket not in argv[2]
    assert argv[3:] == ["--", malicious_bucket]


def test_shodan_passes_target_as_bash_argument() -> None:
    malicious_target = "example.com; touch /tmp/vxis-injected"
    context = DAGContext(target=malicious_target, scan_profile="standard")

    command = ShodanPlugin().build_command(
        target=context.target,
        scan_profile=context.scan_profile,
        ctx=context,
        tool_config={},
    )
    argv = shlex.split(command)

    assert argv[:2] == ["bash", "-c"]
    assert malicious_target not in argv[2]
    assert argv[3:] == ["--", malicious_target]
