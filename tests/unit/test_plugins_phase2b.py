"""Phase 2b plugin tests — semgrep, bandit, checkov, kube-bench, trivy-k8s,
poutine, actionlint."""

from __future__ import annotations

import json

import pytest

from vxis.core.context import DAGContext
from vxis.plugins.cicd.actionlint_plugin import ActionlintPlugin
from vxis.plugins.cicd.poutine_plugin import PoutinePlugin
from vxis.plugins.code.bandit_plugin import BanditPlugin
from vxis.plugins.code.checkov_plugin import CheckovPlugin
from vxis.plugins.code.semgrep_plugin import SemgrepPlugin
from vxis.plugins.container.kube_bench_plugin import KubeBenchPlugin
from vxis.plugins.container.trivy_k8s_plugin import TrivyK8sPlugin


# ---------------------------------------------------------------------------
# Sample raw output payloads (as provided in the spec)
# ---------------------------------------------------------------------------

SEMGREP_RAW = (
    '{"results":[{"check_id":"python.lang.security.audit.exec-detected",'
    '"extra":{"message":"exec() detected","severity":"ERROR",'
    '"metadata":{"cwe":["CWE-78"]}},"path":"app.py","start":{"line":42}}]}'
)

BANDIT_RAW = (
    '{"results":[{"test_id":"B101","issue_text":"Use of assert",'
    '"issue_severity":"MEDIUM","filename":"test.py","line_number":10,'
    '"issue_cwe":{"id":703}}]}'
)

CHECKOV_RAW = (
    '{"results":{"failed_checks":[{"check_id":"CKV_AWS_18",'
    '"name":"Ensure S3 bucket has logging",'
    '"guideline":"https://docs.checkov.io",'
    '"file_path":"/main.tf","file_line_range":[1,5],"severity":"HIGH"}]}}'
)

KUBE_BENCH_RAW = (
    '{"Controls":[{"id":"1.1","tests":[{"results":[{"test_number":"1.1.1",'
    '"test_desc":"Ensure API server --anonymous-auth is false",'
    '"remediation":"Set --anonymous-auth=false","status":"FAIL","scored":true}]}]}]}'
)

TRIVY_K8S_RAW = (
    '{"ClusterName":"prod","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-1234",'
    '"Severity":"CRITICAL","Title":"K8s API vuln"}]}'
)

POUTINE_RAW = (
    '{"rules":[{"id":"untrusted-checkout","title":"Untrusted checkout in PR trigger",'
    '"severity":"high","details":"pull_request_target with checkout"}]}'
)

# actionlint emits JSON Lines (one object per line)
ACTIONLINT_RAW = (
    '{"filepath":".github/workflows/ci.yml","line":15,"column":5,'
    '"message":"shellcheck reported issue","kind":"expression"}'
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ctx() -> DAGContext:
    return DAGContext(target="example.com", scan_profile="standard")


@pytest.fixture()
def semgrep() -> SemgrepPlugin:
    return SemgrepPlugin()


@pytest.fixture()
def bandit() -> BanditPlugin:
    return BanditPlugin()


@pytest.fixture()
def checkov() -> CheckovPlugin:
    return CheckovPlugin()


@pytest.fixture()
def kube_bench() -> KubeBenchPlugin:
    return KubeBenchPlugin()


@pytest.fixture()
def trivy_k8s() -> TrivyK8sPlugin:
    return TrivyK8sPlugin()


@pytest.fixture()
def poutine() -> PoutinePlugin:
    return PoutinePlugin()


@pytest.fixture()
def actionlint() -> ActionlintPlugin:
    return ActionlintPlugin()


# ===========================================================================
# Plugin 1: SemgrepPlugin
# ===========================================================================


class TestSemgrepPluginMeta:
    def test_meta_name(self, semgrep: SemgrepPlugin) -> None:
        assert semgrep.meta.name == "semgrep"

    def test_meta_binary(self, semgrep: SemgrepPlugin) -> None:
        assert semgrep.meta.tool_binary == "semgrep"

    def test_meta_category(self, semgrep: SemgrepPlugin) -> None:
        assert semgrep.meta.category == "code"

    def test_meta_produces(self, semgrep: SemgrepPlugin) -> None:
        assert "sast_findings" in semgrep.meta.produces

    def test_meta_timeout(self, semgrep: SemgrepPlugin) -> None:
        assert semgrep.meta.timeout_seconds == 1800

    def test_meta_depends_on_empty(self, semgrep: SemgrepPlugin) -> None:
        assert semgrep.meta.depends_on == ()


class TestSemgrepBuildCommand:
    def test_default_source_path(self, semgrep: SemgrepPlugin, ctx: DAGContext) -> None:
        cmd = semgrep.build_command("example.com", "standard", ctx, {})
        assert "semgrep scan" in cmd
        assert "--config auto" in cmd
        assert "--json" in cmd
        assert "--severity ERROR" in cmd
        assert "--severity WARNING" in cmd
        assert cmd.endswith(" .")

    def test_custom_source_path(self, semgrep: SemgrepPlugin, ctx: DAGContext) -> None:
        cmd = semgrep.build_command("example.com", "standard", ctx, {"source_path": "/src"})
        assert cmd.endswith(" /src")


class TestSemgrepParseOutput:
    def test_parse_sample(self, semgrep: SemgrepPlugin) -> None:
        out = semgrep.parse_output(SEMGREP_RAW, "")
        assert out.plugin_name == "semgrep"
        assert len(out.findings) == 1
        finding = out.findings[0]
        assert finding["check_id"] == "python.lang.security.audit.exec-detected"
        assert finding["severity"] == "ERROR"
        assert "CWE-78" in finding["cwe_ids"]
        assert finding["path"] == "app.py"
        assert finding["line"] == 42
        assert finding["affected_component"] == "app.py:42"

    def test_parse_empty(self, semgrep: SemgrepPlugin) -> None:
        out = semgrep.parse_output("", "")
        assert out.findings == []
        assert out.errors == []

    def test_parse_invalid_json(self, semgrep: SemgrepPlugin) -> None:
        out = semgrep.parse_output("not-json", "")
        assert out.findings == []
        assert len(out.errors) > 0

    def test_parse_no_results(self, semgrep: SemgrepPlugin) -> None:
        out = semgrep.parse_output('{"results":[]}', "")
        assert out.findings == []

    def test_parsed_data_key(self, semgrep: SemgrepPlugin) -> None:
        out = semgrep.parse_output(SEMGREP_RAW, "")
        assert "sast_findings" in out.parsed_data
        assert len(out.parsed_data["sast_findings"]) == 1


# ===========================================================================
# Plugin 2: BanditPlugin
# ===========================================================================


class TestBanditPluginMeta:
    def test_meta_name(self, bandit: BanditPlugin) -> None:
        assert bandit.meta.name == "bandit"

    def test_meta_binary(self, bandit: BanditPlugin) -> None:
        assert bandit.meta.tool_binary == "bandit"

    def test_meta_category(self, bandit: BanditPlugin) -> None:
        assert bandit.meta.category == "code"

    def test_meta_produces(self, bandit: BanditPlugin) -> None:
        assert "python_sast" in bandit.meta.produces

    def test_meta_timeout(self, bandit: BanditPlugin) -> None:
        assert bandit.meta.timeout_seconds == 600

    def test_meta_depends_on_empty(self, bandit: BanditPlugin) -> None:
        assert bandit.meta.depends_on == ()


class TestBanditBuildCommand:
    def test_default_source_path(self, bandit: BanditPlugin, ctx: DAGContext) -> None:
        cmd = bandit.build_command("example.com", "standard", ctx, {})
        assert "bandit -r ." in cmd
        assert "-f json" in cmd
        assert "-ll" in cmd

    def test_custom_source_path(self, bandit: BanditPlugin, ctx: DAGContext) -> None:
        cmd = bandit.build_command("example.com", "standard", ctx, {"source_path": "/app"})
        assert "bandit -r /app" in cmd


class TestBanditParseOutput:
    def test_parse_sample(self, bandit: BanditPlugin) -> None:
        out = bandit.parse_output(BANDIT_RAW, "")
        assert out.plugin_name == "bandit"
        assert len(out.findings) == 1
        finding = out.findings[0]
        assert finding["test_id"] == "B101"
        assert finding["issue_text"] == "Use of assert"
        assert finding["issue_severity"] == "MEDIUM"
        assert finding["filename"] == "test.py"
        assert finding["line_number"] == 10
        assert finding["cwe_id"] == 703

    def test_parse_empty(self, bandit: BanditPlugin) -> None:
        out = bandit.parse_output("", "")
        assert out.findings == []

    def test_parse_invalid_json(self, bandit: BanditPlugin) -> None:
        out = bandit.parse_output("bad", "")
        assert out.findings == []
        assert len(out.errors) > 0

    def test_parsed_data_key(self, bandit: BanditPlugin) -> None:
        out = bandit.parse_output(BANDIT_RAW, "")
        assert "python_sast" in out.parsed_data


# ===========================================================================
# Plugin 3: CheckovPlugin
# ===========================================================================


class TestCheckovPluginMeta:
    def test_meta_name(self, checkov: CheckovPlugin) -> None:
        assert checkov.meta.name == "checkov"

    def test_meta_binary(self, checkov: CheckovPlugin) -> None:
        assert checkov.meta.tool_binary == "checkov"

    def test_meta_category(self, checkov: CheckovPlugin) -> None:
        assert checkov.meta.category == "code"

    def test_meta_produces(self, checkov: CheckovPlugin) -> None:
        assert "iac_findings" in checkov.meta.produces

    def test_meta_timeout(self, checkov: CheckovPlugin) -> None:
        assert checkov.meta.timeout_seconds == 900

    def test_meta_depends_on_empty(self, checkov: CheckovPlugin) -> None:
        assert checkov.meta.depends_on == ()


class TestCheckovBuildCommand:
    def test_default_source_path(self, checkov: CheckovPlugin, ctx: DAGContext) -> None:
        cmd = checkov.build_command("example.com", "standard", ctx, {})
        assert "checkov -d ." in cmd
        # --framework all covers every framework checkov supports (Terraform,
        # CloudFormation, Kubernetes, Dockerfile, ARM, Bicep, Ansible, GitHub
        # Actions, …) without requiring an explicit allowlist.
        assert "--framework all" in cmd
        assert "--output json" in cmd
        assert "--compact" in cmd

    def test_custom_source_path(self, checkov: CheckovPlugin, ctx: DAGContext) -> None:
        cmd = checkov.build_command("example.com", "standard", ctx, {"source_path": "/iac"})
        assert "checkov -d /iac" in cmd


class TestCheckovParseOutput:
    def test_parse_sample(self, checkov: CheckovPlugin) -> None:
        out = checkov.parse_output(CHECKOV_RAW, "")
        assert out.plugin_name == "checkov"
        assert len(out.findings) == 1
        finding = out.findings[0]
        assert finding["check_id"] == "CKV_AWS_18"
        assert finding["name"] == "Ensure S3 bucket has logging"
        assert finding["guideline"] == "https://docs.checkov.io"
        assert finding["file_path"] == "/main.tf"
        assert finding["file_line_range"] == [1, 5]
        assert finding["severity"] == "HIGH"

    def test_parse_empty(self, checkov: CheckovPlugin) -> None:
        out = checkov.parse_output("", "")
        assert out.findings == []

    def test_parse_invalid_json(self, checkov: CheckovPlugin) -> None:
        out = checkov.parse_output("notjson", "")
        assert out.findings == []
        assert len(out.errors) > 0

    def test_parsed_data_key(self, checkov: CheckovPlugin) -> None:
        out = checkov.parse_output(CHECKOV_RAW, "")
        assert "iac_findings" in out.parsed_data


# ===========================================================================
# Plugin 4: KubeBenchPlugin
# ===========================================================================


class TestKubeBenchPluginMeta:
    def test_meta_name(self, kube_bench: KubeBenchPlugin) -> None:
        assert kube_bench.meta.name == "kube-bench"

    def test_meta_binary(self, kube_bench: KubeBenchPlugin) -> None:
        assert kube_bench.meta.tool_binary == "kube-bench"

    def test_meta_category(self, kube_bench: KubeBenchPlugin) -> None:
        assert kube_bench.meta.category == "container"

    def test_meta_produces(self, kube_bench: KubeBenchPlugin) -> None:
        assert "k8s_cis" in kube_bench.meta.produces

    def test_meta_timeout(self, kube_bench: KubeBenchPlugin) -> None:
        assert kube_bench.meta.timeout_seconds == 300

    def test_meta_depends_on_empty(self, kube_bench: KubeBenchPlugin) -> None:
        assert kube_bench.meta.depends_on == ()


class TestKubeBenchBuildCommand:
    def test_build_command(self, kube_bench: KubeBenchPlugin, ctx: DAGContext) -> None:
        cmd = kube_bench.build_command("cluster", "standard", ctx, {})
        assert cmd == "kube-bench run --json"


class TestKubeBenchParseOutput:
    def test_parse_sample(self, kube_bench: KubeBenchPlugin) -> None:
        out = kube_bench.parse_output(KUBE_BENCH_RAW, "")
        assert out.plugin_name == "kube-bench"
        assert len(out.findings) == 1
        finding = out.findings[0]
        assert finding["test_number"] == "1.1.1"
        assert finding["test_desc"] == "Ensure API server --anonymous-auth is false"
        assert finding["remediation"] == "Set --anonymous-auth=false"
        assert finding["status"] == "FAIL"
        assert finding["scored"] is True

    def test_parse_pass_results_filtered(self, kube_bench: KubeBenchPlugin) -> None:
        data = {
            "Controls": [
                {
                    "id": "1.1",
                    "tests": [
                        {
                            "results": [
                                {
                                    "test_number": "1.1.2",
                                    "test_desc": "Some check",
                                    "status": "PASS",
                                    "scored": True,
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        out = kube_bench.parse_output(json.dumps(data), "")
        assert out.findings == []

    def test_parse_empty(self, kube_bench: KubeBenchPlugin) -> None:
        out = kube_bench.parse_output("", "")
        assert out.findings == []

    def test_parsed_data_key(self, kube_bench: KubeBenchPlugin) -> None:
        out = kube_bench.parse_output(KUBE_BENCH_RAW, "")
        assert "k8s_cis" in out.parsed_data


# ===========================================================================
# Plugin 5: TrivyK8sPlugin
# ===========================================================================


class TestTrivyK8sPluginMeta:
    def test_meta_name(self, trivy_k8s: TrivyK8sPlugin) -> None:
        assert trivy_k8s.meta.name == "trivy-k8s"

    def test_meta_binary(self, trivy_k8s: TrivyK8sPlugin) -> None:
        assert trivy_k8s.meta.tool_binary == "trivy"

    def test_meta_category(self, trivy_k8s: TrivyK8sPlugin) -> None:
        assert trivy_k8s.meta.category == "container"

    def test_meta_produces(self, trivy_k8s: TrivyK8sPlugin) -> None:
        assert "k8s_vulns" in trivy_k8s.meta.produces

    def test_meta_timeout(self, trivy_k8s: TrivyK8sPlugin) -> None:
        assert trivy_k8s.meta.timeout_seconds == 900

    def test_meta_depends_on_empty(self, trivy_k8s: TrivyK8sPlugin) -> None:
        assert trivy_k8s.meta.depends_on == ()


class TestTrivyK8sBuildCommand:
    def test_build_command(self, trivy_k8s: TrivyK8sPlugin, ctx: DAGContext) -> None:
        cmd = trivy_k8s.build_command("cluster", "standard", ctx, {})
        assert "trivy k8s" in cmd
        assert "--report all" in cmd
        assert "--format json" in cmd
        assert "--severity CRITICAL,HIGH" in cmd


class TestTrivyK8sParseOutput:
    def test_parse_sample(self, trivy_k8s: TrivyK8sPlugin) -> None:
        out = trivy_k8s.parse_output(TRIVY_K8S_RAW, "")
        assert out.plugin_name == "trivy-k8s"
        assert len(out.findings) == 1
        finding = out.findings[0]
        assert finding["cluster_name"] == "prod"
        assert finding["vulnerability_id"] == "CVE-2024-1234"
        assert finding["severity"] == "CRITICAL"
        assert finding["title"] == "K8s API vuln"

    def test_parse_empty(self, trivy_k8s: TrivyK8sPlugin) -> None:
        out = trivy_k8s.parse_output("", "")
        assert out.findings == []

    def test_parse_invalid_json(self, trivy_k8s: TrivyK8sPlugin) -> None:
        out = trivy_k8s.parse_output("notjson", "")
        assert out.findings == []
        assert len(out.errors) > 0

    def test_parsed_data_key(self, trivy_k8s: TrivyK8sPlugin) -> None:
        out = trivy_k8s.parse_output(TRIVY_K8S_RAW, "")
        assert "k8s_vulns" in out.parsed_data


# ===========================================================================
# Plugin 6: PoutinePlugin
# ===========================================================================


class TestPoutinePluginMeta:
    def test_meta_name(self, poutine: PoutinePlugin) -> None:
        assert poutine.meta.name == "poutine"

    def test_meta_binary(self, poutine: PoutinePlugin) -> None:
        assert poutine.meta.tool_binary == "poutine"

    def test_meta_category(self, poutine: PoutinePlugin) -> None:
        assert poutine.meta.category == "cicd"

    def test_meta_produces(self, poutine: PoutinePlugin) -> None:
        assert "cicd_findings" in poutine.meta.produces

    def test_meta_timeout(self, poutine: PoutinePlugin) -> None:
        assert poutine.meta.timeout_seconds == 600

    def test_meta_depends_on_empty(self, poutine: PoutinePlugin) -> None:
        assert poutine.meta.depends_on == ()


class TestPoutineBuildCommand:
    def test_build_command_uses_tool_config_repo_url(
        self, poutine: PoutinePlugin, ctx: DAGContext
    ) -> None:
        cmd = poutine.build_command(
            "example.com", "standard", ctx, {"repo_url": "https://github.com/org/repo"}
        )
        assert "poutine analyze_repo https://github.com/org/repo" in cmd
        assert "--format json" in cmd

    def test_build_command_falls_back_to_target(
        self, poutine: PoutinePlugin, ctx: DAGContext
    ) -> None:
        cmd = poutine.build_command("https://github.com/org/repo", "standard", ctx, {})
        assert "poutine analyze_repo https://github.com/org/repo" in cmd


class TestPoutineParseOutput:
    def test_parse_sample(self, poutine: PoutinePlugin) -> None:
        out = poutine.parse_output(POUTINE_RAW, "")
        assert out.plugin_name == "poutine"
        assert len(out.findings) == 1
        finding = out.findings[0]
        assert finding["id"] == "untrusted-checkout"
        assert finding["title"] == "Untrusted checkout in PR trigger"
        assert finding["severity"] == "high"
        assert finding["details"] == "pull_request_target with checkout"

    def test_parse_empty(self, poutine: PoutinePlugin) -> None:
        out = poutine.parse_output("", "")
        assert out.findings == []

    def test_parse_invalid_json(self, poutine: PoutinePlugin) -> None:
        out = poutine.parse_output("bad", "")
        assert out.findings == []
        assert len(out.errors) > 0

    def test_parsed_data_key(self, poutine: PoutinePlugin) -> None:
        out = poutine.parse_output(POUTINE_RAW, "")
        assert "cicd_findings" in out.parsed_data


# ===========================================================================
# Plugin 7: ActionlintPlugin
# ===========================================================================


class TestActionlintPluginMeta:
    def test_meta_name(self, actionlint: ActionlintPlugin) -> None:
        assert actionlint.meta.name == "actionlint"

    def test_meta_binary(self, actionlint: ActionlintPlugin) -> None:
        assert actionlint.meta.tool_binary == "actionlint"

    def test_meta_category(self, actionlint: ActionlintPlugin) -> None:
        assert actionlint.meta.category == "cicd"

    def test_meta_produces(self, actionlint: ActionlintPlugin) -> None:
        assert "gha_lint" in actionlint.meta.produces

    def test_meta_timeout(self, actionlint: ActionlintPlugin) -> None:
        assert actionlint.meta.timeout_seconds == 120

    def test_meta_depends_on_empty(self, actionlint: ActionlintPlugin) -> None:
        assert actionlint.meta.depends_on == ()


class TestActionlintBuildCommand:
    def test_default_workflow_dir(self, actionlint: ActionlintPlugin, ctx: DAGContext) -> None:
        cmd = actionlint.build_command("example.com", "standard", ctx, {})
        assert "actionlint" in cmd
        assert ".github/workflows" in cmd

    def test_custom_workflow_dir(self, actionlint: ActionlintPlugin, ctx: DAGContext) -> None:
        cmd = actionlint.build_command(
            "example.com", "standard", ctx, {"workflow_dir": "/repo/.github/workflows"}
        )
        assert "/repo/.github/workflows" in cmd


class TestActionlintParseOutput:
    def test_parse_sample(self, actionlint: ActionlintPlugin) -> None:
        out = actionlint.parse_output(ACTIONLINT_RAW, "")
        assert out.plugin_name == "actionlint"
        assert len(out.findings) == 1
        finding = out.findings[0]
        assert finding["filepath"] == ".github/workflows/ci.yml"
        assert finding["line"] == 15
        assert finding["message"] == "shellcheck reported issue"
        assert finding["kind"] == "expression"
        # "expression" is security-relevant → medium
        assert finding["severity"] == "medium"

    def test_parse_non_security_kind_is_low(self, actionlint: ActionlintPlugin) -> None:
        raw = '{"filepath":"ci.yml","line":1,"column":1,"message":"syntax error","kind":"syntax"}'
        out = actionlint.parse_output(raw, "")
        assert out.findings[0]["severity"] == "low"

    def test_parse_empty(self, actionlint: ActionlintPlugin) -> None:
        out = actionlint.parse_output("", "")
        assert out.findings == []

    def test_parse_multiple_json_lines(self, actionlint: ActionlintPlugin) -> None:
        raw = "\n".join([
            '{"filepath":"ci.yml","line":1,"column":1,"message":"err1","kind":"expression"}',
            '{"filepath":"ci.yml","line":2,"column":3,"message":"err2","kind":"syntax"}',
        ])
        out = actionlint.parse_output(raw, "")
        assert len(out.findings) == 2
        assert out.findings[0]["severity"] == "medium"
        assert out.findings[1]["severity"] == "low"

    def test_parsed_data_key(self, actionlint: ActionlintPlugin) -> None:
        out = actionlint.parse_output(ACTIONLINT_RAW, "")
        assert "gha_lint" in out.parsed_data
