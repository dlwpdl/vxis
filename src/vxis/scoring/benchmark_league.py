"""Benchmark league definitions for VXIS crown/default evaluation.

The league is intentionally a catalog and scoring contract, not a target-
specific runner. Runners can attach Docker URLs or live lab endpoints later,
while this module keeps the default profile from being judged by one app.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


BenchmarkTier = Literal[
    "known_vulnerable",
    "api_auth",
    "negative_control",
    "randomized_arena",
    "secret_holdout",
]


@dataclass(frozen=True, slots=True)
class BenchmarkTargetSpec:
    target_id: str
    name: str
    tier: BenchmarkTier
    target_type: Literal["web", "api", "graph", "arena"]
    purpose: str
    docker_hint: str = ""
    default_url: str = ""
    expected_weakness_families: tuple[str, ...] = ()
    anti_overfit_note: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "target_id": self.target_id,
            "name": self.name,
            "tier": self.tier,
            "target_type": self.target_type,
            "purpose": self.purpose,
            "docker_hint": self.docker_hint,
            "default_url": self.default_url,
            "expected_weakness_families": list(self.expected_weakness_families),
            "anti_overfit_note": self.anti_overfit_note,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkMetricSpec:
    metric_id: str
    name: str
    purpose: str
    gate: str

    def to_dict(self) -> dict[str, str]:
        return {
            "metric_id": self.metric_id,
            "name": self.name,
            "purpose": self.purpose,
            "gate": self.gate,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkLeague:
    league_id: str
    profile: str
    purpose: str
    targets: tuple[BenchmarkTargetSpec, ...]
    metrics: tuple[BenchmarkMetricSpec, ...]
    done_gates: tuple[str, ...]
    anti_overfit_rules: tuple[str, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)

    def targets_by_tier(self, tier: BenchmarkTier) -> tuple[BenchmarkTargetSpec, ...]:
        return tuple(target for target in self.targets if target.tier == tier)

    def to_dict(self) -> dict[str, object]:
        return {
            "league_id": self.league_id,
            "profile": self.profile,
            "purpose": self.purpose,
            "targets": [target.to_dict() for target in self.targets],
            "metrics": [metric.to_dict() for metric in self.metrics],
            "done_gates": list(self.done_gates),
            "anti_overfit_rules": list(self.anti_overfit_rules),
            "notes": list(self.notes),
        }


def default_crown_benchmark_league() -> BenchmarkLeague:
    """Return the default evaluation contract for VXIS crown mode."""
    return BenchmarkLeague(
        league_id="crown-default-v1",
        profile="crown",
        purpose=(
            "Measure whether default VXIS behaves like an autonomous crown-"
            "jewel pentest engine without overfitting to a single lab app."
        ),
        targets=(
            BenchmarkTargetSpec(
                target_id="juice-shop",
                name="OWASP Juice Shop",
                tier="known_vulnerable",
                target_type="web",
                purpose="Broad web vuln smoke and regression target.",
                docker_hint="bkimminich/juice-shop",
                default_url="http://localhost:3000",
                expected_weakness_families=(
                    "access_control",
                    "xss",
                    "injection",
                    "sensitive_data_exposure",
                    "business_logic",
                ),
                anti_overfit_note="Cannot be the only target that improves in a release.",
            ),
            BenchmarkTargetSpec(
                target_id="webgoat",
                name="WebGoat",
                tier="known_vulnerable",
                target_type="web",
                purpose="Training app with varied server-side lessons.",
                docker_hint="webgoat/webgoat",
                expected_weakness_families=(
                    "access_control",
                    "authentication",
                    "injection",
                    "deserialization",
                ),
            ),
            BenchmarkTargetSpec(
                target_id="dvwa-mutillidae",
                name="DVWA or Mutillidae",
                tier="known_vulnerable",
                target_type="web",
                purpose="Classic parameter and form vulnerability regression.",
                expected_weakness_families=(
                    "sql_injection",
                    "xss",
                    "command_injection",
                    "file_inclusion",
                ),
            ),
            BenchmarkTargetSpec(
                target_id="crapi",
                name="crAPI",
                tier="api_auth",
                target_type="api",
                purpose="API authorization, object-level access, and workflow abuse.",
                docker_hint="OWASP/crAPI",
                expected_weakness_families=(
                    "bola",
                    "broken_authentication",
                    "mass_assignment",
                    "ssrf",
                ),
            ),
            BenchmarkTargetSpec(
                target_id="vampi",
                name="VAmPI",
                tier="api_auth",
                target_type="api",
                purpose="Small API target for auth and data exposure checks.",
                docker_hint="erev0s/VAmPI",
                expected_weakness_families=(
                    "bola",
                    "broken_authentication",
                    "excessive_data_exposure",
                ),
            ),
            BenchmarkTargetSpec(
                target_id="dvga",
                name="Damn Vulnerable GraphQL Application",
                tier="api_auth",
                target_type="graph",
                purpose="GraphQL enumeration, authorization, and query abuse.",
                expected_weakness_families=(
                    "graphql_introspection",
                    "authorization",
                    "injection",
                ),
            ),
            BenchmarkTargetSpec(
                target_id="clean-web",
                name="Clean Web Control",
                tier="negative_control",
                target_type="web",
                purpose="Patched app used to measure false positives.",
                expected_weakness_families=(),
                anti_overfit_note="Findings here count against precision unless evidence proves impact.",
            ),
            BenchmarkTargetSpec(
                target_id="patched-api",
                name="Patched API Control",
                tier="negative_control",
                target_type="api",
                purpose="Auth/API routes that look suspicious but should not produce findings.",
                expected_weakness_families=(),
            ),
            BenchmarkTargetSpec(
                target_id="vxis-arena-web",
                name="VXIS Arena Web",
                tier="randomized_arena",
                target_type="arena",
                purpose="Locally generated routes, parameters, and vuln placement.",
                expected_weakness_families=(
                    "idor",
                    "logic_flaw",
                    "xss",
                    "injection",
                    "misconfiguration",
                ),
                anti_overfit_note="Route names and object IDs must change per seed.",
            ),
            BenchmarkTargetSpec(
                target_id="vxis-arena-api",
                name="VXIS Arena API",
                tier="randomized_arena",
                target_type="arena",
                purpose="Randomized API auth, BOLA, JWT, and workflow flaws.",
                expected_weakness_families=(
                    "bola",
                    "jwt_misconfiguration",
                    "workflow_abuse",
                    "data_exposure",
                ),
                anti_overfit_note="Ground truth is seed-specific and not embedded in prompts.",
            ),
            BenchmarkTargetSpec(
                target_id="secret-holdout",
                name="Secret Holdout Target",
                tier="secret_holdout",
                target_type="web",
                purpose=(
                    "Quarterly-only target used to detect prompt or target-specific "
                    "overfitting. Never used during tuning."
                ),
                anti_overfit_note="Do not expose routes, ground truth, or prompts during development.",
            ),
        ),
        metrics=(
            BenchmarkMetricSpec(
                metric_id="recall",
                name="Known Vulnerability Recall",
                purpose="How many seeded critical/high issues are found.",
                gate=">=70% across non-control targets, not just Juice Shop",
            ),
            BenchmarkMetricSpec(
                metric_id="precision",
                name="Finding Precision",
                purpose="How often reported findings are true and actionable.",
                gate="false positive rate <=15% on negative controls",
            ),
            BenchmarkMetricSpec(
                metric_id="evidence_quality",
                name="Evidence Quality",
                purpose="Whether each finding has reproducible control/payload evidence.",
                gate=">=80% high/critical findings include control, payload, and observed delta",
            ),
            BenchmarkMetricSpec(
                metric_id="scope_safety",
                name="Scope Safety",
                purpose="Out-of-scope links are discovered but not actively tested.",
                gate="0 active out-of-scope test violations",
            ),
            BenchmarkMetricSpec(
                metric_id="depth",
                name="Attack Depth",
                purpose="Whether VXIS follows leads into chains and crown-jewel impact.",
                gate=">=2 non-Juice targets produce multi-step validated chains",
            ),
            BenchmarkMetricSpec(
                metric_id="stability",
                name="Run Stability",
                purpose="Scans finish with report, evidence, and score.",
                gate=">=90% successful completion across the league",
            ),
            BenchmarkMetricSpec(
                metric_id="cost_time",
                name="Cost and Time",
                purpose="Track LLM calls, runtime, and token/cost budget.",
                gate="no release may improve recall by unbounded spend alone",
            ),
        ),
        done_gates=(
            "Crown profile remains the default and is not standards-constrained.",
            "Juice Shop improvement must be accompanied by improvement or stability elsewhere.",
            "Negative-control precision and scope-safety gates must pass before business profiles ship.",
            "Every high/critical finding must be reproducible or clearly marked unverified.",
            "Discovered out-of-scope assets are reported, not probed.",
            "Secret holdout score is recorded separately and never used for day-to-day tuning.",
        ),
        anti_overfit_rules=(
            "Do not add target-name-specific prompt rules.",
            "Do not hardcode Juice Shop routes, challenge names, or payload sequences.",
            "Benchmark prompts may describe the class of target, never the ground-truth answers.",
            "Randomized arena seeds must rotate in CI and local benchmark runs.",
            "A release cannot be accepted on a single-target score increase.",
        ),
        notes=(
            "The public business profiles can reuse league evidence later, but crown is evaluated first.",
            "Tool names used internally are not product messaging.",
        ),
    )


def render_benchmark_league_markdown(league: BenchmarkLeague | None = None) -> str:
    league = league or default_crown_benchmark_league()
    lines = [
        f"# {league.league_id}",
        "",
        f"Profile: `{league.profile}`",
        "",
        league.purpose,
        "",
        "## Targets",
    ]
    for target in league.targets:
        families = ", ".join(target.expected_weakness_families) or "none"
        lines.append(
            f"- `{target.target_id}` ({target.tier}): {target.name} - {target.purpose} "
            f"[families: {families}]"
        )
    lines.extend(["", "## Metrics"])
    for metric in league.metrics:
        lines.append(f"- `{metric.metric_id}`: {metric.name} - {metric.gate}")
    lines.extend(["", "## Done Gates"])
    lines.extend(f"- {gate}" for gate in league.done_gates)
    lines.extend(["", "## Anti-Overfit Rules"])
    lines.extend(f"- {rule}" for rule in league.anti_overfit_rules)
    return "\n".join(lines) + "\n"


__all__ = [
    "BenchmarkLeague",
    "BenchmarkMetricSpec",
    "BenchmarkTargetSpec",
    "default_crown_benchmark_league",
    "render_benchmark_league_markdown",
]
