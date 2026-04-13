"""Skill runner tool — Brain calls run_skill to execute attack capabilities.

One run_skill call = dozens of payloads tested = one Brain decision.
Brain decides WHAT to test WHERE, the skill handles HOW.
"""
from __future__ import annotations
import json
import logging
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)


class RunSkillTool:
    name = "run_skill"
    description = (
        "Execute a pre-built attack skill. Each skill runs a complete "
        "attack test (dozens of payloads) in one call. Brain decides "
        "WHICH skill to run on WHICH endpoint — the skill handles HOW.\n\n"
        "Available skills:\n"
        "  enumerate_endpoints — scan 120+ paths, return all accessible endpoints\n"
        "  test_injection — SQLi/XSS/SSTI/CMDi (40+ payloads) on URL+param\n"
        "  attempt_auth — default creds + SQLi bypass + password reset\n"
        "  post_auth_enum — with token, test all authenticated endpoints\n"
        "  test_sensitive_files — scan 60+ sensitive file/config paths\n"
        "  test_idor — iterate IDs on an endpoint, detect access control issues\n"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "skill": {
                "type": "string",
                "description": "Skill name: enumerate_endpoints, test_injection, attempt_auth, post_auth_enum, test_sensitive_files, test_idor",
            },
            "target_url": {
                "type": "string",
                "description": "Target URL (e.g. http://localhost:3000)",
            },
            "params": {
                "type": "object",
                "description": "Additional parameters for the skill (e.g. token, param_name, url_pattern)",
            },
        },
        "required": ["skill", "target_url"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        skill_name = str(kwargs.get("skill", "")).strip()
        target_url = str(kwargs.get("target_url", "")).strip()
        params = kwargs.get("params", {}) or {}

        if not skill_name or not target_url:
            return ToolResult(
                ok=False,
                summary="run_skill: skill and target_url required",
                error="missing_args",
            )

        try:
            from vxis.agent.skills import SKILL_REGISTRY
        except ImportError as e:
            return ToolResult(ok=False, summary=f"run_skill: import error: {e}", error=str(e))

        if skill_name not in SKILL_REGISTRY:
            available = ", ".join(SKILL_REGISTRY.keys())
            return ToolResult(
                ok=False,
                summary=f"run_skill: unknown skill '{skill_name}'. Available: {available}",
                error="unknown_skill",
            )

        skill = SKILL_REGISTRY[skill_name]
        fn = skill["fn"]

        try:
            # Execute the skill
            if skill_name == "test_idor":
                # test_idor uses url_pattern, not target_url
                result = await fn(
                    url_pattern=params.get("url_pattern", target_url + "/api/Users/{id}"),
                    token=params.get("token"),
                    **{k: v for k, v in params.items() if k not in ("url_pattern", "token")},
                )
            elif skill_name in ("post_auth_enum",):
                result = await fn(target_url=target_url, token=params.get("token", ""), **{k: v for k, v in params.items() if k != "token"})
            elif skill_name == "test_injection":
                # For injection, target_url should include the param
                result = await fn(url=target_url, **params)
            else:
                result = await fn(target_url=target_url, **params)
        except Exception as e:
            logger.exception("run_skill %s failed", skill_name)
            return ToolResult(ok=False, summary=f"run_skill {skill_name}: {type(e).__name__}: {e}", error=str(e))

        # Build a compact summary
        summary_parts = [f"skill:{skill_name}"]

        if skill_name == "enumerate_endpoints":
            accessible = result.get("accessible", [])
            auth_req = result.get("auth_required", [])
            errors = result.get("errors", [])
            summary_parts.append(f"{len(accessible)} accessible, {len(auth_req)} auth-required, {len(errors)} errors")
            if accessible:
                summary_parts.append("Top: " + ", ".join(f"{e['path']}({e['size']}B)" for e in accessible[:5]))

        elif skill_name == "test_injection":
            findings = result.get("findings", [])
            summary_parts.append(f"{'VULNERABLE' if result.get('vulnerable') else 'clean'} — {len(findings)} finding(s)")
            for f in findings[:3]:
                summary_parts.append(f"  {f['type']}: {f['payload'][:30]} ({f['severity']})")

        elif skill_name == "attempt_auth":
            if result.get("authenticated"):
                summary_parts.append(f"AUTHENTICATED via {result['method']}! token={result['token'][:30]}...")
                summary_parts.append(f"user: {result.get('user_info', {})}")
            else:
                summary_parts.append(f"auth failed ({len(result.get('all_attempts', []))} attempts)")

        elif skill_name == "post_auth_enum":
            acc = result.get("accessible", [])
            new = result.get("new_endpoints", [])
            exposed = result.get("user_data_exposed", [])
            summary_parts.append(f"{len(acc)} accessible, {len(new)} new (auth-only), {len(exposed)} with user data")

        elif skill_name == "test_sensitive_files":
            exposed = result.get("exposed", [])
            summary_parts.append(f"{len(exposed)} sensitive files found")
            for e in exposed[:5]:
                summary_parts.append(f"  [{e['severity']}] {e['path']} ({e['size']}B)")

        elif skill_name == "test_idor":
            summary_parts.append(
                f"{'VULNERABLE' if result.get('vulnerable') else 'clean'} — "
                f"{len(result.get('accessible_ids', []))} accessible, "
                f"{len(result.get('auth_bypass_ids', []))} without auth"
            )

        return ToolResult(
            ok=True,
            data=result,
            summary=" | ".join(summary_parts),
        )
