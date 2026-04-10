"""Finding CRUD tools — Brain reports / queries / chains discovered vulnerabilities.

State is held in a module-level list of Finding dicts for Phase A. Phase B may
swap this for a persistent store (SQLite/Postgres episodic memory).

Tools:
- report_finding: Brain submits a new finding. Assigns an ID, stores it, returns the ID.
- query_findings: Brain searches existing findings by type/severity/component/free text.
- link_chain: Brain asserts a causal attack chain between N previously-reported findings.
"""
from __future__ import annotations

import logging
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

# Module-level findings store — Phase A in-memory
_findings: list[dict[str, Any]] = []
_chains: list[dict[str, Any]] = []

_VALID_SEVERITIES = ("critical", "high", "medium", "low", "informational")


def _reset_for_tests() -> None:
    """Reset module-level state. Called from test fixtures, NOT from production."""
    global _findings, _chains
    _findings = []
    _chains = []


def _get_findings() -> list[dict[str, Any]]:
    """Public accessor for integration (ScanAgentLoop) to read the findings list."""
    return list(_findings)


def _get_chains() -> list[dict[str, Any]]:
    """Public accessor for integration to read the chains list."""
    return list(_chains)


class ReportFindingTool:
    name = "report_finding"
    description = (
        "Submit a discovered vulnerability. Returns the assigned finding ID. "
        "Include enough detail (title, severity, component, evidence, description) "
        "for a penetration test report. The ID is stable and can be used in link_chain."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": list(_VALID_SEVERITIES)},
            "finding_type": {"type": "string", "description": "snake_case vuln type e.g. 'sql_injection', 'xss_reflected'"},
            "affected_component": {"type": "string"},
            "description": {"type": "string"},
            "evidence": {"type": "string", "description": "Raw evidence: HTTP req/resp, payload, log excerpt"},
            "remediation": {"type": "string"},
            "cwe": {"type": "string", "description": "e.g. 'CWE-89'"},
        },
        "required": ["title", "severity", "finding_type", "affected_component", "description"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        severity = kwargs.get("severity", "").lower()
        if severity not in _VALID_SEVERITIES:
            return ToolResult(
                ok=False,
                summary=f"report_finding: invalid severity '{severity}'. Use one of {_VALID_SEVERITIES}.",
                error="invalid_severity",
            )

        required = ["title", "finding_type", "affected_component", "description"]
        missing = [k for k in required if not kwargs.get(k)]
        if missing:
            return ToolResult(
                ok=False,
                summary=f"report_finding: missing required fields: {missing}",
                error="missing_fields",
            )

        # Phase B: simple dedup — if a finding with the same (finding_type,
        # affected_component) already exists, skip re-creation and return the
        # existing id. Prevents Brain from reporting the same issue twice when
        # it loses track of its own state.
        def _normalize(s: str) -> str:
            """Normalize finding_type and affected_component for dedup matching."""
            s = str(s).lower().strip()
            s = s.rstrip("/")
            s = " ".join(s.split())
            return s

        def _base_path(component: str) -> str:
            """Extract base API path, stripping numeric IDs and query params.

            /api/Orders/1      → /api/orders
            /api/Orders/2      → /api/orders
            /api/Baskets/1/items → /api/baskets
            http://x:3000/api/Orders/1 → /api/orders
            /rest/products/search?q=test' → /rest/products/search
            """
            import re
            from urllib.parse import urlparse
            try:
                parsed = urlparse(component)
                path = parsed.path or component
            except Exception:
                path = component
            path = path.lower().strip().rstrip("/")
            # Remove query string
            path = path.split("?")[0]
            # Strip trailing numeric segments (/1, /2, /123)
            path = re.sub(r"/\d+(/|$)", "/", path).rstrip("/")
            return path

        new_type = _normalize(kwargs["finding_type"])
        new_component = _normalize(kwargs["affected_component"])
        new_base = _base_path(kwargs["affected_component"])

        for existing in _findings:
            ex_type = _normalize(existing["finding_type"])
            ex_component = _normalize(existing["affected_component"])
            ex_base = _base_path(existing["affected_component"])

            # Exact match OR same base path + same finding type
            if ex_type == new_type and (ex_component == new_component or ex_base == new_base):
                # If base-path match, append this variant to affected_endpoints
                if ex_component != new_component:
                    endpoints = existing.get("affected_endpoints", [existing["affected_component"]])
                    if kwargs["affected_component"] not in endpoints:
                        endpoints.append(kwargs["affected_component"])
                    existing["affected_endpoints"] = endpoints
                    logger.info(
                        "[Finding] base-path dedup: %s grouped into %s (%d endpoints)",
                        new_component, existing["id"], len(endpoints),
                    )
                else:
                    logger.info(
                        "[Finding] exact dedup: %s %s (already %s)",
                        new_type, new_component, existing["id"],
                    )
                return ToolResult(
                    ok=True,
                    data={
                        "id": existing["id"],
                        "total_findings": len(_findings),
                        "deduped": True,
                        "affected_endpoints": existing.get("affected_endpoints", []),
                    },
                    summary=(
                        f"finding grouped into {existing['id']} "
                        f"(same base path {ex_base}). "
                        f"Try a DIFFERENT endpoint or attack type instead."
                    ),
                )

        finding_id = f"VXIS-{len(_findings) + 1:04d}"
        finding = {
            "id": finding_id,
            "title": str(kwargs["title"]),
            "severity": severity,
            "finding_type": str(kwargs["finding_type"]),
            "affected_component": str(kwargs["affected_component"]),
            "description": str(kwargs["description"]),
            "evidence": str(kwargs.get("evidence", "")),
            "remediation": str(kwargs.get("remediation", "")),
            "cwe": str(kwargs.get("cwe", "")),
        }
        _findings.append(finding)
        logger.info("[Finding] %s [%s] %s — %s", finding_id, severity.upper(), kwargs["finding_type"], str(kwargs["title"])[:80])

        return ToolResult(
            ok=True,
            data={"id": finding_id, "total_findings": len(_findings)},
            summary=f"finding recorded: {finding_id} [{severity}] {str(kwargs['title'])[:60]}",
        )


class QueryFindingsTool:
    name = "query_findings"
    description = (
        "Search previously-reported findings. Filter by severity, finding_type, "
        "affected_component substring, or free-text substring match against title/description. "
        "Returns matching finding IDs and summaries."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "severity": {"type": "string", "enum": list(_VALID_SEVERITIES)},
            "finding_type": {"type": "string"},
            "component_contains": {"type": "string"},
            "text_contains": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Max results (default 20)"},
        },
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        severity = kwargs.get("severity")
        finding_type = kwargs.get("finding_type")
        component_substr = (kwargs.get("component_contains") or "").lower()
        text_substr = (kwargs.get("text_contains") or "").lower()
        try:
            limit = int(kwargs.get("limit", 20))
        except (TypeError, ValueError):
            limit = 20
        limit = max(1, min(100, limit))

        results = []
        for f in _findings:
            if severity and f["severity"] != severity:
                continue
            if finding_type and f["finding_type"] != finding_type:
                continue
            if component_substr and component_substr not in f["affected_component"].lower():
                continue
            if text_substr:
                blob = (f["title"] + " " + f["description"]).lower()
                if text_substr not in blob:
                    continue
            results.append({
                "id": f["id"],
                "severity": f["severity"],
                "finding_type": f["finding_type"],
                "title": f["title"][:120],
                "affected_component": f["affected_component"],
            })
            if len(results) >= limit:
                break

        return ToolResult(
            ok=True,
            data={"count": len(results), "findings": results, "total_in_store": len(_findings)},
            summary=f"query_findings: {len(results)} match(es) (of {len(_findings)} total)",
        )


class LinkChainTool:
    name = "link_chain"
    description = (
        "Assert that a sequence of previously-reported findings forms a causal attack chain. "
        "Example: low-sev info disclosure → medium-sev IDOR → high-sev privilege escalation. "
        "Finding IDs must be in the store (report_finding first). The chain is stored "
        "separately and surfaced in the final report."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "finding_ids": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 2,
                "description": "Ordered list of finding IDs forming the chain, e.g. ['VXIS-0001', 'VXIS-0003', 'VXIS-0007']",
            },
            "rationale": {"type": "string", "description": "Why these findings chain together — the attack narrative"},
            "crown_jewel": {"type": "string", "description": "What the chain ultimately compromises (e.g. 'admin account takeover', 'full DB dump')"},
        },
        "required": ["finding_ids", "rationale"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        finding_ids = kwargs.get("finding_ids") or []
        rationale = kwargs.get("rationale", "")
        crown_jewel = kwargs.get("crown_jewel", "")

        if not isinstance(finding_ids, list) or len(finding_ids) < 2:
            return ToolResult(
                ok=False,
                summary="link_chain: need at least 2 finding IDs",
                error="insufficient_findings",
            )
        if not rationale:
            return ToolResult(ok=False, summary="link_chain: rationale is required", error="missing_rationale")

        known_ids = {f["id"] for f in _findings}
        unknown = [fid for fid in finding_ids if fid not in known_ids]
        if unknown:
            return ToolResult(
                ok=False,
                summary=f"link_chain: unknown finding IDs {unknown}. Use report_finding first.",
                error="unknown_finding_ids",
            )

        chain_id = f"CHAIN-{len(_chains) + 1:03d}"
        chain = {
            "id": chain_id,
            "finding_ids": list(finding_ids),
            "rationale": str(rationale),
            "crown_jewel": str(crown_jewel),
            "length": len(finding_ids),
        }
        _chains.append(chain)
        logger.info("[Chain] %s: %s → %s", chain_id, " → ".join(finding_ids), str(crown_jewel)[:60])

        return ToolResult(
            ok=True,
            data={"id": chain_id, "length": len(finding_ids), "total_chains": len(_chains)},
            summary=f"chain recorded: {chain_id} ({len(finding_ids)} findings) → {str(crown_jewel)[:60]}",
        )
