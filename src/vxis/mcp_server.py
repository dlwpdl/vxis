"""VXIS MCP Server — AI 에이전트가 VXIS를 도구로 사용할 수 있게 하는 MCP 서버.

Claude, GPT, Copilot 등의 AI가 VXIS에 연결하여:
1. 보안 스캔 시작
2. 스캔 결과 조회
3. 리포트 생성
4. 플러그인 상태 확인

Protocol: JSON-RPC 2.0 over stdio (MCP spec compliant)

Usage:
    python -m vxis.mcp_server
    # or via entry point:
    vxis-mcp

Claude Code integration:
    claude mcp add vxis python -m vxis.mcp_server
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Silence all library-level log output so it does not pollute the stdio channel.
# The MCP protocol communicates exclusively over stdout; any stray text breaks it.
logging.disable(logging.CRITICAL)

# ---------------------------------------------------------------------------
# MCP Protocol constants
# ---------------------------------------------------------------------------

MCP_VERSION = "2024-11-05"
SERVER_NAME = "vxis"
SERVER_VERSION = "0.1.0"

# JSON-RPC error codes (JSON-RPC 2.0 spec)
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# ---------------------------------------------------------------------------
# Tool definitions (MCP tools/list schema)
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "vxis_scan",
        "description": (
            "Start a VXIS security scan against a target. "
            "Runs the full plugin pipeline (recon, vuln scan, enrichment) "
            "and returns a summary with scan_id and findings count."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Scan target: domain, IP address, or CIDR range (e.g. example.com, 10.0.0.1, 192.168.1.0/24)",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["zero_touch", "external", "internal", "code", "cloud", "full"],
                    "description": "Type of scan to perform. Defaults to 'external'.",
                    "default": "external",
                },
                "profile": {
                    "type": "string",
                    "enum": ["passive", "stealth", "standard", "aggressive"],
                    "description": "Scan intensity profile. Defaults to 'standard'.",
                    "default": "standard",
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "vxis_results",
        "description": (
            "Retrieve detailed findings from a completed scan. "
            "Returns a list of security findings with severity, title, description, "
            "CVE IDs, remediation guidance, and source plugin."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "The scan_id returned by vxis_scan.",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["informational", "low", "medium", "high", "critical"],
                    "description": "Filter to only return findings at or above this severity. Defaults to 'informational' (all).",
                    "default": "informational",
                },
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "vxis_report",
        "description": (
            "Generate a professional security assessment report from a completed scan. "
            "Produces an HTML or DOCX report file and returns the file path."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "The scan_id returned by vxis_scan.",
                },
                "format": {
                    "type": "string",
                    "enum": ["html", "docx"],
                    "description": "Output format. Defaults to 'html'.",
                    "default": "html",
                },
                "client_name": {
                    "type": "string",
                    "description": "Client/organisation name to display in the report header.",
                    "default": "VXIS Assessment",
                },
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "vxis_plugins",
        "description": (
            "List all available VXIS security plugins with their category "
            "and availability status (whether the required binary is installed)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Optional filter by category (e.g. 'recon', 'vuln', 'secret'). Returns all categories if omitted.",
                },
            },
        },
    },
    {
        "name": "vxis_agent_scan",
        "description": (
            "Launch an AI-driven autonomous security scan using the VXIS Master Agent. "
            "The agent autonomously decides which tools to run, interprets results, "
            "and iterates to maximise finding coverage. More thorough than vxis_scan "
            "but takes longer. Returns findings and a step-by-step execution log."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Scan target: domain, IP address, or CIDR range.",
                },
                "max_steps": {
                    "type": "integer",
                    "description": "Maximum reasoning steps the agent may take. Higher = more thorough but slower. Defaults to 15.",
                    "default": 15,
                    "minimum": 1,
                    "maximum": 50,
                },
                "profile": {
                    "type": "string",
                    "enum": ["passive", "stealth", "standard", "aggressive"],
                    "description": "Scan intensity profile. Defaults to 'standard'.",
                    "default": "standard",
                },
            },
            "required": ["target"],
        },
    },
]

# ---------------------------------------------------------------------------
# In-memory scan result store
# Scans triggered via MCP are kept here for subsequent vxis_results calls.
# In a production deployment this would delegate to the VXIS database.
# ---------------------------------------------------------------------------

_scan_store: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def _handle_vxis_scan(args: dict[str, Any]) -> dict[str, Any]:
    """Execute vxis_scan tool: run ScanOrchestrator and return a summary."""
    target: str = args.get("target", "").strip()
    if not target:
        raise ValueError("'target' is required and must not be empty.")

    profile: str = args.get("profile", "standard")
    scan_type: str = args.get("scan_type", "external")

    # Map scan_type to tier (zero_touch = recon-only tier 1)
    tier = 1 if scan_type in ("zero_touch", "passive") else 2

    try:
        from vxis.config.schema import VXISConfig
        from vxis.core.orchestrator import ScanOrchestrator

        config = VXISConfig()
        orchestrator = ScanOrchestrator(config)
        result = await orchestrator.run_scan(
            target=target,
            profile=profile,
            tier=tier,
        )
    except Exception as exc:
        raise RuntimeError(f"Scan failed: {exc}") from exc

    # Cache findings for vxis_results
    _scan_store[result.scan_id] = {
        "scan_id": result.scan_id,
        "target": result.target,
        "profile": result.profile,
        "findings": [_serialise_finding(f) for f in result.findings],
        "tool_runs": result.tool_runs,
        "errors": result.errors,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "duration_seconds": result.duration_seconds,
        "severity_counts": result.severity_counts,
    }

    severity_counts = result.severity_counts
    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "profile": profile,
        "scan_type": scan_type,
        "total_findings": len(result.findings),
        "severity_counts": severity_counts,
        "duration_seconds": round(result.duration_seconds, 1),
        "errors": len(result.errors),
        "summary": (
            f"Scan of {target} completed in {result.duration_seconds:.0f}s. "
            f"Found {len(result.findings)} findings "
            f"(critical={severity_counts.get('critical', 0)}, "
            f"high={severity_counts.get('high', 0)}, "
            f"medium={severity_counts.get('medium', 0)}, "
            f"low={severity_counts.get('low', 0)})."
        ),
    }


async def _handle_vxis_results(args: dict[str, Any]) -> dict[str, Any]:
    """Execute vxis_results tool: return findings for a scan_id."""
    scan_id: str = args.get("scan_id", "").strip()
    if not scan_id:
        raise ValueError("'scan_id' is required.")

    min_severity: str = args.get("min_severity", "informational")

    _severity_order = ["informational", "low", "medium", "high", "critical"]
    if min_severity not in _severity_order:
        raise ValueError(
            f"'min_severity' must be one of: {', '.join(_severity_order)}"
        )
    min_weight = _severity_order.index(min_severity)

    # Check in-memory store first (scans triggered in this session)
    cached = _scan_store.get(scan_id)
    if cached is not None:
        findings = cached["findings"]
        filtered = [
            f for f in findings
            if _severity_order.index(f.get("severity", "informational")) >= min_weight
        ]
        return {
            "scan_id": scan_id,
            "target": cached["target"],
            "total_findings": len(filtered),
            "findings": filtered,
        }

    # Fall back to database query
    try:
        from vxis.config.schema import VXISConfig
        from vxis.core.db import create_engine, init_db, get_session
        from vxis.models.db_models import ScanRecord, FindingRecord
        from sqlalchemy import select

        config = VXISConfig()
        db_url = config.db_url
        if ":///" in db_url:
            prefix, path = db_url.split("///", 1)
            db_url = f"{prefix}///{Path(path).expanduser()}"

        engine = create_engine(db_url)
        await init_db(engine)

        async with get_session(engine) as session:
            # Locate the scan by UUID stored in config_snapshot
            stmt = select(ScanRecord)
            scans = (await session.execute(stmt)).scalars().all()
            matching_scan = next(
                (
                    s for s in scans
                    if isinstance(s.config_snapshot, dict)
                    and s.config_snapshot.get("scan_id") == scan_id
                ),
                None,
            )

            if matching_scan is None:
                raise ValueError(f"scan_id '{scan_id}' not found in database.")

            findings_stmt = select(FindingRecord).where(
                FindingRecord.scan_id == matching_scan.id
            )
            finding_records = (await session.execute(findings_stmt)).scalars().all()

        findings: list[dict[str, Any]] = []
        for rec in finding_records:
            sev = rec.effective_severity or rec.severity or "informational"
            if _severity_order.index(sev) < min_weight:
                continue
            findings.append({
                "title": rec.title,
                "severity": sev,
                "description": rec.description or "",
                "target": rec.target or "",
                "port": rec.port,
                "protocol": rec.protocol or "",
                "affected_component": rec.affected_component or "",
                "cve_ids": rec.cve_ids or [],
                "cwe_ids": rec.cwe_ids or [],
                "cvss_score": rec.cvss_score,
                "remediation": rec.remediation or "",
                "source_plugin": rec.source_plugin or "",
                "confidence": rec.confidence,
                "discovered_at": (
                    rec.discovered_at.isoformat()
                    if rec.discovered_at
                    else None
                ),
            })

        return {
            "scan_id": scan_id,
            "target": matching_scan.target,
            "total_findings": len(findings),
            "findings": findings,
        }

    except ValueError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Failed to retrieve results: {exc}") from exc


async def _handle_vxis_report(args: dict[str, Any]) -> dict[str, Any]:
    """Execute vxis_report tool: generate HTML or DOCX report."""
    scan_id: str = args.get("scan_id", "").strip()
    if not scan_id:
        raise ValueError("'scan_id' is required.")

    fmt: str = args.get("format", "html").lower()
    if fmt not in ("html", "docx"):
        raise ValueError("'format' must be 'html' or 'docx'.")

    client_name: str = args.get("client_name", "VXIS Assessment")

    # Resolve findings for the scan_id
    results = await _handle_vxis_results({"scan_id": scan_id})

    target: str = results.get("target", "unknown")

    # Reconstruct Finding objects for the report generator
    try:
        from vxis.models.finding import Finding, Severity, FindingStatus
        from vxis.report.generator import ReportData, ReportGenerator
        from vxis.config.schema import VXISConfig
    except ImportError as exc:
        raise RuntimeError(f"VXIS report dependencies not available: {exc}") from exc

    findings: list[Finding] = []
    for raw in results.get("findings", []):
        try:
            sev_str = raw.get("severity", "informational")
            try:
                sev = Severity(sev_str)
            except ValueError:
                sev = Severity.informational

            finding = Finding(
                title=raw.get("title", "Unnamed Finding"),
                description=raw.get("description", ""),
                severity=sev,
                finding_type=raw.get("finding_type", "vulnerability"),
                target=raw.get("target", target),
                port=raw.get("port"),
                protocol=raw.get("protocol"),
                affected_component=raw.get("affected_component"),
                cve_ids=raw.get("cve_ids") or [],
                cwe_ids=raw.get("cwe_ids") or [],
                remediation=raw.get("remediation"),
                source_plugin=raw.get("source_plugin", "vxis"),
                confidence=raw.get("confidence", 0.8),
            )
            findings.append(finding)
        except Exception:
            # Skip malformed findings rather than aborting the whole report
            continue

    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    report_data = ReportData(
        scan_id=scan_id,
        client_name=client_name,
        target=target,
        scan_date=scan_date,
        findings=findings,
    )

    config = VXISConfig()
    output_dir = config.data_dir / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_filename = f"vxis_report_{scan_id[:8]}_{scan_date}.{fmt}"
    output_path = output_dir / output_filename

    generator = ReportGenerator()

    if fmt == "html":
        generated_path = generator.generate_html_file(report_data, output_path)
    else:
        # DOCX export — requires optional python-docx dependency
        try:
            from vxis.report.docx_export import DocxExporter

            exporter = DocxExporter()
            generated_path = exporter.export(report_data, output_path)
        except ImportError:
            raise RuntimeError(
                "DOCX export requires the 'export' optional dependency: "
                "pip install 'vxis[export]'"
            )

    return {
        "scan_id": scan_id,
        "format": fmt,
        "report_path": str(generated_path),
        "finding_count": len(findings),
        "message": (
            f"Report generated successfully: {generated_path.name} "
            f"({len(findings)} findings)"
        ),
    }


async def _handle_vxis_plugins(args: dict[str, Any]) -> dict[str, Any]:
    """Execute vxis_plugins tool: list available plugins with status."""
    category_filter: str | None = args.get("category")

    try:
        from vxis.plugins.registry import discover_plugins

        registry = discover_plugins()
    except Exception as exc:
        raise RuntimeError(f"Failed to discover plugins: {exc}") from exc

    plugins: list[dict[str, Any]] = []
    for name, plugin in sorted(registry.items()):
        meta = plugin.meta

        plugin_category = getattr(meta, "category", "unknown")
        if category_filter and plugin_category.lower() != category_filter.lower():
            continue

        available = plugin.validate_environment()
        plugins.append({
            "name": name,
            "category": plugin_category,
            "description": getattr(meta, "description", ""),
            "tier": getattr(meta, "tier", 1),
            "available": available,
            "tags": list(getattr(meta, "tags", [])),
        })

    available_count = sum(1 for p in plugins if p["available"])

    return {
        "total": len(plugins),
        "available": available_count,
        "unavailable": len(plugins) - available_count,
        "plugins": plugins,
        "summary": (
            f"{available_count}/{len(plugins)} plugins available"
            + (f" (category: {category_filter})" if category_filter else "")
        ),
    }


async def _handle_vxis_agent_scan(args: dict[str, Any]) -> dict[str, Any]:
    """Execute vxis_agent_scan tool: run autonomous AI-driven pentest."""
    target: str = args.get("target", "").strip()
    if not target:
        raise ValueError("'target' is required and must not be empty.")

    max_steps: int = int(args.get("max_steps", 15))
    profile: str = args.get("profile", "standard")

    if max_steps < 1 or max_steps > 50:
        raise ValueError("'max_steps' must be between 1 and 50.")

    try:
        from vxis.config.schema import VXISConfig
        from vxis.agent.executor import AgentExecutor

        config = VXISConfig()
        executor = AgentExecutor(config=config, max_steps=max_steps)
        result = await executor.run(target=target, profile=profile)
    except Exception as exc:
        raise RuntimeError(f"Agent scan failed: {exc}") from exc

    serialised_findings = [_serialise_finding(f) for f in result.findings]

    # Cache in store with a synthetic scan_id derived from target + timestamp
    import hashlib
    synthetic_id = hashlib.sha256(
        f"{target}-{result.duration_seconds}".encode()
    ).hexdigest()[:36]

    _scan_store[synthetic_id] = {
        "scan_id": synthetic_id,
        "target": target,
        "profile": profile,
        "findings": serialised_findings,
        "tool_runs": [],
        "errors": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": result.duration_seconds,
        "severity_counts": _count_severities(serialised_findings),
    }

    severity_counts = _count_severities(serialised_findings)

    return {
        "scan_id": synthetic_id,
        "target": target,
        "profile": profile,
        "steps_taken": result.steps_taken,
        "total_findings": len(result.findings),
        "severity_counts": severity_counts,
        "duration_seconds": round(result.duration_seconds, 1),
        "execution_log": result.execution_log,
        "findings": serialised_findings,
        "summary": (
            f"Agent scan of {target} completed in {result.duration_seconds:.0f}s "
            f"over {result.steps_taken} steps. "
            f"Found {len(result.findings)} findings "
            f"(critical={severity_counts.get('critical', 0)}, "
            f"high={severity_counts.get('high', 0)}, "
            f"medium={severity_counts.get('medium', 0)}, "
            f"low={severity_counts.get('low', 0)})."
        ),
    }


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _serialise_finding(finding: Any) -> dict[str, Any]:
    """Convert a Finding domain object to a plain JSON-serialisable dict."""
    return {
        "title": finding.title,
        "severity": finding.effective_severity.value,
        "description": finding.description or "",
        "target": finding.target or "",
        "port": finding.port,
        "protocol": finding.protocol or "",
        "affected_component": finding.affected_component or "",
        "cve_ids": list(finding.cve_ids or []),
        "cwe_ids": list(finding.cwe_ids or []),
        "cvss_score": finding.cvss.base_score if finding.cvss else None,
        "remediation": finding.remediation or "",
        "source_plugin": finding.source_plugin or "",
        "confidence": finding.confidence,
        "finding_type": finding.finding_type or "vulnerability",
        "discovered_at": (
            finding.discovered_at.isoformat()
            if finding.discovered_at
            else None
        ),
    }


def _count_severities(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity level, returning all five buckets."""
    counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
    for f in findings:
        sev = f.get("severity", "informational")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# JSON-RPC dispatcher
# ---------------------------------------------------------------------------

# Map tool names to their async handler coroutines
_TOOL_HANDLERS = {
    "vxis_scan": _handle_vxis_scan,
    "vxis_results": _handle_vxis_results,
    "vxis_report": _handle_vxis_report,
    "vxis_plugins": _handle_vxis_plugins,
    "vxis_agent_scan": _handle_vxis_agent_scan,
}


async def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    """Dispatch a single JSON-RPC request and return the response dict.

    Returns None for JSON-RPC notifications (requests without an 'id'),
    which must not receive a response per the spec.
    """
    req_id = request.get("id")
    method: str = request.get("method", "")

    # --- initialize ---
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": MCP_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
            },
        }

    # --- notifications/initialized (no response required) ---
    if method == "notifications/initialized":
        return None

    # --- tools/list ---
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS},
        }

    # --- tools/call ---
    if method == "tools/call":
        params: dict[str, Any] = request.get("params", {})
        tool_name: str = params.get("name", "")
        tool_args: dict[str, Any] = params.get("arguments") or {}

        handler = _TOOL_HANDLERS.get(tool_name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": METHOD_NOT_FOUND,
                    "message": (
                        f"Unknown tool '{tool_name}'. "
                        f"Available tools: {', '.join(_TOOL_HANDLERS)}"
                    ),
                },
            }

        try:
            result_data = await handler(tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result_data, indent=2, default=str),
                        }
                    ],
                    "isError": False,
                },
            }
        except (ValueError, TypeError) as exc:
            # Caller errors — surface as tool-level error content (not JSON-RPC error)
            # This allows the LLM to see the message and self-correct.
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Input error: {exc}",
                        }
                    ],
                    "isError": True,
                },
            }
        except Exception as exc:
            tb = traceback.format_exc()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Tool execution error: {exc}\n\n{tb}",
                        }
                    ],
                    "isError": True,
                },
            }

    # --- ping ---
    if method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {},
        }

    # --- unknown method ---
    if req_id is None:
        # Notification — silently ignore unknown methods
        return None

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {
            "code": METHOD_NOT_FOUND,
            "message": f"Method '{method}' not found.",
        },
    }


# ---------------------------------------------------------------------------
# Stdio transport loop
# ---------------------------------------------------------------------------


def _write_response(response: dict[str, Any]) -> None:
    """Serialise *response* to a single JSON line on stdout."""
    sys.stdout.write(json.dumps(response, default=str) + "\n")
    sys.stdout.flush()


def _write_error(req_id: Any, code: int, message: str) -> None:
    """Write a JSON-RPC error response to stdout."""
    _write_response(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }
    )


async def _async_main() -> None:
    """Async main loop: read JSON-RPC lines from stdin, write responses to stdout."""
    loop = asyncio.get_event_loop()

    # Use a ThreadPoolExecutor-backed reader so we do not block the event loop
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        try:
            raw_line = await reader.readline()
        except Exception:
            break

        if not raw_line:
            # EOF — client disconnected
            break

        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line:
            continue

        req_id: Any = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                _write_error(None, INVALID_REQUEST, "Request must be a JSON object.")
                continue

            req_id = request.get("id")
            response = await handle_request(request)
            if response is not None:
                _write_response(response)

        except json.JSONDecodeError as exc:
            _write_error(req_id, PARSE_ERROR, f"Parse error: {exc}")
        except Exception as exc:
            _write_error(req_id, INTERNAL_ERROR, f"Internal error: {exc}")


def main() -> None:
    """Entry point for the VXIS MCP server.

    Starts the asyncio event loop and runs the stdio JSON-RPC transport.
    Designed to be called by the ``vxis-mcp`` console script entry point
    or directly via ``python -m vxis.mcp_server``.
    """
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
