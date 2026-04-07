"""VXIS MCP Server — Brain-First primitive exposure.

External Brains (Claude Code Opus, etc.) connect via MCP JSON-RPC and call
VXIS primitives as tools. This server is **LLM-free**: it only dispatches to
pure primitive functions, Phase Registry lookups, and Scope Enforcement. The
reasoning lives in the external Brain.

Tool groups:
    sense_*    — HTTP/browser/traffic observation (sensing primitives)
    pattern_*  — regex-based vuln pattern detection
    kb_*       — knowledge base / CVE / WAF bypass lookups
    session_*  — authenticated session lifecycle
    ghost_*    — anonymity layer control
    chain_*    — attack chain graph algorithms
    output_*   — finding storage, scoring, report generation
    phase_*    — Phase Registry lookup (strategic guides)
    scope_*    — Scope & PII enforcement

Transport: JSON-RPC 2.0 over stdio (MCP 2024-11-05).

Usage:
    python -m vxis.mcp_server
    claude mcp add vxis python -m vxis.mcp_server
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import sys
import traceback
from dataclasses import asdict, is_dataclass
from typing import Any, Awaitable, Callable

# Silence library logs — stdout belongs to JSON-RPC.
logging.disable(logging.CRITICAL)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

MCP_VERSION = "2024-11-05"
SERVER_NAME = "vxis"
SERVER_VERSION = "0.2.0"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


# ---------------------------------------------------------------------------
# Lazy primitive imports — fail softly so a broken submodule doesn't kill MCP
# ---------------------------------------------------------------------------

def _lazy(path: str) -> Callable[..., Any]:
    """Return a function that imports and calls `path` on demand."""

    async def _call(**kwargs: Any) -> Any:
        mod_name, fn_name = path.rsplit(".", 1)
        mod = __import__(mod_name, fromlist=[fn_name])
        fn = getattr(mod, fn_name)
        result = fn(**kwargs)
        if inspect.isawaitable(result):
            result = await result
        return result

    return _call


# ---------------------------------------------------------------------------
# Tool specifications
#
# Each entry: (name, description, input_schema, handler)
# handler is an async callable that takes kwargs from the JSON-RPC arguments.
# ---------------------------------------------------------------------------

def _s(**props: Any) -> dict[str, Any]:
    """Shorthand: build a JSONSchema object with properties & optional required."""
    required = [k for k, v in props.items() if v.pop("_req", False)]
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def _p(
    type_: str,
    description: str,
    *,
    required: bool = False,
    default: Any = None,
    enum: list[Any] | None = None,
) -> dict[str, Any]:
    spec: dict[str, Any] = {"type": type_, "description": description, "_req": required}
    if default is not None:
        spec["default"] = default
    if enum is not None:
        spec["enum"] = enum
    return spec


TOOLS_SPEC: list[tuple[str, str, dict[str, Any], Callable[..., Awaitable[Any]]]] = [
    # ---- sensing ----
    (
        "sense_crawl",
        "Crawl a target and return discovered endpoints, forms, links, and tech stack. No LLM.",
        _s(
            target=_p("string", "Base URL of the target", required=True),
            depth=_p("integer", "Max link-follow depth 1-5", default=3),
            stealth_level=_p("integer", "1=fast, 5=very slow", default=3),
        ),
        _lazy("vxis.primitives.sensing.primitive_crawl"),
    ),
    (
        "sense_probe",
        "Send a single HTTP request via an existing session and return raw response (status/headers/body/timing).",
        _s(
            session_id=_p("string", "Session id from sense_crawl or session_create", required=True),
            method=_p("string", "HTTP verb", required=True),
            url=_p("string", "Absolute URL or path", required=True),
            headers=_p("object", "Optional extra headers"),
            body=_p("object", "Optional JSON body"),
            stealth_level=_p("integer", "1-5", default=3),
        ),
        _lazy("vxis.primitives.sensing.primitive_probe"),
    ),
    (
        "sense_fingerprint",
        "Fingerprint server/tech of a target URL.",
        _s(target=_p("string", "Target URL", required=True)),
        _lazy("vxis.primitives.sensing.primitive_fingerprint"),
    ),
    (
        "sense_subdomain_enum",
        "Enumerate subdomains for a root domain.",
        _s(domain=_p("string", "Root domain, e.g. example.com", required=True)),
        _lazy("vxis.primitives.sensing.primitive_subdomain_enum"),
    ),
    (
        "sense_screenshot",
        "Capture a rendered screenshot of a URL. Returns file path.",
        _s(
            url=_p("string", "URL to render", required=True),
            viewport=_p("string", "WxH viewport", default="1920x1080"),
        ),
        _lazy("vxis.primitives.sensing.primitive_screenshot"),
    ),
    (
        "sense_xray_start",
        "Start a passive traffic interception session (X-Ray). Returns session id.",
        _s(target=_p("string", "Target base URL", required=True)),
        _lazy("vxis.primitives.sensing.primitive_xray_start"),
    ),
    (
        "sense_xray_flows",
        "Retrieve captured flows from an X-Ray session.",
        _s(
            session_id=_p("string", "X-Ray session id", required=True),
            filter=_p("string", "Filter expression", default=""),
        ),
        _lazy("vxis.primitives.sensing.primitive_xray_flows"),
    ),
    # ---- patterns ----
    (
        "pattern_detect_sql",
        "Regex-based SQL injection detector. Returns {detected, confidence, evidence}.",
        _s(
            response_body=_p("string", "Response body text", required=True),
            status=_p("integer", "HTTP status code", required=True),
        ),
        _lazy("vxis.primitives.patterns.detect_sql_injection"),
    ),
    (
        "pattern_detect_xss",
        "Reflected XSS detector.",
        _s(
            response_body=_p("string", "Response body", required=True),
            payload=_p("string", "Injected payload", required=True),
        ),
        _lazy("vxis.primitives.patterns.detect_xss_reflection"),
    ),
    (
        "pattern_detect_path_traversal",
        "Path traversal detector.",
        _s(response_body=_p("string", "Response body", required=True)),
        _lazy("vxis.primitives.patterns.detect_path_traversal"),
    ),
    (
        "pattern_detect_ssrf",
        "SSRF detector (status + timing heuristic).",
        _s(
            response_body=_p("string", "Response body", required=True),
            status=_p("integer", "HTTP status", required=True),
            timing_ms=_p("integer", "Request timing in ms", required=True),
        ),
        _lazy("vxis.primitives.patterns.detect_ssrf"),
    ),
    (
        "pattern_detect_waf",
        "WAF fingerprint detector. Returns {waf_type, confidence}.",
        _s(
            response_body=_p("string", "Response body", required=True),
            status=_p("integer", "HTTP status", required=True),
            headers=_p("object", "Response headers", required=True),
        ),
        _lazy("vxis.primitives.patterns.detect_waf"),
    ),
    (
        "pattern_extract_secrets",
        "Extract API keys / tokens / JWTs from arbitrary text.",
        _s(text=_p("string", "Text to scan", required=True)),
        _lazy("vxis.primitives.patterns.extract_secrets"),
    ),
    (
        "pattern_parse_forms",
        "Parse HTML forms from a page.",
        _s(html_text=_p("string", "HTML content", required=True)),
        _lazy("vxis.primitives.patterns.parse_forms"),
    ),
    (
        "pattern_parse_openapi",
        "Parse an OpenAPI / Swagger spec.",
        _s(spec_text=_p("string", "OpenAPI JSON or YAML", required=True)),
        _lazy("vxis.primitives.patterns.parse_openapi"),
    ),
    # ---- knowledge ----
    (
        "kb_query",
        "Query the vector/vuln knowledge base by tech stack.",
        _s(
            tech_stack=_p("array", "List of tech stack tokens", required=True),
            vuln_type=_p("string", "Optional vuln type filter", default=""),
        ),
        _lazy("vxis.primitives.knowledge.query_kb"),
    ),
    (
        "kb_list_vectors",
        "List available attack vectors, optionally filtered by category/phase.",
        _s(
            category=_p("string", "Category filter", default=""),
            phase=_p("string", "Phase filter", default=""),
        ),
        _lazy("vxis.primitives.knowledge.list_vectors"),
    ),
    (
        "kb_get_vector_payloads",
        "Get payloads registered for a specific attack vector id.",
        _s(vector_id=_p("string", "Attack vector id", required=True)),
        _lazy("vxis.primitives.knowledge.get_vector_payloads"),
    ),
    (
        "kb_cve_lookup",
        "Look up CVEs for a product (+optional version).",
        _s(
            product=_p("string", "Product name", required=True),
            version=_p("string", "Version", default=""),
        ),
        _lazy("vxis.primitives.knowledge.cve_lookup"),
    ),
    (
        "kb_waf_bypass",
        "Return WAF bypass variants of a payload for a given WAF type (269 variants across 8 WAFs).",
        _s(
            original_payload=_p("string", "Original payload", required=True),
            waf_type=_p("string", "WAF type (cloudflare, akamai, aws, ...)", required=True),
        ),
        _lazy("vxis.primitives.knowledge.get_waf_bypass_variants"),
    ),
    # ---- session ----
    (
        "session_create",
        "Create a new authenticated session for a target.",
        _s(
            target=_p("string", "Target base URL", required=True),
            auth_type=_p("string", "Auth type", default="none"),
            credentials=_p("object", "Auth credentials dict"),
        ),
        _lazy("vxis.primitives.session.session_create"),
    ),
    (
        "session_get",
        "Get an existing session id for a target.",
        _s(target=_p("string", "Target URL", required=True)),
        _lazy("vxis.primitives.session.session_get"),
    ),
    (
        "session_list",
        "List all active sessions.",
        _s(),
        _lazy("vxis.primitives.session.session_list"),
    ),
    (
        "session_close",
        "Close a session.",
        _s(session_id=_p("string", "Session id", required=True)),
        _lazy("vxis.primitives.session.session_close"),
    ),
    # ---- ghost ----
    (
        "ghost_activate",
        "Activate Ghost Layer anonymization (mandatory for non-P0 phases).",
        _s(profile=_p("string", "Ghost profile", default="standard")),
        _lazy("vxis.primitives.ghost.ghost_activate"),
    ),
    (
        "ghost_verify",
        "Verify Ghost Layer is active and IP is anonymized.",
        _s(),
        _lazy("vxis.primitives.ghost.ghost_verify"),
    ),
    (
        "ghost_status",
        "Return current Ghost Layer status.",
        _s(),
        _lazy("vxis.primitives.ghost.ghost_status"),
    ),
    # ---- chain ----
    (
        "chain_graph",
        "Build a chain graph from findings (pure graph algorithm, no LLM).",
        _s(findings=_p("array", "List of finding dicts", required=True)),
        _lazy("vxis.primitives.chain.chain_graph_from_findings"),
    ),
    (
        "chain_score",
        "Score an attack chain.",
        _s(chain=_p("array", "Ordered list of finding dicts", required=True)),
        _lazy("vxis.primitives.chain.chain_score"),
    ),
    (
        "chain_link",
        "Record a manual chain link between two findings.",
        _s(
            from_finding_id=_p("string", "Source finding id", required=True),
            to_finding_id=_p("string", "Target finding id", required=True),
            reasoning=_p("string", "Why the link", required=True),
        ),
        _lazy("vxis.primitives.chain.chain_link"),
    ),
    # ---- output ----
    (
        "output_finding_add",
        "Persist a finding for a scan. Returns finding id.",
        _s(
            scan_id=_p("string", "Scan id", required=True),
            finding_data=_p("object", "Finding dict", required=True),
        ),
        _lazy("vxis.primitives.output.finding_add"),
    ),
    (
        "output_finding_list",
        "List findings for a scan.",
        _s(
            scan_id=_p("string", "Scan id", required=True),
            min_severity=_p("string", "Minimum severity", default="informational"),
        ),
        _lazy("vxis.primitives.output.finding_list"),
    ),
    (
        "output_score",
        "Compute score for a scan's findings.",
        _s(scan_id=_p("string", "Scan id", required=True)),
        _lazy("vxis.primitives.output.score_compute"),
    ),
    (
        "output_report",
        "Generate NCC-style HTML report for a scan. Returns file path.",
        _s(
            scan_id=_p("string", "Scan id", required=True),
            template=_p("string", "Report template", default="ncc_group"),
        ),
        _lazy("vxis.primitives.output.report_generate"),
    ),
]


# ---------------------------------------------------------------------------
# Non-primitive tools — phase registry & scope enforcement
# ---------------------------------------------------------------------------

async def _tool_phase_list(**_: Any) -> Any:
    from vxis.phases.registry import EXECUTION_ORDER, PHASE_REGISTRY

    out = []
    for pid in EXECUTION_ORDER:
        g = PHASE_REGISTRY.get(pid)
        if g is None:
            continue
        out.append(
            {
                "id": g.id,
                "name_en": g.name_en,
                "name_ko": g.name_ko,
                "parallel_group": g.parallel_group,
                "depends_on": list(g.depends_on),
            }
        )
    return {"phases": out, "total": len(out)}


async def _tool_phase_get(phase_id: str) -> Any:
    from vxis.phases.registry import PHASE_REGISTRY

    g = PHASE_REGISTRY.get(phase_id)
    if g is None:
        raise ValueError(f"Unknown phase id: {phase_id}")
    return {
        "id": g.id,
        "name_en": g.name_en,
        "name_ko": g.name_ko,
        "objective_en": g.objective_en,
        "objective_ko": g.objective_ko,
        "strategic_advice_en": g.strategic_advice_en,
        "strategic_advice_ko": g.strategic_advice_ko,
        "crown_hint_en": getattr(g, "crown_hint_en", ""),
        "crown_hint_ko": getattr(g, "crown_hint_ko", ""),
        "recommended_primitives": list(g.recommended_primitives),
        "dead_end_criteria": [
            {
                "id": c.id,
                "description_en": c.description_en,
                "description_ko": c.description_ko,
            }
            for c in g.dead_end_criteria
        ],
        "parallel_group": g.parallel_group,
        "depends_on": list(g.depends_on),
    }


async def _tool_phase_validate(**_: Any) -> Any:
    from vxis.phases.registry import validate_dependencies

    issues = validate_dependencies()
    return {"valid": not issues, "issues": issues}


async def _tool_scope_check_url(url: str, action: str = "read") -> Any:
    from vxis.scope import ScopeEnforcer, load_scope

    scope = load_scope()
    enforcer = ScopeEnforcer(scope)
    result = enforcer.check_url(url, action=action)
    return _to_dict(result)


async def _tool_scope_check_action(action: str, target: str = "") -> Any:
    from vxis.scope import ScopeEnforcer, load_scope

    scope = load_scope()
    enforcer = ScopeEnforcer(scope)
    result = enforcer.check_action(action, target=target)
    return _to_dict(result)


async def _tool_scope_check_pii(text: str) -> Any:
    from vxis.scope import PIIDetector

    detection = PIIDetector().scan(text)
    return {
        "contains_pii": detection.found,
        "types": list(detection.types),
        "matches": detection.matches,
    }


async def _tool_scope_redact(text: str) -> Any:
    from vxis.scope import PIIDetector

    detection = PIIDetector().scan(text)
    return {
        "redacted": detection.redacted_text,
        "contains_pii": detection.found,
        "types": list(detection.types),
    }


NON_PRIMITIVE_TOOLS: list[tuple[str, str, dict[str, Any], Callable[..., Awaitable[Any]]]] = [
    (
        "phase_list",
        "List all Phase Guides in execution order (Brain-First strategic playbook).",
        _s(),
        _tool_phase_list,
    ),
    (
        "phase_get",
        "Fetch the full strategic guide for a Phase id (objective, advice, primitives, dead-end criteria).",
        _s(phase_id=_p("string", "Phase id e.g. P4_cpr", required=True)),
        _tool_phase_get,
    ),
    (
        "phase_validate",
        "Validate Phase Registry dependency graph.",
        _s(),
        _tool_phase_validate,
    ),
    (
        "scope_check_url",
        "Check whether a URL is in-scope for an action.",
        _s(
            url=_p("string", "URL to check", required=True),
            action=_p("string", "Action (read/probe/inject)", default="read"),
        ),
        _tool_scope_check_url,
    ),
    (
        "scope_check_action",
        "Check whether an action is permitted by the current scope policy.",
        _s(
            action=_p("string", "Action name", required=True),
            target=_p("string", "Optional target", default=""),
        ),
        _tool_scope_check_action,
    ),
    (
        "scope_check_pii",
        "Detect PII in arbitrary text (emails, SSNs, credit cards, JWTs, ...).",
        _s(text=_p("string", "Text to scan", required=True)),
        _tool_scope_check_pii,
    ),
    (
        "scope_redact",
        "Redact detected PII from text.",
        _s(text=_p("string", "Text to redact", required=True)),
        _tool_scope_redact,
    ),
]


ALL_TOOLS = TOOLS_SPEC + NON_PRIMITIVE_TOOLS


# ---------------------------------------------------------------------------
# Build tools/list payload & dispatch table
# ---------------------------------------------------------------------------

def _clean_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Strip internal `_req` markers before publishing."""
    cleaned: dict[str, Any] = {"type": schema.get("type", "object")}
    props = {}
    for name, spec in schema.get("properties", {}).items():
        props[name] = {k: v for k, v in spec.items() if k != "_req"}
    cleaned["properties"] = props
    if "required" in schema:
        cleaned["required"] = schema["required"]
    return cleaned


TOOLS: list[dict[str, Any]] = [
    {
        "name": name,
        "description": description,
        "inputSchema": _clean_schema(schema),
    }
    for (name, description, schema, _handler) in ALL_TOOLS
]

_HANDLERS: dict[str, Callable[..., Awaitable[Any]]] = {
    name: handler for (name, _d, _s2, handler) in ALL_TOOLS
}


def _to_dict(obj: Any) -> Any:
    """Best-effort JSON serialisation for dataclass / pydantic / plain objects."""
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_dict(v) for v in obj]
    if is_dataclass(obj):
        return _to_dict(asdict(obj))
    if hasattr(obj, "model_dump"):  # pydantic v2
        return obj.model_dump()
    if hasattr(obj, "dict"):  # pydantic v1
        try:
            return obj.dict()
        except Exception:
            pass
    if hasattr(obj, "__dict__"):
        return {k: _to_dict(v) for k, v in obj.__dict__.items() if not k.startswith("_")}
    return str(obj)


# ---------------------------------------------------------------------------
# JSON-RPC dispatcher
# ---------------------------------------------------------------------------

async def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    req_id = request.get("id")
    method: str = request.get("method", "")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": MCP_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        params: dict[str, Any] = request.get("params", {})
        tool_name: str = params.get("name", "")
        tool_args: dict[str, Any] = params.get("arguments") or {}

        handler = _HANDLERS.get(tool_name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": METHOD_NOT_FOUND,
                    "message": f"Unknown tool '{tool_name}'. Available: {', '.join(sorted(_HANDLERS))}",
                },
            }

        try:
            result_data = await handler(**tool_args)
            payload = _to_dict(result_data)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {"type": "text", "text": json.dumps(payload, indent=2, default=str)}
                    ],
                    "isError": False,
                },
            }
        except (ValueError, TypeError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Input error: {exc}"}],
                    "isError": True,
                },
            }
        except Exception as exc:
            tb = traceback.format_exc()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": f"Tool execution error: {exc}\n\n{tb}"}],
                    "isError": True,
                },
            }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if req_id is None:
        return None

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": METHOD_NOT_FOUND, "message": f"Method '{method}' not found."},
    }


# ---------------------------------------------------------------------------
# Stdio transport loop
# ---------------------------------------------------------------------------

def _write_response(response: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(response, default=str) + "\n")
    sys.stdout.flush()


def _write_error(req_id: Any, code: int, message: str) -> None:
    _write_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


async def _async_main() -> None:
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    while True:
        try:
            raw_line = await reader.readline()
        except Exception:
            break

        if not raw_line:
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
    """Entry point: ``python -m vxis.mcp_server`` or ``vxis-mcp``."""
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
