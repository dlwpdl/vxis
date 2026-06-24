from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

HIGH_SEVERITIES = {"critical", "high"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_REQUEST_LINE_RE = re.compile(
    r"(?im)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)(?:\s+HTTP/\d(?:\.\d)?)?\s*$"
)
_SKIP_MARKER_PREFIXES = (
    "get ",
    "post ",
    "put ",
    "patch ",
    "delete ",
    "head ",
    "options ",
    "host:",
    "http/",
    "negative",
    "control",
    "repeat_count",
)


def replay_gate_passed(finding: dict[str, Any]) -> bool:
    if str(finding.get("severity", "")).lower() not in HIGH_SEVERITIES:
        return True
    gate = finding.get("replay_gate")
    gate_passed = isinstance(gate, dict) and str(gate.get("status", "")).lower() == "passed"
    confirmed = (
        str(finding.get("status", "")).lower() == "confirmed"
        or str(finding.get("verifier_verdict", "")).upper() == "CONFIRMED"
        or bool(finding.get("verified"))
    )
    return gate_passed and confirmed


def blocking_replay_gate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    for finding in findings:
        if replay_gate_passed(finding):
            continue
        gate = finding.get("replay_gate")
        blockers.append(
            {
                "id": str(finding.get("id", "")),
                "title": str(finding.get("title", ""))[:120],
                "severity": str(finding.get("severity", "")),
                "replay_gate_status": str(gate.get("status", "")) if isinstance(gate, dict) else "",
                "verifier_verdict": str(finding.get("verifier_verdict", "")),
            }
        )
    return blockers


def _base_url(target: str) -> str:
    parsed = urlparse(str(target or ""))
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def parse_raw_http_requests(text: str, target: str) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    text = str(text or "").replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    matches = list(_REQUEST_LINE_RE.finditer(str(text or "")))
    base_url = _base_url(target)
    for index, match in enumerate(matches):
        block_end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[match.start() : block_end]
        method = match.group(1).upper()
        raw_target = match.group(2).strip()
        header_blob, _, body_blob = block.partition("\n\n")
        if not body_blob:
            header_blob, _, body_blob = block.partition("\r\n\r\n")
        headers: dict[str, str] = {}
        for line in header_blob.splitlines()[1:]:
            name, sep, value = line.partition(":")
            if sep and name.strip().lower() not in {"host", "content-length"}:
                headers[name.strip()] = value.strip()
        body = re.split(r"(?im)^\s*HTTP/\d(?:\.\d)?\s+\d{3}\b", body_blob, maxsplit=1)[0].strip()
        args: dict[str, Any] = {"method": method, "headers": headers}
        parsed = urlparse(raw_target)
        if parsed.scheme and parsed.netloc:
            args["url"] = raw_target
        elif base_url:
            args["base_url"] = base_url
            args["path"] = raw_target if raw_target.startswith("/") else f"/{raw_target}"
        else:
            continue
        if body and method not in {"GET", "HEAD", "OPTIONS"}:
            args["data"] = body
        requests.append(args)
    return requests


def _candidate_markers(*values: Any) -> list[str]:
    seen: set[str] = set()
    markers: list[str] = []
    for value in values:
        for line in str(value or "").splitlines():
            marker = line.strip()
            lower = marker.lower()
            if len(marker) < 4 or lower.startswith(_SKIP_MARKER_PREFIXES):
                continue
            if not any(token in lower for token in ("<", "{", "token", "session", "admin", "error", "uid=", "role")):
                continue
            marker = marker[:160]
            if marker not in seen:
                seen.add(marker)
                markers.append(marker)
    return markers[:8]


async def machine_replay_gate(
    *,
    finding: dict[str, Any],
    target: str,
    dispatch: Any,
) -> dict[str, Any]:
    severity = str(finding.get("severity", "")).lower()
    if severity not in HIGH_SEVERITIES:
        return {}
    if not callable(dispatch):
        return {"status": "blocked_oracle", "method": "machine_http", "reason": "no dispatch"}

    control_requests = parse_raw_http_requests(str(finding.get("control_comparison", "")), target)
    replay_requests = parse_raw_http_requests(
        "\n\n".join(
            str(finding.get(key, ""))
            for key in ("request_or_payload", "replay_command", "poc_script_code")
            if finding.get(key)
        ),
        target,
    )
    if not control_requests and len(replay_requests) >= 2:
        control_requests = [replay_requests[0]]
    if not replay_requests or not control_requests:
        return {"status": "blocked_oracle", "method": "machine_http", "reason": "missing raw control/replay request"}

    control_args = control_requests[0]
    replay_args = replay_requests[-1]
    if str(control_args.get("method", "")).upper() not in SAFE_METHODS or str(replay_args.get("method", "")).upper() not in SAFE_METHODS:
        return {"status": "blocked_policy", "method": "machine_http", "reason": "unsafe method requires operator policy"}

    control = await dispatch("http_request", control_args)
    replay = await dispatch("http_request", replay_args)
    control_data = getattr(control, "data", {}) if getattr(control, "ok", False) else {}
    replay_data = getattr(replay, "data", {}) if getattr(replay, "ok", False) else {}
    control_status = int(control_data.get("status") or 0)
    replay_status = int(replay_data.get("status") or 0)
    control_body = str(control_data.get("body_preview", ""))
    replay_body = str(replay_data.get("body_preview", ""))
    matched = [
        marker
        for marker in _candidate_markers(finding.get("response_or_effect"), finding.get("poc_script_code"))
        if marker in replay_body and marker not in control_body
    ]
    passed = bool(getattr(control, "ok", False) and getattr(replay, "ok", False)) and (
        bool(matched) or (control_status and replay_status and control_status != replay_status)
    )
    return {
        "status": "passed" if passed else "failed",
        "method": "machine_http",
        "control_status": control_status,
        "replay_status": replay_status,
        "matched_markers": matched,
        "reason": "status_or_marker_delta" if passed else "no status or marker delta",
    }
