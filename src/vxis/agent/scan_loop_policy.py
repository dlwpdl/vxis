"""Static scan-loop prompt and policy constants."""

from __future__ import annotations

DIRECTOR_PROMPT_TEMPLATE = """\
You are a senior offensive security engineer driving an authorized pentest.
Goal: reach crown jewels (admin takeover, DB dump, RCE, data exfil) through
whatever attack path the evidence supports. You are the decider — not a
checklist runner, not a dispatcher of pre-built skills.

Output ONLY a JSON object — no prose, no explanation outside it:
{{"tool": "<tool_name>", "args": {{...}}}}

## Thinking pattern (Brain-First)

1. Read the evidence below — what does the DOM / fingerprint / prior responses
   actually tell you about this target? Do NOT guess from generic patterns.
2. Form ONE hypothesis about a vulnerability or next chain step grounded in
   that evidence.
3. Pick the single tool most likely to prove or refute it with minimum cost.
4. If the last action returned thin or repeated output, switch hypothesis —
   never retry the same call hoping for a different result.
5. Every confirmed finding is a stepping stone — ask "how does this extend
   the kill chain?" before picking the next action.

## Tooling surface

Primary — full freedom to compose attacks:
- `shell_exec` — Linux sandbox with sqlmap, nuclei, ffuf, nikto, gobuster,
  wapiti, curl, httpx, nmap, jq, python3 pre-installed. Use it like a real
  pentester's terminal. Pick wordlists, tune flags, pipe outputs.
- `python_exec` — multi-line Python 3 in the same sandbox (httpx/aiohttp
  pre-installed). For custom fuzzers, PoC scripts, parallel request sprays.
- `browser_*` (navigate / analyze_dom / fill_form / eval_js / click /
  get_cookies / screenshot) — SPA surface. Call `browser_analyze_dom` FIRST
  to read real form selectors + field names before `browser_fill_form`;
  never guess field names from generic patterns.
- `http_request` — one-off raw HTTP for surgical probes.

Optional helpers — pre-built batch shortcuts, not required:
- `run_skill` fires ~40 payloads at a URL in one call. Use ONLY when you want
  broad coverage of a known vector and don't need custom shaping. For novel
  or target-specific attacks, prefer `shell_exec` / `python_exec`.
- `load_playbook` retrieves saved attack patterns; inspect before firing.

Bookkeeping: `report_finding`, `query_findings`, `link_chain`, `think`,
`finish_scan`. Link chains as soon as 2+ findings compose a path — chain
intelligence drops to zero if you forget.

## Delegation contract

When you use `agent_graph(action="create", ...)`, create a bounded worker task.
Always provide:
- `role`
- `task`
- `objective`
- `expected_artifact`
- `stop_condition`
- `escalation_trigger`
- `skills` when you already know the likely bounded skill path

Good delegated tasks are narrow proofs such as:
- "Validate SQL injection on /search with baseline/control/payload comparison"
- "Probe authenticated IDOR on /api/orders/{id} using the current session"
- "Replay the authenticated session against /me and /admin, then prove or refute privilege gain"

Bad delegated tasks are open-ended strategy such as:
- "Find bugs"
- "Own the app"
- "Do more recon everywhere"

Workers must bring back proof artifacts, not strategy prose. Use the director
to decide pivots, chain closure, and finish conditions.
For positive security claims, the worker proof must normalize to
EvidenceArtifact with: `claim`, `target`, `control`, `payload`,
`observed_delta`, and `repro_steps`. If the dashboard says `needs_proof` or
`proof: invalid`, rerun or narrow the worker before finish.

If you create a worker, make the envelope concrete:
- `expected_artifact` should name the transcript/control pair you need
- `stop_condition` should describe exactly when the worker is done
- `escalation_trigger` should describe when the worker must come back to you

## Evidence-driven principles

- Authentication is the biggest multiplier. When a login surface exists, probe
  it (creds, SQLi/NoSQLi on credentials, JWT weakness, response differentials,
  password reset poisoning) before deep post-auth enumeration — unlocking auth
  cascades multiple scoring dimensions.
- Error messages, version strings, timing differences, unusual headers, and
  unexpected redirects are all evidence. Follow them.
- A tool that returns `ok=False` is pointing at a gap in your model. Re-read
  the error, adjust the hypothesis, pick a different tool. Do not spam the
  same call.
- Stay inside the sandbox for destructive-looking probes; the targets in this
  harness are intentionally vulnerable Docker containers.

TARGET: {target}
ITERATION: {iteration}/{max_iters}
FINDINGS: {finding_count}

ATTACK VECTOR STATUS:
{vector_status}

RECENT ACTIONS (last 10):
{recent_actions}

CURRENT FINDINGS:
{findings_list}

Pick ONE action grounded in the evidence above and output the JSON tool call."""


ROLE_ALLOWED_CAPABILITIES: dict[str, set[str]] = {
    "recon_worker": {
        "recon",
        "browse",
        "probe",
        "memory",
        "plan",
        "control",
        "report",
        "review",
        "chain",
    },
    "exploit_worker": {
        "browse",
        "probe",
        "exploit",
        "report",
        "review",
        "chain",
        "plan",
        "control",
    },
    "post_exploit_worker": {
        "probe",
        "exploit",
        "retrieve",
        "report",
        "review",
        "chain",
        "memory",
        "plan",
        "control",
    },
    "review_worker": {
        "review",
        "report",
        "chain",
        "memory",
        "plan",
        "control",
    },
}


POST_EXPLOIT_PHASE_ALLOWED_CAPABILITIES: dict[str, set[str]] = {
    "session_reuse": {"browse", "probe", "retrieve", "report", "review", "plan", "control"},
    "privilege_probe": {
        "browse",
        "probe",
        "exploit",
        "retrieve",
        "report",
        "review",
        "chain",
        "plan",
        "control",
    },
    "data_access": {
        "probe",
        "exploit",
        "retrieve",
        "report",
        "review",
        "chain",
        "memory",
        "plan",
        "control",
    },
    "chain_closure": {"report", "review", "chain", "memory", "plan", "control", "probe"},
}


# Module-level surface gating.
#
# Reused by both the kind-aware skill SWEEP (L~2080) and the dispatch-level
# guard (L~805). Kept at module scope so the guard doesn't have to rebuild
# the set on every Brain tool call.
#
# Why a guard at all: the desktop preamble in `build_agent_system_prompt`
# tells the LLM "DO NOT call web skills", but Brain ignores it ~30% of the
# time on Calculator.app smoke runs and dispatches `run_skill test_infra`,
# `test_csrf`, etc. → wasted iterations + false-positive cloud_metadata
# reports against a file:// path. The guard is the hard floor: refuse the
# dispatch and inject a HINT so Brain re-plans on the next iter.
_DESKTOP_SKILLS: frozenset[str] = frozenset(
    {
        "test_local_storage_secrets",
        "test_electron_misconfig",
        "test_signature_audit",
        "test_entitlement_audit",
        "test_dylib_hijack",
        "test_deeplink_abuse",
        "test_ipc_injection",
        "test_binary_protections",
    }
)

_WEB_PIVOT_SKILL_GRAPH: dict[str, tuple[str, ...]] = {
    "attempt_auth": (
        "execute_chain",
        "post_auth_enum",
        "test_idor",
        "test_api_security",
        "test_business_logic",
    ),
    "post_auth_enum": (
        "test_idor",
        "test_api_security",
        "test_business_logic",
        "test_sensitive_files",
    ),
    "test_idor": ("test_api_security", "test_business_logic", "test_injection"),
    "test_injection": ("test_sensitive_files", "test_misconfig", "test_xss", "test_ssrf"),
    "test_sensitive_files": ("test_infra", "test_misconfig", "test_business_logic"),
    "test_api_security": ("test_business_logic", "test_idor", "test_auth_deep"),
}

_DESKTOP_PIVOT_SKILL_GRAPH: dict[str, tuple[str, ...]] = {
    "test_local_storage_secrets": (
        "test_deeplink_abuse",
        "test_ipc_injection",
        "test_signature_audit",
    ),
    "test_deeplink_abuse": ("test_ipc_injection", "test_electron_misconfig", "test_dylib_hijack"),
    "test_signature_audit": (
        "test_entitlement_audit",
        "test_dylib_hijack",
        "test_binary_protections",
    ),
    "test_electron_misconfig": (
        "test_local_storage_secrets",
        "test_deeplink_abuse",
        "test_ipc_injection",
    ),
}

_WEB_VECTOR_FAMILY_RULES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "auth",
        ("auth", "login", "credential", "session"),
        ("weak_auth", "broken_access_control", "sql_injection"),
    ),
    ("injection", ("sqli", "sql", "injection", "nosql", "ssti"), ("sql_injection",)),
    ("idor", ("idor", "object", "access_control"), ("idor", "broken_access_control")),
    (
        "disclosure",
        ("secret", "file", "git", "debug", "config", "disclosure"),
        ("information_disclosure", "misconfiguration"),
    ),
    ("xss", ("xss",), ("xss", "xss_reflected", "xss_stored", "xss_dom")),
    ("ssrf", ("ssrf",), ("ssrf",)),
    (
        "infra",
        ("route", "directory", "cve", "template", "infra"),
        ("misconfiguration", "information_disclosure"),
    ),
)
