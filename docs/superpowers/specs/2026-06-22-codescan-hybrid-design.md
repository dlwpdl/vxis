# VXIS Hybrid White-box Codescan Engine — Design (2026-06-22)

## Context

VXIS Agent Mode is black-box only: it takes a URL and attacks the running app.
A repo path was treated as a web URL and failed preflight (fixed in L1,
`infer_target_kind`). This spec is **L2**: a hybrid white-box engine that reads
source to find candidate vulnerabilities, then **dynamically verifies** each one
against the running app — only verified findings are reported. This matches
Strix's `--target ./dir` flow and is the project's named incubator candidate
(`incubator/README.md`: "CODE/white-box Brain tools").

Decisions locked in brainstorming (2026-06-22):

- **Architecture: adaptive hybrid.** A cheap deterministic pre-pass always
  produces candidates (local-LLM / cost friendly); the Brain deep-dives with
  source-aware tools only when budget allows (cloud); a dynamic skill verifies
  each candidate against the URL. Ties to the dual-mode cost-governor.
- **MVP: one complete vertical slice** — `path + url → candidates → dynamic
  verify → confirmed findings`.
- **First (and for now only) target: OWASP Juice Shop (Node/Express/TS).**
  `cloud-api` (the user's real Clojure product) is explicitly **out of scope** —
  pointing an immature active-verification engine at production is unacceptable.
  juice-shop is a disposable benchmark and may be attacked at full strength.
- **Lives in `incubator/codescan/`** until the slice is complete + tested, then
  promoted into `src/vxis/` and the L1 code/hybrid gate is flipped.

## Goal

Clone-or-path a repo + give a running URL → VXIS finds a vulnerability in the
source, proves it over HTTP, and reports a verified finding that carries **both**
the dynamic PoC and the source `file:line` lineage. Demonstrated end-to-end on
the juice-shop `/rest/products/search` SQL injection.

## Scope

**In:** Node/Express(TypeScript) static analysis (routes + sinks), the hybrid
loop, dynamic verification via existing skills, the juice-shop integration test.

**Out (deferred / not now):** Clojure/Python/other analyzers (interface is
pluggable, but only `NodeAnalyzer` is built); the Brain source-aware deep-dive
tools beyond a minimal read (phase 2 within incubator); POST-body / header sink
verification (existing skills are GET-querystring only — see Risks); wiring into
live Agent Mode (stays gated until promotion); `cloud-api` and any non-benchmark
target.

## Architecture

```
repo(+url)
  → CodeRecon.fingerprint        (REUSE: detects Node/Express, multi-lang)
  → Analyzer registry [NodeAnalyzer]  (NEW: routes + sinks → candidates)
  → CodeCandidate[]              (NEW DTO: + source_ref file:line)
  → prioritize (confidence_hint, crown-jewel potential)
  → [cost-governor] deep-dive?  (cloud: Brain read_code to confirm sink; local: skip)
  → endpoint_map: candidate → concrete url + param_name (or url_pattern{id})
  → dynamic skill (PATH A: SKILL_REGISTRY[name]['fn'](url=, param_name=, round=))
  → _verify_and_gate → verify_finding + report_finding store contract
  → confirmed finding  (dynamic PoC = primary evidence; source_ref = extra_evidence)
```

Invariant (kept, structurally): **code analysis never reports a finding
directly — a dynamic surface must confirm it.** Code only emits *unverified*
candidates; the source `file:line` rides along as corroboration and attaches to
the finding only after dynamic confirmation.

## Components (`incubator/codescan/`)

Each unit has one purpose, a clear interface, and stated dependencies.

1. **`recon.py`** — thin wrapper over the existing `CodeRecon.fingerprint`
   (`src/vxis/interaction/code/code_recon.py`, works today, no new deps).
   In: repo path → `Target(kind=CODE)`. Out: `ReconReport` (tech fingerprint +
   manifest/openapi/secret/dockerfile components).

2. **`candidate.py`** — `CodeCandidate` DTO. Extends today's `CodeHypothesis`
   (`code_to_hypothesis.py:34`) with `source_ref: str` (`file:line`) and
   `sink_param: str | None`. Fields: `description_en/ko`, `target_endpoint`,
   `http_method`, `sink_param`, `vector_id_candidate`, `source_ref`,
   `confidence_hint`, `status="unverified"`, `source=TargetKind.CODE`.

3. **`analyzer.py`** — `Analyzer` ABC + registry keyed by tech label.
   `analyze(repo, recon) -> list[CodeCandidate]`. Lets future Clojure/Python
   analyzers plug in without touching the loop.

4. **`node_analyzer.py`** — `NodeAnalyzer(Analyzer)`. Uses `CodeHands`
   (read/grep/glob, traversal-safe) to:
   - parse `server.ts` route registry: `app.<method>('<path>', <handler>)` +
     `finale.resource({endpoints:['/api/<Model>s','/api/<Model>s/:id']})`
     auto-CRUD; record method, path, `:params`, and `security.isAuthorized()`
     auth coupling;
   - resolve `<handler>` → `routes/<file>.ts` factory; grep the sink patterns
     (raw `sequelize.query(\`...${req.*}...\`)` → SQLi; MarsDB `.find/.update`
     with req object → NoSQLi; `res.send/json` echo → XSS; `sendFile`/static →
     path traversal; req-derived http client → SSRF; `req.params.id`→db w/o JWT
     → IDOR);
   - emit a `CodeCandidate` per (route, taint-source, sink) with `source_ref`,
     `target_endpoint`, `sink_param`, and a `vector_id_candidate` → skill name.

5. **`endpoint_map.py`** — the missing glue. Maps a candidate to a concrete
   skill invocation: build `url = base + path` with the sink param seeded in the
   querystring + `param_name=sink_param` (injection/xss/ssrf); or `url_pattern =
   base + path-with-{id}` + `token` (idor). Mirrors the existing
   `enumerate_endpoints` → `queue_skill(skill, trigger, {'url': full_url})`
   pattern (`scan_loop_run_skills.py:262`).

6. **`loop.py`** — hybrid orchestration. Recon → analyze → prioritize →
   (optional Brain deep-dive) → for each top candidate: invoke the mapped skill
   via **PATH A** (`SKILL_REGISTRY[name]['fn'](...)` — direct call, bypasses the
   exploitation-ceiling gate + the stuck-loop BLOCK that PATH B imposes), read
   the returned dict (`{vulnerable, findings:[{type,payload,param,evidence,
   control:{...},severity}], ...}`), and on a vulnerable result hand a
   report_finding payload through the **existing** `_verify_and_gate` chokepoint.
   The source `file:line` goes into `extra_evidence` as
   `{evidence_type:"code_source_ref", title:"sink at routes/search.ts:23",
   content:"<snippet>"}` — **never** the primary evidence.

7. **`cost_governor.py`** (minimal for MVP) — decides deep-dive width from
   (model tier, budget). MVP default: deterministic pre-pass always; Brain
   deep-dive OFF (deferred). Establishes the seam for the dual-mode adaptive
   behavior without building the expensive layer yet.

## Integration points (verified against current code)

- **Skill invocation:** PATH A direct call returns a dict (not a ToolResult).
  Driving skills directly means the loop must **replicate the
  `sr.data → report_finding` mapping** (auto-reporting only exists inside
  `_run_scheduled_skills`, `scan_loop_run_skills.py:172`). Keep round/param
  variation so PATH B's cache BLOCK is irrelevant (PATH A skips it anyway).
- **Verifier/finding gate:** every reported finding goes through
  `_verify_and_gate` (`scan_loop_actions.py:738`) → `verify_finding`
  (`verifier_tools.py:324`) + `report_finding` store contract
  (`finding_tools.py:723`). A CONFIRMED high/critical needs
  attempt + observed_result + control/baseline + `repeat_count>=2` + negative
  + the Strix fields (impact/technical_analysis/poc_description/poc_script_code/
  remediation). The dynamic skill's `control:{baseline_*, payload_*}` block
  supplies the control/baseline; the loop must issue the PoC request
  `>=2` times to satisfy repeat.
- **DAG bridge (optional, for in-loop use):** to feed the real P3 queue, add a
  `CodeCandidate → HypothesisNode` adapter (`agent/hypothesis/dag.py:32`) rather
  than leaving candidates in the orphan `CodeHypothesis` model. MVP can keep
  candidates internal to `loop.py`; the DAG bridge is a clean follow-up.

## Invariant enforcement (must keep)

1. No `report_finding`/`link_chain` import or call from any codescan analyzer or
   `code_to_hypothesis`; code is physically incapable of writing findings.
2. No CODE branch in `_compute_vxis_score`.
3. Source `file:line` lives **only** in `extra_evidence` (corroboration); never
   in `evidence`/`poc_script_code`/`technical_analysis`/`poc_description` that
   the gate scores, and never added to `tools/_poc_signals.py` marker sets.
4. Regression test: a `report_finding` carrying only a code `source_ref` (no
   HTTP/control/repeat) is blocked by both `verify_finding` (thin_evidence) and
   `report_finding` (weak_poc).

## First integration test (definition of "the loop works")

Target: juice-shop `/rest/products/search` SQL injection (unauthenticated;
`routes/search.ts` interpolates `req.query.q` into a raw `sequelize.query`
template literal; registered in `server.ts`).

End-to-end assertion (against a running juice-shop on localhost):
1. `NodeAnalyzer` finds the route `GET /rest/products/search` + the
   `sequelize.query(\`...${criteria}...\`)` SQLi sink with `sink_param="q"`,
   emitting a candidate with the correct `source_ref` and
   `vector_id_candidate → test_injection`.
2. `endpoint_map` builds `url=http://localhost:3000/rest/products/search?q=SEED`,
   `param_name="q"`.
3. `loop` invokes `test_injection.execute(url=..., param_name="q")`; the dict
   returns `vulnerable=True` (500-on-quote oracle / UNION data) with a control
   block.
4. The finding passes `_verify_and_gate` → CONFIRMED, minted as a VXIS finding
   with the dynamic PoC as primary evidence and `routes/search.ts:NN` as
   `extra_evidence`.

Cross-check: juice-shop's `data/static/challenges.yml` documents this as a known
challenge — ground truth that the hybrid found a real, documented vuln.

## Safety / scope

- juice-shop may be attacked at full strength (disposable benchmark).
- The engine inherits the existing scope/egress enforcement so it **cannot leave
  the explicitly-scoped target** — this is what keeps it on juice-shop and off
  `cloud-api` or any other host. Dynamic verification uses the existing skills,
  which already route through the egress contract.
- Not wired into live Agent Mode until promotion; the L1 gate keeps CODE targets
  showing the honest "in development" message in the meantime.

## Testing & Definition of Done

- Unit: `NodeAnalyzer` route extraction + sink detection on fixtures (a
  `server.ts` + `routes/search.ts` excerpt); `endpoint_map` candidate→url;
  `CodeCandidate` DTO; the invariant regression test (above).
- Integration: the juice-shop SQLi loop above produces a CONFIRMED finding;
  a benign route produces **no** finding (no false positive).
- Gates: `uv run ruff check` clean, `uv run pytest -q` green.
- **Done = juice-shop SQLi confirmed end-to-end + all unit/integration tests
  green.** Only then: promote `incubator/codescan/` → `src/vxis/`, flip the L1
  `infer_target_kind`→CODE gate to route into the engine, add a wiring
  regression test.

## Risks / open questions

- **GET-only skills:** `test_injection`/`test_xss` inject only the GET
  querystring. juice-shop's search SQLi is GET (ideal first case), but login
  SQLi is POST-body — body-sink verification needs a new skill or
  `python_exec`. MVP targets the GET search SQLi; body sinks are a follow-up.
- **Sink detection precision:** regex/grep sink matching (no taint/dataflow)
  will miss indirect sinks and may over-flag; acceptable for MVP (the dynamic
  verify step filters false candidates — a candidate that does not reproduce is
  simply never reported).
- **`finale.resource` auto-CRUD** routes have no explicit `app.get` line; the
  analyzer must model them or it will miss `/api/<Model>s` endpoints.
