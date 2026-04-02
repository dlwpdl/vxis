# Pipeline Improvements — Multi-Target Support & Bug Fixes

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix URL double-concatenation bug, add retry/adaptive timeout, expand Brain prompts with app-specific context, and improve vector coverage scoring accuracy.

**Architecture:** Fix 4 interconnected issues in pipeline.py (Brain prompt, URL construction), hands.py (timeout/retry), and engine.py (scoring denominator). Each task is independent and can be parallelized.

**Tech Stack:** Python 3.12, httpx, VXIS pipeline/scoring/hands modules

---

### Task 1: Fix URL double-concatenation in endpoint construction

**Files:**
- Modify: `src/vxis/pipeline/pipeline.py:896` (endpoint normalization before session calls)
- Modify: `src/vxis/pipeline/pipeline.py:252` (`_make_fallback_decision` endpoint construction)

The httpx client has `base_url` set, so passing a full URL like `http://localhost:8082/index.php?page=...` causes httpx to prepend `base_url` again. Endpoints must be relative paths when passed to session methods.

- [ ] **Step 1: Add endpoint normalization helper**

In `src/vxis/pipeline/pipeline.py`, add after the `_make_fallback_decision` function (after line ~272):

```python
def _normalize_endpoint(endpoint: str, base_url: str) -> str:
    """Ensure endpoint is a relative path for httpx base_url client.
    
    If endpoint is a full URL matching the base, strip the base to avoid
    httpx double-concatenation (base_url + full_url = broken URL).
    """
    if not endpoint.startswith("http"):
        return endpoint
    base = base_url.rstrip("/")
    if endpoint.startswith(base):
        return endpoint[len(base):] or "/"
    # Different host — return as-is, httpx handles absolute URLs to other hosts
    return endpoint
```

- [ ] **Step 2: Apply normalization in `_execute_brain_decisions`**

In `src/vxis/pipeline/pipeline.py`, at line ~896 where endpoint is extracted from decision:

```python
endpoint = target_spec.get("endpoint", "/")
# Normalize: strip base_url prefix to avoid httpx double-concat
endpoint = _normalize_endpoint(endpoint, ctx.target)
```

- [ ] **Step 3: Fix `_make_fallback_decision` to return relative paths**

In `src/vxis/pipeline/pipeline.py`, line 252, change:
```python
# Before:
endpoint = target.rstrip("/") + rel_path
# After:
endpoint = rel_path
```

And line 254 (the `app_specific_urls` fallback):
```python
# Before:
endpoint = app_specific_urls[0]
# After: strip base URL from app_specific_urls
_base = target.rstrip("/")
_first = app_specific_urls[0]
endpoint = _first[len(_base):] if _first.startswith(_base) else _first
```

- [ ] **Step 4: Verify by running a quick scan**

```bash
python tools/growth_loop_runner.py --targets mutillidae --iterations 1
```

Expected: No more `http://host:porthttp://host:port/...` double URLs in logs.

- [ ] **Step 5: Commit**

```bash
git add src/vxis/pipeline/pipeline.py
git commit -m "fix(pipeline): normalize endpoints to relative paths — prevent httpx double-concat"
```

---

### Task 2: Add retry logic and adaptive timeout for slow targets

**Files:**
- Modify: `src/vxis/interaction/hands.py:490-506` (request method — add retry)
- Modify: `src/vxis/interaction/hands.py:432` (init — configurable timeout)

- [ ] **Step 1: Add retry with backoff to `TargetSession.request()`**

In `src/vxis/interaction/hands.py`, replace the try/except block around `self._client.request()` (lines 490-506):

```python
    max_retries = 2
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            resp = await self._client.request(
                method=method.upper(),
                url=path,
                data=data,
                json=json_data,
                headers=extra_headers if extra_headers else None,
                params=params,
            )
            last_exc = None
            break
        except httpx.TimeoutException as e:
            last_exc = e
            _display_url = path if path.startswith("http") else f"{self.base_url}{path}"
            if attempt < max_retries:
                wait = (attempt + 1) * 2.0
                logger.info("Timeout (attempt %d/%d): %s %s — retrying in %.0fs",
                            attempt + 1, max_retries + 1, method, _display_url, wait)
                import asyncio as _aio
                await _aio.sleep(wait)
            else:
                logger.warning("Timeout (final): %s %s", method, _display_url)
        except httpx.ConnectError as e:
            _display_url = path if path.startswith("http") else f"{self.base_url}{path}"
            logger.warning("Connection failed: %s %s: %s", method, _display_url, e)
            raise

    if last_exc is not None:
        raise last_exc
```

- [ ] **Step 2: Commit**

```bash
git add src/vxis/interaction/hands.py
git commit -m "feat(hands): add retry with backoff for timeout — 2 retries before failure"
```

---

### Task 3: Expand Brain prompt with full app-specific context

**Files:**
- Modify: `src/vxis/pipeline/pipeline.py:700-727` (system/user prompts)

The Brain LLM currently gets only 6 app_specific_urls and a generic system prompt. It should receive the full app context including endpoint-to-vector mappings.

- [ ] **Step 1: Update system prompt to include app name dynamically**

In `src/vxis/pipeline/pipeline.py`, replace the hardcoded app list in system prompt (line 703):

```python
# Before:
"Target is a KNOWN INTENTIONALLY VULNERABLE benchmark app (DVWA, Juice Shop, WebGoat, NodeGoat). "
# After:
f"Target is {app_name}, a KNOWN INTENTIONALLY VULNERABLE benchmark app. "
```

- [ ] **Step 2: Increase endpoint limits in user prompt**

In `src/vxis/pipeline/pipeline.py`, lines 718-719:

```python
# Before:
+ (f"\n{api_spec_context}\n" if api_spec_context else f"Known vulnerable paths: {app_specific_urls[:6]}\n")
+ f"Discovered endpoints: {effective_endpoints[:8]}\n"
# After:
+ (f"\n{api_spec_context}\n" if api_spec_context else f"Known vulnerable paths: {app_specific_urls[:20]}\n")
+ f"Discovered endpoints: {effective_endpoints[:15]}\n"
```

- [ ] **Step 3: Feed vector-to-endpoint mapping into user prompt**

Add the `_APP_VECTOR_ENDPOINTS` mapping for the current target into the user prompt so Brain knows which endpoint to use for each vector:

```python
# After effective_endpoints line, before user_prompt construction:
_app_key = None
_tl = ctx.target.lower()
for _port, _key in [("8081", "dvwa_8081"), ("4000", "nodegoat_4000"), ("8888", "webgoat_8888"),
                     ("8082", "mutillidae_8082"), ("8083", "bwapp_8083"), ("5013", "dvga_5013")]:
    if _port in _tl:
        _app_key = _key
        break
_vec_endpoint_hints = ""
if _app_key and _app_key in _APP_VECTOR_ENDPOINTS:
    _hints = _APP_VECTOR_ENDPOINTS[_app_key]
    _vec_endpoint_hints = "Vector→Endpoint mapping (use these exact paths):\n" + "\n".join(
        f"  {vid}: {path}" for vid, path in _hints.items()
    ) + "\n"
```

Then add `_vec_endpoint_hints` to user_prompt:

```python
user_prompt = (
    f"Target app: {app_name} at {ctx.target}\n"
    + (f"\n{api_spec_context}\n" if api_spec_context else f"Known vulnerable paths: {app_specific_urls[:20]}\n")
    + f"Discovered endpoints: {effective_endpoints[:15]}\n"
    + _vec_endpoint_hints
    + f"Tech stack: {tech_stack or ['web', 'http']}\n"
    # ... rest unchanged
)
```

- [ ] **Step 4: Commit**

```bash
git add src/vxis/pipeline/pipeline.py
git commit -m "feat(brain): enrich prompt with app-specific vector→endpoint mapping + more paths"
```

---

### Task 4: Fix effective_endpoints fallback for new targets

**Files:**
- Modify: `src/vxis/pipeline/pipeline.py:638-639` (effective_endpoints construction)

Currently `effective_endpoints` only uses live crawled URLs or hardcoded paths. For new targets with no crawl data, ensure all `app_specific` paths are used.

- [ ] **Step 1: Increase app_specific_urls limit**

In `src/vxis/pipeline/pipeline.py`, line 639:

```python
# Before:
effective_endpoints = live_urls[:15] or app_specific_urls[:8] or [target_base]
# After:
effective_endpoints = live_urls[:20] or app_specific_urls[:20] or [target_base]
```

- [ ] **Step 2: Commit**

```bash
git add src/vxis/pipeline/pipeline.py
git commit -m "fix(pipeline): increase effective_endpoints limit from 8 to 20 for better coverage"
```

---

### Task 5: Verify all fixes with mutillidae scan

- [ ] **Step 1: Run scan**

```bash
python tools/growth_loop_runner.py --targets mutillidae --iterations 1
```

- [ ] **Step 2: Check results**

Expected improvements:
- No URL double-concatenation in logs
- Fewer timeouts (retries kick in)
- Brain uses Mutillidae-specific endpoints (user-info.php, dns-lookup.php, etc.)
- Score should be higher than 783.9 baseline
- ScoringEngine works without error

- [ ] **Step 3: Commit results**

```bash
git add tools/benchmark/
git commit -m "bench(mutillidae): post-fix scan results"
```
