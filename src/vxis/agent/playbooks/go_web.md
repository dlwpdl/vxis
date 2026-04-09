# Playbook: Go Web Services (Gin / Echo / Fiber / net/http)

Go web services are popular for microservices and APIs. They have fewer
default exposures than Python/Ruby (no debug mode, no auto-docs) but
pprof and expvar endpoints leak heavily when exposed.

## Fingerprint indicators

- `Server: nginx/...` proxying Go backend (common pattern)
- No `X-Powered-By` header (Go typically omits)
- Very fast response times (<20ms) on warm requests
- Response body JSON without whitespace indentation (Go default marshal)
- `Set-Cookie` absent or simple opaque tokens
- Error bodies like `{"error":"..."}` with Go error format
- Asset paths under `/assets/` or `/static/` without framework hashing

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
paths = [
    # Go pprof (net/http/pprof package) — CRITICAL if 200
    "debug/pprof/", "debug/pprof/profile", "debug/pprof/heap",
    "debug/pprof/goroutine", "debug/pprof/cmdline",
    "debug/pprof/symbol", "debug/pprof/trace",
    # expvar
    "debug/vars", "vars",
    # Go metrics
    "metrics", "metrics/prometheus", "healthz", "readyz", "livez",
    # Kubernetes common paths
    "k8s/", "api/v1/namespaces",
    # Common Go API roots
    "api", "api/v1", "api/v2", "v1", "v2",
    "api/v1/users", "api/v1/auth", "api/v1/admin",
    # Gin / Echo / Fiber default routes
    "ping", "health", "hello",
    # Swagger (if swagger-ui middleware mounted)
    "swagger/index.html", "swagger/doc.json",
    # Leaked artifacts
    "go.mod", "go.sum", "main.go", "Dockerfile",
    # Auth
    "login", "register", "oauth/token", "jwt",
]
async def p(u):
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as c:
        try:
            r = await c.get(f"<TARGET_URL>/{u}")
            return f"{r.status_code} {len(r.content):>7}B  /{u}"
        except Exception as e: return f"ERR  /{u}: {e}"
async def main():
    results = await asyncio.gather(*[p(u) for u in paths])
    for r in results:
        if " 200 " in r or " 500 " in r: print(r)
asyncio.run(main())
''')
```

## Interpretation rules

- `debug/pprof/*` 200 = **HIGH** (full profiler access, can enumerate code paths,
  heap dump contains in-memory secrets and session tokens)
- `debug/pprof/cmdline` 200 = **HIGH** (reveals command-line flags including
  DB connection strings)
- `debug/vars` 200 = **MEDIUM** (expvar leaks memory stats + custom vars)
- `metrics` 200 with Prometheus format = **LOW/MEDIUM** (infrastructure
  enumeration, sometimes leaks endpoint names)
- `go.mod` / `go.sum` 200 = **MEDIUM** (dependency enumeration for CVE lookup)
- 500 with Go stack trace = **MEDIUM** (info disclosure)

## Post-exploit chains

1. pprof `heap` dump → download → strings(1) grep for passwords, keys, tokens
2. pprof `profile` (CPU) → infer hot code paths → targeted DoS
3. pprof `cmdline` → reveals args like `-db-url=postgres://user:pass@...`
4. expvar custom vars → reveal in-memory state like session counts
