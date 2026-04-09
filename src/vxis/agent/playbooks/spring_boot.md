# Playbook: Spring Boot / Java Spring Framework

Spring Boot is the dominant Java web framework. Its default Actuator
endpoints are the single richest source of post-exploitation info on any
web app. Misconfigured actuators reveal environment variables, heap dumps,
database schemas, in-memory beans, and more.

## Fingerprint indicators

Look for any of these signals in response headers or body:
- `Server: Apache-Coyote/...` header
- `X-Application-Context: ...` header
- `Set-Cookie: JSESSIONID=...` cookie
- `<meta name="generator" content="Spring...` HTML tag
- Error page showing "Whitelabel Error Page" or "There was an unexpected error (type=..."
- JSESSIONID in URL (`;jsessionid=`)
- Response body mentions "Spring", "Hibernate", "Tomcat", "Jetty", "Undertow"
- 302 redirect to `/login` with spring-security pattern

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
# Spring Boot default actuator prefix — usually /actuator, sometimes /admin
# or under an app context like /myapp/actuator
actuator_bases = ["actuator", "admin", "management", "api/actuator"]
endpoints = [
    "",                    # actuator index — lists all available endpoints
    "env",                 # environment variables (CRITICAL — creds leak)
    "health",              # health check (often exposed, LOW)
    "info",                # app metadata (LOW)
    "beans",               # Spring bean registry (MEDIUM)
    "mappings",            # URL → handler mappings (MEDIUM)
    "configprops",         # config properties (MEDIUM — can leak keys)
    "heapdump",            # full JVM heap dump (CRITICAL)
    "threaddump",          # thread stack traces (MEDIUM)
    "loggers",             # logger config (LOW)
    "metrics",             # app metrics (LOW)
    "httptrace",           # recent HTTP requests (MEDIUM — session hijack)
    "trace",               # legacy trace endpoint (same)
    "auditevents",         # audit log (MEDIUM)
    "shutdown",            # admin shutdown — test with POST (CRITICAL if works)
    "jolokia",             # JMX over HTTP (CRITICAL — full bean manipulation)
    "jolokia/list",
    "refresh",             # config refresh (LOW)
    "restart",             # restart endpoint (HIGH — DoS)
]
# Spring-specific non-actuator paths
extras = [
    "h2-console",          # H2 database console (CRITICAL if 200 — often no auth)
    "error",               # default error page (often leaks stack trace)
    "v2/api-docs", "v3/api-docs",  # Swagger/OpenAPI JSON
    "swagger-ui.html", "swagger-ui/index.html",
    "registration",        # open registration (MEDIUM if unrestricted)
    "api/swagger-ui.html",
]
async def p(u):
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as c:
        try:
            r = await c.get(f"<TARGET_URL>/{u}")
            return f"{r.status_code} {len(r.content):>7}B  /{u}"
        except Exception as e: return f"ERR  /{u}: {e}"
async def main():
    probes = []
    for base in actuator_bases:
        for ep in endpoints:
            probes.append(f"{base}/{ep}" if ep else base)
    probes.extend(extras)
    results = await asyncio.gather(*[p(u) for u in probes])
    for r in results:
        if " 200 " in r or " 403 " in r or " 500 " in r:
            print(r)
asyncio.run(main())
''')
```

## Interpretation rules

- `actuator/env` 200 = **CRITICAL** — env vars leaked
- `actuator/heapdump` 200 = **CRITICAL** — full JVM memory dump
- `actuator/jolokia/*` 200 = **CRITICAL** — JMX manipulation possible
- `h2-console` 200 = **CRITICAL** — default admin/no-password DB console
- `actuator/shutdown` POST 200 = **CRITICAL** — auth bypass DoS
- `actuator/httptrace` 200 = **MEDIUM** — session cookies in recent requests
- `actuator/mappings` 200 = **MEDIUM** — reveals all routes
- `actuator/health` 200 = **LOW** — usually public by design
- `actuator` index 200 = **MEDIUM** — reveals which endpoints are enabled
- Default `/error` 200 with stacktrace = **LOW/MEDIUM** — info disclosure
- `v2/api-docs` 200 = **LOW/MEDIUM** — full API surface enumerated

## Post-exploit chains

1. `env` leaks DB password → direct DB connection → data extraction
2. `heapdump` → download → inspect for credentials/session tokens in memory
3. `jolokia` → create new MBean → RCE via deserialization
4. `h2-console` → default creds → CREATE ALIAS → system command execution
