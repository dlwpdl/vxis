# Playbook: Flask / FastAPI / Python Microframework

Flask and FastAPI cover most Python-backed REST APIs. FastAPI's automatic
/docs and /openapi.json are particularly leaky.

## Fingerprint indicators

- `Server: Werkzeug/...` (Flask dev server — should NEVER be in prod)
- `Server: gunicorn/...` or `uvicorn` (common Flask/FastAPI prod)
- `Set-Cookie: session=...` (Flask default) with unique format
- Response body contains `<title>Swagger UI</title>` on /docs (FastAPI)
- Error traceback with "File "/app/...", line N, in" — Flask debug mode
- `X-Process-Time:` header common in FastAPI
- URL patterns like `/docs`, `/redoc`, `/openapi.json`

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
paths = [
    # FastAPI auto-docs (CRITICAL exposure risk)
    "docs", "redoc", "openapi.json", "api/openapi.json",
    "docs/oauth2-redirect",
    # Flask debug
    "console", "debugger",  # Werkzeug debugger pin-prompt
    # Config files commonly committed next to code
    "config.py", "settings.py", "app.py", "main.py",
    "requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock",
    # Common auth endpoints
    "login", "auth/login", "auth/token", "oauth/token",
    "api/login", "api/auth", "api/users", "api/users/1",
    # Admin surfaces
    "admin", "admin/login", "flask-admin/",
    # Metrics / health
    "metrics", "health", "status", "ping", "healthz",
    # Flask extension artifacts
    "static/", "static/config.json",
    # Error handling
    "nonexistent/triggers/500",  # force 500 to check debug leakage
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

- `openapi.json` or `docs` 200 = **MEDIUM** (full API surface + schemas)
- `console` 200 returning HTML with "Werkzeug" = **CRITICAL** (debug RCE)
- `debugger` 200 = **CRITICAL** (Werkzeug PIN can be brute-forced → RCE)
- 500 with full Python stacktrace = **MEDIUM** (info disclosure, inspect for secrets)
- `config.py` or `settings.py` 200 = **CRITICAL** (app secrets)
- `requirements.txt` 200 = **LOW/MEDIUM** (dependency enum for CVE lookup)
- `metrics` 200 unauth = **LOW/MEDIUM** (Prometheus scrape — sometimes leaks URLs)

## Post-exploit chains

1. Werkzeug debugger PIN bypass → direct Python REPL → RCE
2. `openapi.json` schema dump → find unauth endpoints → authorized ops without auth
3. Flask session cookie forge via leaked SECRET_KEY (from config.py) → admin impersonation
4. FastAPI `/docs` exposes all endpoints → methodically probe each for IDOR
