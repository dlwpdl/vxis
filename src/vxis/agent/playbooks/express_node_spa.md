# Playbook: Express / Node.js (with SPA frontend)

Modern Node.js apps typically serve a SPA (Angular/React/Vue) with a REST
or GraphQL API. Juice Shop, the OWASP benchmark, is the canonical example.

## Fingerprint indicators

- `X-Powered-By: Express` header
- `Set-Cookie: connect.sid=...` or `io=...` cookie
- Angular: `<app-root>`, `ng-version=`, bundled `main.*.js`
- React: `<div id="root">`, `__REACT_DEVTOOLS_GLOBAL_HOOK__`
- Vue: `<div id="app">`, `__VUE__`, `data-v-...` attrs
- Response to unknown path returns same body as `/` (SPA shell fallback)
- `Content-Type: application/json` on `/api/*` or `/rest/*`

## SPA detection protocol

Before anything else: confirm SPA behavior.
```python
shell_exec(command="for u in / /definitely-not-real; do curl -sk -o /dev/null -w 'PATH=$u SIZE=%{size_download} CODE=%{http_code}\\n' <TARGET_URL>$u; done")
```
If both rows show the same SIZE → SPA. Remember the SIZE as baseline for
ffuf's `-fs <SIZE>` filter.

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
paths = [
    # REST / API surfaces
    "rest/products", "rest/users", "rest/user/login", "rest/user/whoami",
    "rest/admin/application-configuration", "rest/admin/application-version",
    "rest/basket/1", "rest/basket/2", "rest/order", "rest/captcha",
    "rest/memories", "rest/languages", "rest/saveLoginIp",
    "api", "api/users", "api/products", "api/v1/users", "api/v2/users",
    "api/auth", "api/login", "api/logout", "api/register", "api/profile",
    # Docs / schema surfaces
    "api-docs", "api/docs", "swagger.json", "swagger-ui.html",
    "openapi.json", "graphql", "graphiql",
    # Static / filesystem leaks
    "ftp/", "ftp/package.json.bak", "assets/public/", "public/",
    "uploads/", "files/", "downloads/",
    # Node-specific leaks
    "package.json", "package-lock.json", "yarn.lock",
    "node_modules/", ".npmrc", ".yarnrc",
    # Debug / dev
    "debug", "__debug__", "_debug", "status", "healthz",
    # SQL injection probe candidates (response-length oracle)
    "rest/products/search?q=1",
    "rest/products/search?q=%27",
    "rest/products/search?q=1%27%20OR%20%271%27=%271",
]
async def p(u):
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as c:
        try:
            r = await c.get(f"<TARGET_URL>/{u}")
            return f"{r.status_code} {len(r.content):>7}B  /{u}"
        except Exception as e: return f"ERR  /{u}: {e}"
async def main():
    results = await asyncio.gather(*[p(u) for u in paths])
    for r in results: print(r)
asyncio.run(main())
''')
```

## Interpretation rules

- REST endpoint returning 500 = **HIGH** (unhandled error, possible injection)
- Admin-config endpoint 200 with large body = **HIGH** (config leak)
- `/ftp/` or `/uploads/` returning directory listing = **MEDIUM**
- `.bak` / `.old` files with 403 = **MEDIUM** (bypassable via query params)
- `package.json` / `package-lock.json` 200 = **LOW/MEDIUM** (dependency leak)
- 401 on enumerable resource IDs (`/rest/basket/1`, `/rest/basket/2`) =
  **MEDIUM** — IDOR candidate, test with auth
- Query-param size delta between `q=1` and `q='` = **HIGH** — SQL injection signal
- Directory listing under `/assets/public/` = **MEDIUM**

## Post-exploit chains

1. `/rest/user/whoami` with no auth → session inference → hijack
2. `/ftp/package.json.bak` bypass via `?md5=...` → dependency tree → CVE lookup
3. `/rest/products/search?q='` SQL break → `sqlmap -u '...' --batch --dbs`
4. Admin-config leak → hardcoded API keys / credentials → direct backend access
