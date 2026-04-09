# Playbook: Generic REST / GraphQL API

Apply this for any API-first target (no HTML frontend, or JSON-only responses
dominate).

## Fingerprint indicators

- `Content-Type: application/json` on most responses
- Response body is JSON, not HTML
- URL structure like `/api/v1/...` or `/v2/...`
- `Access-Control-Allow-Origin:` CORS headers
- GraphQL: POST to `/graphql` with `{"query":"..."}` body
- REST: resource-style URLs with HTTP verbs (GET/POST/PUT/DELETE)

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
api_roots = ["api", "api/v1", "api/v2", "v1", "v2", "rest", "services"]
resources = [
    "users", "user", "accounts", "account", "profile",
    "products", "orders", "items", "posts",
    "admin", "config", "settings", "status",
    "health", "ping", "version", "metrics",
    "auth", "login", "logout", "register", "me", "whoami",
    "tokens", "keys", "secrets", "docs", "schema",
]
special = [
    "graphql", "graphiql", "playground",  # GraphQL
    "swagger.json", "swagger-ui.html", "swagger-ui/index.html",
    "openapi.json", "openapi.yaml", "api-docs",
    "v2/api-docs", "v3/api-docs",
    ".well-known/openid-configuration",  # OIDC discovery
    ".well-known/jwks.json",              # JWT signing keys
    "docs", "api/docs",
]
async def p(u):
    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as c:
        try:
            r = await c.get(f"<TARGET_URL>/{u}")
            return f"{r.status_code} {len(r.content):>7}B  /{u}"
        except Exception as e: return f"ERR  /{u}: {e}"
async def main():
    probes = list(special)
    for root in api_roots:
        probes.append(root)
        for res in resources:
            probes.append(f"{root}/{res}")
    results = await asyncio.gather(*[p(u) for u in probes])
    for r in results:
        if " 200 " in r or " 401 " in r or " 500 " in r: print(r)
asyncio.run(main())
''')
```

## Interpretation rules

- GraphQL introspection enabled = **MEDIUM** — full schema dump
  - Verify: POST `/graphql` with `{"query":"{__schema{types{name}}}"}`
- Swagger / OpenAPI endpoint 200 = **LOW/MEDIUM** — surface enumeration
- JWKS endpoint 200 without proper signing = **MEDIUM** — token forging possible
- OIDC `.well-known/openid-configuration` = **LOW** — config leak
- `/api/users` without auth returning array = **HIGH** — unauth data access
- Resource with numeric ID (`/api/users/1`) responding 200 unauth = **HIGH** (IDOR)
- 500 on API endpoint with stack trace = **MEDIUM/HIGH** depending on content

## GraphQL post-exploit

If `/graphql` exists:
```python
python_exec(code='''
import httpx
q = "{__schema{types{name fields{name type{name}}}}}"
r = httpx.post("<TARGET_URL>/graphql", json={"query": q}, timeout=10)
print(r.status_code, len(r.content))
print(r.text[:2000])
''')
```
If introspection is on, dump the full schema and look for `User`, `Token`,
`AdminQuery` types. Then craft queries against sensitive types without auth.

## IDOR post-exploit

For any resource endpoint returning 200 with user data:
1. Probe `/resource/1`, `/resource/2`, `/resource/3` — different users
2. If responses differ → IDOR confirmed, report
3. Try numeric ID enumeration via python_exec asyncio loop
