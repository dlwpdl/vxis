# Playbook: Ruby on Rails

Rails powers Shopify, GitHub (historically), Airbnb, Basecamp. Classic
attack surface: debug routes, exposed secrets, session cookie manipulation.

## Fingerprint indicators

- `X-Powered-By: Phusion Passenger` or `Server: WEBrick/Puma/Unicorn`
- `Set-Cookie: _session_id=...` or `_<app>_session=...` cookie
- `X-Runtime:`, `X-Request-Id:` headers
- Response body contains `<meta name="csrf-token"` tag
- Error page "We're sorry, but something went wrong" with Ruby stacktrace
- URL patterns like `/assets/application-<hash>.js`
- `rails` in response body or asset manifests

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
paths = [
    # Development artifacts
    "config/database.yml", "config/secrets.yml", "config/master.key",
    "config/credentials.yml.enc", "config/application.yml",
    ".env", ".env.development", ".env.production",
    # Rails console / rake
    "rails/info/routes", "rails/info/properties", "rails/info",
    "rails/mailers", "rails/db",
    # Sidekiq web UI
    "sidekiq", "sidekiq/busy", "sidekiq/queues",
    # Admin UIs
    "admin", "admin/login", "admin/sign_in",
    "rails_admin", "activeadmin", "trestle",
    # Devise (auth gem) routes
    "users/sign_in", "users/sign_up", "users/password/new",
    # Common Rails API patterns
    "api/v1", "api/v1/users", "api/v1/sessions",
    # Asset pipeline leaks
    "assets/application.js", "assets/config/manifest.json",
    # File leaks
    "public/", "tmp/", "log/production.log",
    "Gemfile", "Gemfile.lock", "config.ru",
    # GraphiQL (if graphql-ruby exposed)
    "graphiql", "graphql",
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
        if " 200 " in r or " 403 " in r or " 500 " in r: print(r)
asyncio.run(main())
''')
```

## Interpretation rules

- `config/master.key` or `config/credentials.yml.enc` 200 = **CRITICAL** (app secrets)
- `config/database.yml` 200 = **CRITICAL** (DB creds)
- `sidekiq` 200 with no auth = **HIGH** (job queue visibility + injection)
- `rails/info/routes` 200 = **MEDIUM** (route enumeration)
- `rails_admin` or `activeadmin` login page 200 = **LOW** (try default creds)
- 500 with Ruby stacktrace in body = **MEDIUM** (info disclosure)
- `Gemfile.lock` 200 = **LOW/MEDIUM** (dependency enumeration → CVE lookup)

## Post-exploit chains

1. `master.key` leak → decrypt `credentials.yml.enc` → app secrets + API keys
2. Sidekiq UI unauth → enqueue malicious job with shell command
3. Devise + leaked `secret_key_base` → forge session → impersonate any user
4. Debug mode stacktrace → leaked DB_URL → direct database access
