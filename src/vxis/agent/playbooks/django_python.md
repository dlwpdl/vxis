# Playbook: Django / Python Web Framework

Django powers many Python-backed apps (Instagram historically, Mozilla,
Pinterest). Its default admin interface and debug mode are the primary
attack surfaces.

## Fingerprint indicators

- `Set-Cookie: csrftoken=...; sessionid=...` cookies
- `X-Frame-Options: DENY` (Django default)
- Page source contains `{% csrf_token %}` references
- 404 page shows "Django tried these URL patterns" (debug mode on)
- Admin login page at `/admin/` with distinctive "Django administration" banner
- Error pages with yellow banner and "Debug: true"

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
paths = [
    # Admin / auth
    "admin/", "admin/login/", "admin/password_reset/",
    # Debug pages
    "__debug__/", "debug/", "django-debug-toolbar/",
    # Settings leakage via debug mode
    "settings.py", "settings", "manage.py",
    # REST framework
    "api/", "api/v1/", "api/users/", "api/token/",
    "api-auth/login/", "api-auth/logout/",
    "accounts/login/", "accounts/signup/",
    # Static / media
    "static/", "media/", "staticfiles/",
    # Common Django apps
    "healthz/", "health/", "health_check/",
    "celery/", "flower/",  # task queue monitors
    # Django REST framework schema
    "schema/", "swagger/", "redoc/",
    # Debug info
    "__debug_info__",
    # Common custom paths
    "users/", "profile/", "dashboard/",
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
        if " 200 " in r or " 302 " in r or " 500 " in r: print(r)
asyncio.run(main())
''')
```

## Interpretation rules

- `admin/` 200 with Django admin login = **LOW** (expected, try default creds)
- `admin/` with password hash leak in error = **CRITICAL**
- 500 showing "Debug: true" + local variables = **CRITICAL** — full env + stack
- `django-debug-toolbar` 200 = **HIGH** — SQL queries + view introspection
- `settings.py` 200 = **CRITICAL** — SECRET_KEY, DB creds
- `api/token/` without auth = **MEDIUM** — JWT token endpoint, test brute force
- `flower/` 200 = **HIGH** — Celery task queue monitor, often no auth

## Post-exploit chains

1. Debug mode on → trigger 500 → read SECRET_KEY from locals → forge session
2. `admin/` default creds (admin/admin) → Django admin shell → RCE via template
3. SECRET_KEY leak → pickle-signed session cookie forge → impersonate any user
4. Celery/flower → schedule task with command injection → RCE as worker user
