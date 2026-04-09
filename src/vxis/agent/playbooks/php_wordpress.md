# Playbook: PHP / WordPress / Laravel

PHP hosts WordPress (45% of all websites), Laravel, and Drupal. Each has
a distinct attack surface.

## Fingerprint indicators

- `X-Powered-By: PHP/...` header
- `Set-Cookie: PHPSESSID=...` cookie
- URL patterns like `?page=` or `index.php?...`
- `<meta name="generator" content="WordPress ...` tag
- `wp-content/`, `wp-includes/`, `wp-json/` in page source
- Laravel: `laravel_session` cookie, `X-Laravel-*` headers, `/livewire/` paths
- Drupal: `/sites/default/`, `X-Drupal-*` headers
- Error messages containing "PHP Fatal error", "Parse error", "Warning:"

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
paths = [
    # Generic PHP exposure
    "phpinfo.php", "info.php", "test.php", "i.php",
    "php.ini", "admin.php", "admin/", "login.php",
    "server-status", "server-info",

    # WordPress — every deployment has these
    "wp-admin/", "wp-admin/admin.php", "wp-admin/install.php",
    "wp-login.php", "wp-config.php", "wp-config.php.bak",
    "wp-config.php.old", "wp-config.php~", "wp-config.txt",
    "wp-content/debug.log", "wp-content/uploads/",
    "wp-content/plugins/", "wp-content/themes/",
    "wp-includes/", "xmlrpc.php", "wp-cron.php",
    "wp-json/", "wp-json/wp/v2/users", "wp-json/wp/v2/pages",
    "readme.html", "license.txt",
    "?author=1", "?author=2",  # username enumeration
    "wp-content/uploads/backup.zip",

    # Laravel — canonical exposures
    ".env", ".env.backup", ".env.save",
    "_ignition/execute-solution",  # RCE CVE-2021-3129
    "_debugbar/", "debugbar/",
    "telescope/", "horizon/",
    "storage/logs/laravel.log",
    "routes/web.php",

    # Drupal
    "CHANGELOG.txt", "core/CHANGELOG.txt",
    "user/login", "admin/config", "?q=admin",
    "sites/default/settings.php",
    "sites/default/files/",
    "node/1", "node/2",

    # PHPMyAdmin
    "phpmyadmin/", "pma/", "mysql/", "myadmin/",
    "phpmyadmin/index.php",
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
        if " 200 " in r or " 403 " in r: print(r)
asyncio.run(main())
''')
```

## Interpretation rules

- `wp-config.php` or `.bak` 200 = **CRITICAL** — DB creds, secrets
- `phpinfo.php` 200 = **MEDIUM** — full PHP config + env
- `wp-admin/install.php` 200 = **HIGH** — possible re-install attack
- `_ignition/execute-solution` 200 = **CRITICAL** — Laravel RCE (CVE-2021-3129)
- `.env` 200 on Laravel = **CRITICAL** — app key, DB creds, mail creds
- `phpmyadmin/` 200 = **HIGH** — default creds, known CVEs
- `?author=N` returning different content per N = **LOW** — username enum
- `wp-json/wp/v2/users` 200 = **LOW/MEDIUM** — user enumeration via REST
- `debug.log` 200 = **MEDIUM** — error + stack traces
- `xmlrpc.php` 200 = **LOW** — brute force amplification vector

## Post-exploit chains

1. `.env` leak → `APP_KEY` → forge signed Laravel session → admin access
2. `wp-config.php` leak → DB creds → direct MySQL → dump tables → plant admin
3. `xmlrpc.php` + `wp.getUsersBlogs` → credential brute with amplification
4. `phpmyadmin` default creds (root/no-password) → MySQL RCE via `INTO OUTFILE`
