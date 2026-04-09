# Playbook: Generic Sensitive Files

Universal first-pass probe for ANY web target regardless of stack. These
paths expose secrets, configuration, source code, or sensitive data on a
shocking number of real-world targets. Always run this before framework-
specific playbooks.

## Fingerprint indicators

None — this playbook applies to every target.

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
paths = [
    # VCS leaks (CRITICAL if 200)
    ".git/config", ".git/HEAD", ".git/index", ".svn/entries", ".hg/store",
    # Env / config leaks (CRITICAL if 200)
    ".env", ".env.local", ".env.production", ".env.dev",
    "config.json", "config.yml", "secrets.yml", "settings.py",
    # Backups (HIGH if 200/403 — 403 often bypassable)
    "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "database.sql", "db.sql", "site.tar.gz", "www.zip",
    # Server info (LOW/MEDIUM if 200)
    "server-status", "server-info", ".htaccess", ".htpasswd",
    "phpinfo.php", "info.php", "test.php",
    # Discovery (LOW if 200)
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "clientaccesspolicy.xml", ".well-known/security.txt",
    # IDE leaks (MEDIUM if 200)
    ".vscode/settings.json", ".idea/workspace.xml", ".project",
    # Editor backups (MEDIUM if 200)
    "index.php.bak", "index.php~", "index.php.old", "index.html.bak",
    # CI/CD leaks (HIGH if 200)
    ".travis.yml", ".circleci/config.yml", ".github/workflows/",
    "Jenkinsfile", "docker-compose.yml", "Dockerfile",
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

Substitute `<TARGET_URL>` with the actual target URL (e.g. `http://localhost:3000`).

## Interpretation rules

- Any 200 on `.git/*`, `.env`, `config.*`, backup files = **CRITICAL**
- 403 on backup files often bypassable via query params or encoding = **MEDIUM**
- 200 on `phpinfo.php` / `server-status` = **LOW/MEDIUM** (info disclosure)
- 200 on `robots.txt` with unusual entries = **LOW** (harvest interesting paths)

## Reporting template

`finding_type`: `information_disclosure`
`severity`: scale by what the file contains (creds/source/config = CRITICAL, metadata only = LOW)
`title`: "Publicly accessible {{file}} exposes {{what}}"
