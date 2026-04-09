# Playbook: ASP.NET / .NET Core / IIS

Microsoft's web stack — ASP.NET (legacy), ASP.NET Core (modern). IIS and
Kestrel as web servers. Common in enterprise / Windows environments.

## Fingerprint indicators

- `Server: Microsoft-IIS/...` or `Server: Kestrel`
- `X-Powered-By: ASP.NET` or `X-AspNet-Version:`
- `X-AspNetMvc-Version:` or `X-AspNet-Mvc-Version:`
- `Set-Cookie: ASP.NET_SessionId=...` or `.AspNetCore.*`
- URL patterns like `/Default.aspx`, `/App_Data/`, `/_vti_bin/`
- Page source contains `<meta name="generator" content="ASP.NET"`
- Error page "YSOD" (Yellow Screen of Death) with .NET stack trace

## Probe recipe

```python
python_exec(code='''
import asyncio, httpx
paths = [
    # Classic ASP.NET leaks
    "web.config", "Web.config", "web.config.bak",
    "App_Data/", "App_Code/", "App_Offline.htm",
    "elmah.axd", "Trace.axd", "trace.axd",  # ELMAH + diagnostics
    "Default.aspx", "default.asp", "webadmin/", "WebAdmin/",
    # IIS-specific
    "iisadmin/", "_vti_bin/", "_vti_pvt/",
    "aspnet_client/", "bin/", "Bin/",
    # .NET Core / Kestrel
    "appsettings.json", "appsettings.Development.json",
    "appsettings.Production.json", "appsettings.Local.json",
    "hosting.json", "launchSettings.json", "secrets.json",
    # Swagger (common in .NET Core APIs)
    "swagger", "swagger/v1/swagger.json", "swagger-ui.html",
    "swagger/index.html", "api/swagger", "api/docs",
    # Health checks (.NET Core default)
    "health", "healthchecks-ui", "hc", "hc-ui",
    # SignalR hubs
    "signalr/hubs", "signalr/negotiate",
    # Blazor
    "_blazor",
    # Authentication
    "Account/Login", "Identity/Account/Login", "login", "signin",
    # File leaks
    "robots.txt", "sitemap.xml", "global.asax", "global.asa",
    # SharePoint
    "_layouts/15/", "_api/web", "_api/contextinfo",
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

- `web.config` 200 = **CRITICAL** (connection strings, machine keys, full config)
- `appsettings.json` or `.Production.json` 200 = **CRITICAL** (.NET Core secrets)
- `secrets.json` 200 = **CRITICAL** (user secrets, never meant to be published)
- `elmah.axd` 200 unauth = **HIGH** (error log with stack traces, query strings,
  session IDs)
- `Trace.axd` 200 = **HIGH** (page-level trace info, forms data)
- `global.asax` 200 = **MEDIUM** (app startup code, sometimes leaks file paths)
- `swagger/v1/swagger.json` 200 = **LOW/MEDIUM** (API enumeration)
- YSOD with full stack trace = **MEDIUM** (info disclosure, find secrets in trace)

## Post-exploit chains

1. `web.config` → machineKey → forge ViewState → .NET ViewState RCE
2. `elmah.axd` → grep errors for session cookies → hijack
3. `appsettings.Production.json` → DB connection string → direct SQL access
4. SharePoint `_api/web` unauth → user/site enumeration → spray attacks
