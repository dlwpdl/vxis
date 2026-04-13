"""Skill: test_sensitive_files — scan for exposed files, configs, backups."""
from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = [
    # Git
    ("/.git/HEAD", "critical", "Git repository HEAD exposed"),
    ("/.git/config", "critical", "Git config with potential remote URLs"),
    ("/.gitignore", "low", "Gitignore reveals file structure"),
    # Environment
    ("/.env", "critical", "Environment variables (may contain secrets)"),
    ("/.env.bak", "critical", "Backup env file"),
    ("/env", "medium", "Environment endpoint"),
    ("/config", "medium", "Configuration endpoint"),
    # Backups
    ("/backup/", "high", "Backup directory listing"),
    ("/backup.sql", "critical", "SQL database backup"),
    ("/backup.zip", "critical", "Compressed backup"),
    ("/db.sqlite3", "critical", "SQLite database file"),
    ("/dump.sql", "critical", "Database dump"),
    # Configs
    ("/wp-config.php", "critical", "WordPress config with DB credentials"),
    ("/web.config", "high", "IIS configuration"),
    ("/application.properties", "high", "Spring Boot config"),
    ("/application.yml", "high", "Spring Boot YAML config"),
    ("/config.json", "medium", "JSON config"),
    ("/config.yml", "medium", "YAML config"),
    ("/settings.py", "critical", "Django settings with SECRET_KEY"),
    ("/package.json", "low", "Node.js dependencies"),
    # Logs
    ("/logs/", "high", "Log directory"),
    ("/log/", "high", "Log directory"),
    ("/support/logs", "high", "Support logs"),
    ("/error.log", "medium", "Error log"),
    ("/access.log", "medium", "Access log"),
    ("/debug.log", "medium", "Debug log"),
    # Keys & certs
    ("/encryptionkeys/", "critical", "Encryption keys directory"),
    ("/keys/", "critical", "Keys directory"),
    ("/private.key", "critical", "Private key file"),
    ("/id_rsa", "critical", "SSH private key"),
    ("/server.key", "critical", "SSL private key"),
    # Metrics & debug
    ("/metrics", "medium", "Prometheus metrics"),
    ("/debug/", "high", "Debug endpoint"),
    ("/actuator/", "high", "Spring Actuator"),
    ("/actuator/env", "critical", "Spring Actuator environment"),
    ("/actuator/health", "low", "Health check"),
    ("/server-status", "medium", "Apache status"),
    ("/phpinfo.php", "medium", "PHP info page"),
    ("/_debug/", "high", "Debug panel"),
    # Documentation
    ("/api-docs/", "medium", "API documentation"),
    ("/swagger.json", "medium", "Swagger spec"),
    ("/swagger-ui/", "medium", "Swagger UI"),
    ("/graphql", "medium", "GraphQL endpoint"),
    ("/graphiql", "medium", "GraphQL IDE"),
    # FTP / uploads
    ("/ftp/", "high", "FTP directory"),
    ("/uploads/", "medium", "Upload directory"),
    ("/files/", "medium", "File directory"),
    # Password files
    ("/.htpasswd", "critical", "Apache password file"),
    ("/etc/passwd", "critical", "System password file"),
    # Other
    ("/robots.txt", "informational", "Robots.txt"),
    ("/sitemap.xml", "informational", "Sitemap"),
    ("/.well-known/security.txt", "informational", "Security contact"),
    ("/crossdomain.xml", "low", "Flash cross-domain policy"),
    ("/security.txt", "informational", "Security contact"),
]


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Scan for sensitive files and configurations.

    Returns:
        {
            "exposed": [{"path", "severity", "description", "status", "size", "preview"}, ...],
            "total_scanned": int,
        }
    """
    import httpx

    target = target_url.rstrip("/")
    exposed: list[dict] = []
    baseline_size: int | None = kwargs.get("baseline_size")

    async with httpx.AsyncClient(base_url=target, timeout=5, verify=False,
                                  limits=httpx.Limits(max_connections=20)) as c:
        if baseline_size is None:
            try:
                r = await c.get("/definitely-not-real-probe")
                if r.status_code == 200:
                    baseline_size = len(r.content)
            except Exception:
                pass

        sem = asyncio.Semaphore(20)

        async def check(path: str, severity: str, description: str) -> None:
            async with sem:
                try:
                    r = await c.get(path)
                    size = len(r.content)
                    if r.status_code == 404 or (baseline_size and size == baseline_size):
                        return
                    if r.status_code == 200 and size > 50:
                        exposed.append({
                            "path": path,
                            "severity": severity,
                            "description": description,
                            "status": r.status_code,
                            "size": size,
                            "preview": r.text[:300],
                        })
                except Exception:
                    pass

        await asyncio.gather(*[check(p, s, d) for p, s, d in SENSITIVE_PATHS])

    exposed.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(x["severity"], 5))

    logger.info("test_sensitive_files: %d exposed out of %d scanned", len(exposed), len(SENSITIVE_PATHS))
    return {"exposed": exposed, "total_scanned": len(SENSITIVE_PATHS)}
