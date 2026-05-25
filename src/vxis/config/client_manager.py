"""Multi-client management for VXIS.

Clients are persisted as individual TOML files inside a ``clients_dir``
directory (default: ``~/.vxis/clients/``).  Each file is named
``<client_id>.toml`` where ``client_id`` is a URL-safe slug derived from the
client's name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vxis.config.branding import BrandingConfig

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _slugify(name: str) -> str:
    """Convert *name* to a lowercase, hyphen-separated slug.

    Examples
    --------
    >>> _slugify("ACME Corporation")
    'acme-corporation'
    >>> _slugify("Foo & Bar 2024!")
    'foo-bar-2024'
    """
    slug = name.lower()
    # Replace any non-alphanumeric character sequence with a hyphen
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    # Strip leading/trailing hyphens
    slug = slug.strip("-")
    return slug


def _branding_to_dict(branding: BrandingConfig) -> dict[str, Any]:
    """Serialise a BrandingConfig to a plain dict for TOML output."""
    return {
        "company_name": branding.company_name,
        "company_address": branding.company_address,
        "company_website": branding.company_website,
        "company_email": branding.company_email,
        "logo_path": str(branding.logo_path) if branding.logo_path else "",
        "primary_color": branding.primary_color,
        "accent_color": branding.accent_color,
        "report_footer": branding.report_footer,
        "report_classification": branding.report_classification,
    }


def _branding_from_dict(data: dict[str, Any]) -> BrandingConfig:
    """Deserialise a BrandingConfig from a raw TOML dict."""
    logo_raw: str = data.get("logo_path", "")
    logo_path = Path(logo_raw) if logo_raw else None
    return BrandingConfig(
        company_name=data.get("company_name", "VXIS Security"),
        company_address=data.get("company_address", ""),
        company_website=data.get("company_website", ""),
        company_email=data.get("company_email", ""),
        logo_path=logo_path,
        primary_color=data.get("primary_color", "#1a1a2e"),
        accent_color=data.get("accent_color", "#e94560"),
        report_footer=data.get("report_footer", "Confidential — {company_name}"),
        report_classification=data.get("report_classification", "Client Confidential"),
    )


def _client_to_dict(client: "Client") -> dict[str, Any]:
    """Convert a Client dataclass to a serialisable dict."""
    data: dict[str, Any] = {
        "id": client.id,
        "name": client.name,
        "domains": client.domains,
        "exclude_targets": client.exclude_targets,
        "exclude_ports": client.exclude_ports,
        "industry": client.industry,
        "contact_name": client.contact_name,
        "contact_email": client.contact_email,
        "notes": client.notes,
        "created_at": client.created_at.isoformat(),
    }
    if client.branding is not None:
        data["branding"] = _branding_to_dict(client.branding)
    return data


def _client_from_dict(data: dict[str, Any]) -> "Client":
    """Build a Client from a raw TOML dict."""
    branding: BrandingConfig | None = None
    if "branding" in data and isinstance(data["branding"], dict):
        branding = _branding_from_dict(data["branding"])

    created_raw: str = data.get("created_at", "")
    try:
        created_at = datetime.fromisoformat(created_raw)
    except (ValueError, TypeError):
        created_at = datetime.now(timezone.utc)

    return Client(
        id=data["id"],
        name=data["name"],
        domains=data.get("domains", []),
        exclude_targets=data.get("exclude_targets", []),
        exclude_ports=data.get("exclude_ports", []),
        industry=data.get("industry", ""),
        contact_name=data.get("contact_name", ""),
        contact_email=data.get("contact_email", ""),
        branding=branding,
        notes=data.get("notes", ""),
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# Minimal TOML serialiser (no external dependency)
# ---------------------------------------------------------------------------


def _toml_value(value: object) -> str:
    """Return the TOML literal representation of a simple Python value."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)
    if isinstance(value, str):
        # Escape backslashes and double-quotes, then wrap in double quotes
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    raise TypeError(f"Unsupported TOML value type: {type(value)!r} for value {value!r}")


def _dict_to_toml_lines(data: dict, _prefix: str = "") -> list[str]:
    """Convert a nested dict to TOML-formatted lines.

    Supported types: str, int, float, bool, list[scalar], dict (inline table
    becomes a TOML [section]).  Handles the single level of nesting required
    by the client schema (a ``branding`` sub-dict).
    """
    lines: list[str] = []
    deferred_sections: list[tuple[str, dict]] = []

    for key, value in data.items():
        full_key = f"{_prefix}.{key}" if _prefix else key
        if isinstance(value, dict):
            # Defer sections to emit after scalar keys
            deferred_sections.append((full_key, value))
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key} = []")
            else:
                items = ", ".join(_toml_value(item) for item in value)
                lines.append(f"{key} = [{items}]")
        else:
            lines.append(f"{key} = {_toml_value(value)}")

    for section_key, section_data in deferred_sections:
        lines.append("")
        lines.append(f"[{section_key}]")
        for k, v in section_data.items():
            if isinstance(v, list):
                if not v:
                    lines.append(f"{k} = []")
                else:
                    items = ", ".join(_toml_value(item) for item in v)
                    lines.append(f"{k} = [{items}]")
            elif isinstance(v, dict):
                # Only one level of nesting supported; emit inline
                inner = ", ".join(f"{ik} = {_toml_value(iv)}" for ik, iv in v.items())
                lines.append(f"{k} = {{{inner}}}")
            else:
                lines.append(f"{k} = {_toml_value(v)}")

    return lines


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Client:
    """Represents a managed client engagement in VXIS.

    Attributes
    ----------
    id:
        URL-safe slug (e.g. ``acme-corp``).  Automatically derived from
        *name* when not supplied explicitly.
    name:
        Human-readable client name (e.g. ``"ACME Corporation"``).
    domains:
        Authorised scan targets for this client.
    exclude_targets:
        Hosts/CIDRs to skip even if they fall within *domains*.
    exclude_ports:
        TCP/UDP port numbers to exclude from scanning.
    industry:
        Client industry sector (e.g. ``"financial"``, ``"healthcare"``).
    contact_name:
        Primary point of contact at the client.
    contact_email:
        Email address of the primary contact.
    branding:
        Optional client-specific branding override.  When ``None`` the
        platform-level branding is used.
    notes:
        Free-text engagement notes.
    created_at:
        UTC timestamp of when this client record was first created.
    """

    id: str
    name: str
    domains: list[str]
    exclude_targets: list[str] = field(default_factory=list)
    exclude_ports: list[int] = field(default_factory=list)
    industry: str = ""
    contact_name: str = ""
    contact_email: str = ""
    branding: BrandingConfig | None = None
    notes: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class ClientManager:
    """Manage client configurations stored as TOML files.

    Each client is stored as ``<clients_dir>/<client_id>.toml``.

    Parameters
    ----------
    clients_dir:
        Directory that contains (or will contain) client TOML files.
        Created automatically if it does not exist.
    """

    def __init__(self, clients_dir: Path) -> None:
        self.clients_dir = Path(clients_dir)
        self.clients_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_client(self, client: Client) -> Path:
        """Persist *client* as a TOML file.

        Parameters
        ----------
        client:
            The client to save.  If ``client.id`` is empty it will be
            derived from ``client.name`` via :func:`_slugify`.

        Returns
        -------
        Path
            Absolute path of the written TOML file.
        """
        try:
            import tomllib  # noqa: F401 — just to check availability
        except ImportError:
            pass

        # Ensure id is populated
        if not client.id:
            client.id = _slugify(client.name)

        toml_path = self.clients_dir / f"{client.id}.toml"
        self._write_toml(toml_path, _client_to_dict(client))
        return toml_path

    def get_client(self, client_id: str) -> Client | None:
        """Load and return the client identified by *client_id*.

        Returns ``None`` when no matching TOML file exists.
        """
        toml_path = self.clients_dir / f"{client_id}.toml"
        if not toml_path.exists():
            return None
        data = self._read_toml(toml_path)
        return _client_from_dict(data)

    def list_clients(self) -> list[Client]:
        """Return a list of all clients found in *clients_dir*.

        Clients are returned in alphabetical order of their IDs.
        """
        clients: list[Client] = []
        for toml_path in sorted(self.clients_dir.glob("*.toml")):
            try:
                data = self._read_toml(toml_path)
                clients.append(_client_from_dict(data))
            except Exception:  # noqa: BLE001 — skip corrupt files
                continue
        return clients

    def update_client(self, client: Client) -> Path:
        """Overwrite an existing client's TOML file with new data.

        Parameters
        ----------
        client:
            Updated client instance.  The ``id`` field is used to locate
            the existing file.

        Returns
        -------
        Path
            Absolute path of the updated TOML file.
        """
        toml_path = self.clients_dir / f"{client.id}.toml"
        self._write_toml(toml_path, _client_to_dict(client))
        return toml_path

    def delete_client(self, client_id: str) -> bool:
        """Delete the TOML file for *client_id*.

        Returns
        -------
        bool
            ``True`` if the file was deleted; ``False`` if it did not exist.
        """
        toml_path = self.clients_dir / f"{client_id}.toml"
        if toml_path.exists():
            toml_path.unlink()
            return True
        return False

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_client_scan_history(
        self,
        client_id: str,
        db_engine: object,
    ) -> list[dict]:
        """Return all scan records whose target matches any of the client's domains.

        The query is performed synchronously using a fresh connection from
        *db_engine* (a SQLAlchemy ``AsyncEngine``).  Results are ordered by
        ``started_at`` descending.

        Parameters
        ----------
        client_id:
            The slug of the client to look up.
        db_engine:
            A SQLAlchemy ``AsyncEngine`` instance (same one used by the
            dashboard).

        Returns
        -------
        list[dict]
            Each dict contains at minimum: ``id``, ``target``, ``profile``,
            ``status``, ``started_at``, ``completed_at``, ``finding_count``.
            Returns an empty list if the client does not exist or has no
            matching scans.
        """
        import asyncio

        client = self.get_client(client_id)
        if client is None or not client.domains:
            return []

        async def _query() -> list[dict]:
            from sqlalchemy import func, select

            from vxis.core.db import get_session
            from vxis.models.db_models import FindingRecord, ScanRecord

            results: list[dict] = []
            async with get_session(db_engine) as session:  # type: ignore[arg-type]
                for domain in client.domains:
                    stmt = (
                        select(ScanRecord)
                        .where(ScanRecord.target.like(f"%{domain}%"))
                        .order_by(ScanRecord.started_at.desc())
                    )
                    rows = list((await session.execute(stmt)).scalars().all())
                    for scan in rows:
                        # Count findings for this scan
                        count_stmt = select(func.count(FindingRecord.id)).where(
                            FindingRecord.scan_id == scan.id
                        )
                        finding_count: int = (
                            await session.execute(count_stmt)
                        ).scalar_one_or_none() or 0

                        results.append(
                            {
                                "id": scan.id,
                                "target": scan.target,
                                "profile": scan.profile,
                                "status": scan.status,
                                "started_at": scan.started_at,
                                "completed_at": scan.completed_at,
                                "finding_count": finding_count,
                            }
                        )
            return results

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Inside an async context — return a coroutine the caller must await
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(asyncio.run, _query())
                    return future.result()
            else:
                return loop.run_until_complete(_query())
        except RuntimeError:
            return asyncio.run(_query())

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_toml(path: Path) -> dict:
        import tomllib  # Available in Python 3.11+ standard library

        with path.open("rb") as fh:
            return tomllib.load(fh)

    @staticmethod
    def _write_toml(path: Path, data: dict) -> None:
        """Serialise *data* to a TOML file at *path*.

        This implementation handles the data types produced by
        :func:`_client_to_dict` (str, int, bool, list[str], list[int], dict)
        without requiring an external ``tomli_w`` dependency.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        lines: list[str] = _dict_to_toml_lines(data)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
