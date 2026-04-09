"""Playbook loading tools — technique library for the Brain.

The Brain fingerprints a target, then loads the relevant playbook(s) to get
stack-specific probe recipes and interpretation rules. Playbooks are plain
markdown files in `src/vxis/agent/playbooks/`. This scales across targets
because technique knowledge is reusable across every app of the same stack.

Brain workflow:
    1. list_playbooks() → see what's available
    2. fingerprint target via http_request/browser_render
    3. load_playbook(name="spring_boot") → get the playbook content
    4. execute the recipes from the playbook
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)

# Locate the playbooks directory relative to this file
_PLAYBOOK_DIR = Path(__file__).parent.parent / "playbooks"


def _list_playbook_files() -> list[Path]:
    if not _PLAYBOOK_DIR.exists():
        return []
    return sorted(p for p in _PLAYBOOK_DIR.glob("*.md") if p.is_file())


def _get_playbook_names() -> list[str]:
    return [p.stem for p in _list_playbook_files()]


class ListPlaybooksTool:
    name = "list_playbooks"
    description = (
        "List all available attack playbooks. Each playbook is a stack-specific "
        "technique library (e.g. spring_boot, express_node_spa, php_wordpress). "
        "Call this FIRST so you know which playbooks exist, then fingerprint "
        "the target and load the relevant ones via load_playbook."
    )
    input_schema: dict[str, Any] = {"type": "object", "properties": {}}

    async def run(self, **kwargs: Any) -> ToolResult:
        files = _list_playbook_files()
        if not files:
            return ToolResult(
                ok=False,
                summary="no playbooks found",
                error="no_playbooks",
            )
        entries: list[dict[str, str]] = []
        for f in files:
            try:
                # Read first 3 lines of each playbook for a quick summary
                lines = f.read_text(encoding="utf-8").splitlines()
                title = next(
                    (line.lstrip("# ").strip() for line in lines if line.startswith("#")),
                    f.stem,
                )
                first_para = ""
                for line in lines[1:]:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        first_para = line[:200]
                        break
                entries.append({"name": f.stem, "title": title, "summary": first_para})
            except Exception as e:
                entries.append({"name": f.stem, "title": f.stem, "summary": f"(read error: {e})"})
        return ToolResult(
            ok=True,
            data={"count": len(entries), "playbooks": entries},
            summary=(
                f"{len(entries)} playbooks available: "
                + ", ".join(e["name"] for e in entries)
            ),
        )


# Module-level dedup: track which playbooks were already loaded in this
# process. Prevents Brain from wasting tokens re-loading the same playbook.
_loaded_playbooks: set[str] = set()


class LoadPlaybookTool:
    name = "load_playbook"
    description = (
        "Load a specific attack playbook by name. Returns the full markdown "
        "content including fingerprint indicators, probe recipes, interpretation "
        "rules, and post-exploitation chains. Use this AFTER fingerprinting the "
        "target. Substitute {{BASE_URL}} in the probe recipes with your actual "
        "target URL before executing them."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": (
                    "Playbook name (without .md extension). "
                    "Call list_playbooks first to see available options."
                ),
            },
        },
        "required": ["name"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        name = str(kwargs.get("name", "")).strip()
        if not name:
            return ToolResult(
                ok=False,
                summary="load_playbook: name is required",
                error="missing_name",
            )

        # Sanitize: only allow alphanumeric + underscore to prevent path traversal
        if not all(c.isalnum() or c == "_" for c in name):
            return ToolResult(
                ok=False,
                summary=f"load_playbook: invalid name '{name}' (alphanumeric + underscore only)",
                error="invalid_name",
            )

        path = _PLAYBOOK_DIR / f"{name}.md"
        if not path.exists():
            available = _get_playbook_names()
            return ToolResult(
                ok=False,
                summary=f"load_playbook: '{name}' not found. Available: {', '.join(available)}",
                error="not_found",
            )

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as e:
            return ToolResult(
                ok=False,
                summary=f"load_playbook: failed to read '{name}': {e}",
                error="read_failed",
            )

        # Dedup: if already loaded this process, return a short summary
        # instead of the full content to save tokens.
        if name in _loaded_playbooks:
            logger.info("Playbook already loaded (dedup): %s", name)
            return ToolResult(
                ok=True,
                data={"name": name, "length": len(content), "already_loaded": True},
                summary=(
                    f"playbook '{name}' already loaded earlier in this scan. "
                    "Re-read the probe recipes from your prior messages and "
                    "execute them — no need to reload."
                ),
            )
        _loaded_playbooks.add(name)
        logger.info("Loaded playbook: %s (%d chars)", name, len(content))
        return ToolResult(
            ok=True,
            data={
                "name": name,
                "length": len(content),
                "content": content,
            },
            summary=f"loaded playbook '{name}' ({len(content)} chars)",
        )
