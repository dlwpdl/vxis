"""Integration hook implementations.

All hooks subclass :class:`IntegrationHook` and override one or more of
``on_finding``, ``on_critical``, and ``on_scan_complete``. Every hook
must fail gracefully — if credentials are missing or the remote API
returns an error, the hook logs a warning and returns without raising.

Bilingual messages follow the project convention ``"English|||한국어"``.

Supported environment variables (see ``registry.load_hooks_from_env``):

* ``VXIS_SLACK_WEBHOOK``       — Slack incoming webhook URL
* ``VXIS_DISCORD_WEBHOOK``     — Discord webhook URL
* ``VXIS_JIRA_URL``            — Jira base URL (e.g. https://acme.atlassian.net)
* ``VXIS_JIRA_TOKEN``          — Jira API token (Basic auth or PAT)
* ``VXIS_JIRA_PROJECT``        — Jira project key (e.g. SEC)
* ``VXIS_LINEAR_API_KEY``      — Linear personal API key
* ``VXIS_LINEAR_TEAM_ID``      — Linear team UUID
* ``VXIS_GITHUB_REPO``         — GitHub repo in ``owner/name`` form
* ``VXIS_GITHUB_TOKEN``        — GitHub PAT with ``issues:write``
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any
from urllib import error as _urlerror
from urllib import request as _urlrequest

logger = logging.getLogger(__name__)

_TIMEOUT = 5.0


def _post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    method: str = "POST",
) -> tuple[bool, str]:
    """POST JSON via urllib. Returns (ok, body_or_error)."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = _urlrequest.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "VXIS-Integrations/1.0")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        with _urlrequest.urlopen(req, timeout=_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return (200 <= resp.status < 300, body)
    except _urlerror.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body = str(exc)
        return False, f"HTTP {exc.code}: {body}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _split_bilingual(text: str | None) -> tuple[str, str]:
    """Split ``"en|||ko"`` strings, falling back to the same value."""
    if not text:
        return "", ""
    if "|||" in text:
        en, ko = text.split("|||", 1)
        return en.strip(), ko.strip()
    return text.strip(), text.strip()


# ──────────────────────────────────────────────────────────────────────
# Base
# ──────────────────────────────────────────────────────────────────────


class IntegrationHook:
    """Base class for VXIS notification hooks.

    Subclasses override the methods they care about. The default
    implementations are no-ops, so partial implementations are fine.
    """

    name: str = "integration"

    def __init__(self) -> None:
        self.enabled: bool = True

    # Lifecycle hooks --------------------------------------------------
    def on_finding(self, finding: Any) -> None:  # noqa: ARG002
        """Called for each high/critical finding after scoring."""
        return None

    def on_critical(self, finding: Any) -> None:  # noqa: ARG002
        """Called only for findings with severity == critical."""
        return None

    def on_scan_complete(self, ctx: Any) -> None:  # noqa: ARG002
        """Called once when the scan finishes (after scoring)."""
        return None

    def test(self) -> tuple[bool, str]:
        """Send a synthetic test notification. Override per hook."""
        return False, "test() not implemented"

    # Helpers ----------------------------------------------------------
    @staticmethod
    def _format_finding_text(finding: Any) -> tuple[str, str]:
        title = _get(finding, "title", "VXIS Finding")
        en, ko = _split_bilingual(title)
        sev = _get(finding, "severity", "")
        sev_str = getattr(sev, "value", str(sev))
        fid = _get(finding, "id", "?")
        target = _get(finding, "target", "?")
        en_msg = f"[{sev_str.upper()}] {fid} — {en}\nTarget: {target}"
        ko_msg = f"[{sev_str.upper()}] {fid} — {ko}\n대상: {target}"
        return en_msg, ko_msg


# ──────────────────────────────────────────────────────────────────────
# Slack
# ──────────────────────────────────────────────────────────────────────


class SlackWebhookHook(IntegrationHook):
    """Sends notifications to a Slack incoming webhook URL.

    Env: ``VXIS_SLACK_WEBHOOK``
    """

    name = "slack"

    def __init__(self, webhook_url: str | None) -> None:
        super().__init__()
        self.webhook_url = webhook_url
        if not webhook_url:
            self.enabled = False
            logger.warning("[slack] disabled — VXIS_SLACK_WEBHOOK not set")

    def _send(self, text_en: str, text_ko: str) -> tuple[bool, str]:
        if not self.enabled or not self.webhook_url:
            return False, "disabled"
        payload = {"text": f"{text_en}\n———\n{text_ko}"}
        ok, body = _post_json(self.webhook_url, payload)
        if not ok:
            logger.warning("[slack] send failed: %s", body)
        return ok, body

    def on_finding(self, finding: Any) -> None:
        en, ko = self._format_finding_text(finding)
        self._send(f":warning: VXIS Finding\n{en}", f":warning: VXIS 발견 항목\n{ko}")

    def on_critical(self, finding: Any) -> None:
        en, ko = self._format_finding_text(finding)
        self._send(f":rotating_light: CRITICAL\n{en}", f":rotating_light: 심각\n{ko}")

    def on_scan_complete(self, ctx: Any) -> None:
        target = _get(ctx, "target", "?")
        n = len(_get(ctx, "findings", []) or [])
        score = _get(ctx, "vxis_score", None)
        total = getattr(score, "total", "?")
        grade = getattr(score, "grade", "?")
        en = f":white_check_mark: VXIS scan complete — {target}\nFindings: {n} | Score: {total} ({grade})"
        ko = f":white_check_mark: VXIS 스캔 완료 — {target}\n발견: {n}건 | 점수: {total} ({grade})"
        self._send(en, ko)

    def test(self) -> tuple[bool, str]:
        return self._send(
            "VXIS integration test — Slack OK",
            "VXIS 통합 테스트 — Slack 정상",
        )


# ──────────────────────────────────────────────────────────────────────
# Discord
# ──────────────────────────────────────────────────────────────────────


class DiscordWebhookHook(IntegrationHook):
    """Sends notifications to a Discord webhook.

    Env: ``VXIS_DISCORD_WEBHOOK``
    """

    name = "discord"

    def __init__(self, webhook_url: str | None) -> None:
        super().__init__()
        self.webhook_url = webhook_url
        if not webhook_url:
            self.enabled = False
            logger.warning("[discord] disabled — VXIS_DISCORD_WEBHOOK not set")

    def _send(self, content_en: str, content_ko: str) -> tuple[bool, str]:
        if not self.enabled or not self.webhook_url:
            return False, "disabled"
        payload = {"content": f"**EN**\n{content_en}\n\n**KO**\n{content_ko}"}
        ok, body = _post_json(self.webhook_url, payload)
        if not ok:
            logger.warning("[discord] send failed: %s", body)
        return ok, body

    def on_finding(self, finding: Any) -> None:
        en, ko = self._format_finding_text(finding)
        self._send(en, ko)

    def on_critical(self, finding: Any) -> None:
        en, ko = self._format_finding_text(finding)
        self._send(f":rotating_light: CRITICAL\n{en}", f":rotating_light: 심각\n{ko}")

    def on_scan_complete(self, ctx: Any) -> None:
        target = _get(ctx, "target", "?")
        n = len(_get(ctx, "findings", []) or [])
        self._send(
            f"VXIS scan complete — {target} ({n} findings)",
            f"VXIS 스캔 완료 — {target} ({n}건)",
        )

    def test(self) -> tuple[bool, str]:
        return self._send(
            "VXIS integration test — Discord OK",
            "VXIS 통합 테스트 — Discord 정상",
        )


# ──────────────────────────────────────────────────────────────────────
# Jira
# ──────────────────────────────────────────────────────────────────────


class JiraIssueHook(IntegrationHook):
    """Creates Jira issues via the REST API v3.

    Env: ``VXIS_JIRA_URL``, ``VXIS_JIRA_TOKEN``, ``VXIS_JIRA_PROJECT``

    The token is sent as a bearer token. For Atlassian Cloud Basic auth,
    pass ``"<email>:<api_token>"`` and it will be base64-encoded.
    """

    name = "jira"

    def __init__(
        self,
        url: str | None,
        api_token: str | None,
        project_key: str | None,
    ) -> None:
        super().__init__()
        self.url = (url or "").rstrip("/")
        self.api_token = api_token or ""
        self.project_key = project_key or ""
        if not (self.url and self.api_token and self.project_key):
            self.enabled = False
            logger.warning(
                "[jira] disabled — VXIS_JIRA_URL/VXIS_JIRA_TOKEN/VXIS_JIRA_PROJECT not all set"
            )

    def _auth_header(self) -> dict[str, str]:
        if ":" in self.api_token:
            b64 = base64.b64encode(self.api_token.encode("utf-8")).decode("ascii")
            return {"Authorization": f"Basic {b64}"}
        return {"Authorization": f"Bearer {self.api_token}"}

    def _create_issue(self, summary: str, description: str, severity: str = "") -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        payload = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": summary[:250],
                "description": description,
                "issuetype": {"name": "Bug"},
                "labels": ["vxis", f"severity-{severity}" if severity else "vxis"],
            }
        }
        ok, body = _post_json(
            f"{self.url}/rest/api/2/issue",
            payload,
            headers=self._auth_header(),
        )
        if not ok:
            logger.warning("[jira] create issue failed: %s", body)
        return ok, body

    def on_finding(self, finding: Any) -> None:
        en, ko = self._format_finding_text(finding)
        sev = _get(finding, "severity", "")
        sev_str = getattr(sev, "value", str(sev))
        desc = _get(finding, "description", "") or ""
        self._create_issue(
            summary=f"[VXIS] {en.splitlines()[0]}",
            description=f"{en}\n\n---\n{ko}\n\n{desc}",
            severity=sev_str,
        )

    def on_critical(self, finding: Any) -> None:
        # on_finding already covers it; subclass can override.
        return None

    def test(self) -> tuple[bool, str]:
        return self._create_issue(
            "VXIS integration test",
            "This is a test issue from VXIS|||VXIS 통합 테스트 이슈입니다",
            severity="informational",
        )


# ──────────────────────────────────────────────────────────────────────
# Linear
# ──────────────────────────────────────────────────────────────────────


class LinearIssueHook(IntegrationHook):
    """Creates Linear issues via GraphQL.

    Env: ``VXIS_LINEAR_API_KEY``, ``VXIS_LINEAR_TEAM_ID``
    """

    name = "linear"
    _ENDPOINT = "https://api.linear.app/graphql"

    def __init__(self, api_key: str | None, team_id: str | None) -> None:
        super().__init__()
        self.api_key = api_key or ""
        self.team_id = team_id or ""
        if not (self.api_key and self.team_id):
            self.enabled = False
            logger.warning(
                "[linear] disabled — VXIS_LINEAR_API_KEY/VXIS_LINEAR_TEAM_ID not set"
            )

    def _create_issue(self, title: str, description: str) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        query = (
            "mutation IssueCreate($title: String!, $description: String!, $teamId: String!) {"
            "  issueCreate(input: {title: $title, description: $description, teamId: $teamId}) {"
            "    success issue { id identifier url }"
            "  }"
            "}"
        )
        payload = {
            "query": query,
            "variables": {
                "title": title[:250],
                "description": description,
                "teamId": self.team_id,
            },
        }
        ok, body = _post_json(
            self._ENDPOINT,
            payload,
            headers={"Authorization": self.api_key},
        )
        if not ok:
            logger.warning("[linear] create issue failed: %s", body)
        return ok, body

    def on_finding(self, finding: Any) -> None:
        en, ko = self._format_finding_text(finding)
        desc = _get(finding, "description", "") or ""
        self._create_issue(
            title=f"[VXIS] {en.splitlines()[0]}",
            description=f"{en}\n\n---\n{ko}\n\n{desc}",
        )

    def test(self) -> tuple[bool, str]:
        return self._create_issue(
            "VXIS integration test",
            "Test issue from VXIS|||VXIS 통합 테스트 이슈",
        )


# ──────────────────────────────────────────────────────────────────────
# GitHub
# ──────────────────────────────────────────────────────────────────────


class GitHubIssueHook(IntegrationHook):
    """Creates GitHub issues via REST API.

    Env: ``VXIS_GITHUB_REPO`` (e.g. ``owner/name``), ``VXIS_GITHUB_TOKEN``
    """

    name = "github"

    def __init__(self, repo: str | None, token: str | None) -> None:
        super().__init__()
        self.repo = repo or ""
        self.token = token or ""
        if not (self.repo and self.token and "/" in self.repo):
            self.enabled = False
            logger.warning(
                "[github] disabled — VXIS_GITHUB_REPO/VXIS_GITHUB_TOKEN not set or invalid"
            )

    def _create_issue(
        self,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> tuple[bool, str]:
        if not self.enabled:
            return False, "disabled"
        url = f"https://api.github.com/repos/{self.repo}/issues"
        payload: dict[str, Any] = {
            "title": title[:250],
            "body": body,
            "labels": labels or ["vxis"],
        }
        ok, resp = _post_json(
            url,
            payload,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
            },
        )
        if not ok:
            logger.warning("[github] create issue failed: %s", resp)
        return ok, resp

    def on_finding(self, finding: Any) -> None:
        en, ko = self._format_finding_text(finding)
        sev = _get(finding, "severity", "")
        sev_str = getattr(sev, "value", str(sev))
        desc = _get(finding, "description", "") or ""
        self._create_issue(
            title=f"[VXIS] {en.splitlines()[0]}",
            body=f"{en}\n\n---\n{ko}\n\n{desc}",
            labels=["vxis", f"severity:{sev_str}" if sev_str else "vxis"],
        )

    def test(self) -> tuple[bool, str]:
        return self._create_issue(
            "VXIS integration test",
            "Test issue from VXIS|||VXIS 통합 테스트 이슈",
        )
