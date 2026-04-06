"""Hook registry — discovers configured integrations from environment.

If no env vars are set, ``load_hooks_from_env`` returns an empty list and
the rest of the pipeline becomes a complete no-op. This is intentional:
the framework must never error out simply because a user has no
integrations configured.

Recognised env vars
-------------------
``VXIS_SLACK_WEBHOOK``
    Slack incoming webhook URL.
``VXIS_DISCORD_WEBHOOK``
    Discord webhook URL.
``VXIS_JIRA_URL`` + ``VXIS_JIRA_TOKEN`` + ``VXIS_JIRA_PROJECT``
    All three required to enable Jira issue creation.
``VXIS_LINEAR_API_KEY`` + ``VXIS_LINEAR_TEAM_ID``
    Both required to enable Linear issue creation.
``VXIS_GITHUB_REPO`` (``owner/name``) + ``VXIS_GITHUB_TOKEN``
    Both required to enable GitHub issue creation.
"""

from __future__ import annotations

import logging
import os

from vxis.integrations.hooks import (
    DiscordWebhookHook,
    GitHubIssueHook,
    IntegrationHook,
    JiraIssueHook,
    LinearIssueHook,
    SlackWebhookHook,
)

logger = logging.getLogger(__name__)


def load_hooks_from_env() -> list[IntegrationHook]:
    """Inspect environment variables and return enabled hooks only."""
    hooks: list[IntegrationHook] = []

    slack = os.getenv("VXIS_SLACK_WEBHOOK")
    if slack:
        h = SlackWebhookHook(slack)
        if h.enabled:
            hooks.append(h)

    discord = os.getenv("VXIS_DISCORD_WEBHOOK")
    if discord:
        h = DiscordWebhookHook(discord)
        if h.enabled:
            hooks.append(h)

    jira_url = os.getenv("VXIS_JIRA_URL")
    jira_token = os.getenv("VXIS_JIRA_TOKEN")
    jira_project = os.getenv("VXIS_JIRA_PROJECT")
    if jira_url and jira_token and jira_project:
        h = JiraIssueHook(jira_url, jira_token, jira_project)
        if h.enabled:
            hooks.append(h)

    linear_key = os.getenv("VXIS_LINEAR_API_KEY")
    linear_team = os.getenv("VXIS_LINEAR_TEAM_ID")
    if linear_key and linear_team:
        h = LinearIssueHook(linear_key, linear_team)
        if h.enabled:
            hooks.append(h)

    gh_repo = os.getenv("VXIS_GITHUB_REPO")
    gh_token = os.getenv("VXIS_GITHUB_TOKEN")
    if gh_repo and gh_token:
        h = GitHubIssueHook(gh_repo, gh_token)
        if h.enabled:
            hooks.append(h)

    if hooks:
        logger.info("[integrations] loaded %d hook(s): %s",
                    len(hooks), ", ".join(h.name for h in hooks))
    return hooks
