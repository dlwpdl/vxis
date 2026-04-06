"""VXIS integrations — webhook hooks for external systems.

Provides pluggable notification hooks for Slack, Discord, Jira, Linear,
and GitHub. All hooks are no-ops unless the corresponding environment
variables are configured. See ``registry.load_hooks_from_env`` for the
list of supported env vars.
"""

from vxis.integrations.hooks import (
    DiscordWebhookHook,
    GitHubIssueHook,
    IntegrationHook,
    JiraIssueHook,
    LinearIssueHook,
    SlackWebhookHook,
)
from vxis.integrations.registry import load_hooks_from_env

__all__ = [
    "IntegrationHook",
    "SlackWebhookHook",
    "DiscordWebhookHook",
    "JiraIssueHook",
    "LinearIssueHook",
    "GitHubIssueHook",
    "load_hooks_from_env",
]
