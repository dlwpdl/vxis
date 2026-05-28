"""SDK-backed agent runtime primitives for the next VXIS scan loop."""

from vxis.agent.sdk_runtime.child_loop import SDKChildAgentLoop, SDKChildPrompt
from vxis.agent.sdk_runtime.coordinator import (
    ACTIVE_AGENT_STATUSES,
    TERMINAL_AGENT_STATUSES,
    AgentStatus,
    SDKAgentCoordinator,
    SDKAgentRecord,
)
from vxis.agent.sdk_runtime.events import SDKEventJournal
from vxis.agent.sdk_runtime.sessions import SDKRunPaths, open_sdk_agent_session
from vxis.agent.sdk_runtime.tools import (
    build_vxis_sdk_agent,
    make_vxis_model_settings,
    sdk_tool_from_registry,
    sdk_tools_from_registry,
)

__all__ = [
    "ACTIVE_AGENT_STATUSES",
    "TERMINAL_AGENT_STATUSES",
    "AgentStatus",
    "SDKChildAgentLoop",
    "SDKChildPrompt",
    "SDKAgentCoordinator",
    "SDKAgentRecord",
    "SDKEventJournal",
    "SDKRunPaths",
    "build_vxis_sdk_agent",
    "make_vxis_model_settings",
    "open_sdk_agent_session",
    "sdk_tool_from_registry",
    "sdk_tools_from_registry",
]
