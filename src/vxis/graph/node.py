from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field


class NodeType(str, Enum):
    ASSET = "asset"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    ACCESS = "access"
    DATA = "data"


@dataclass
class GraphNode:
    id: str
    title: str
    severity: str
    node_type: NodeType
    agent_id: str
    description: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    label: str = "leads_to"
    weight: float = 1.0
