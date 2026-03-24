from __future__ import annotations
from dataclasses import dataclass
from ..mission.config import MissionConfig
from ..graph.attack_graph import LivingAttackGraph
from ..evidence.engine import EvidenceEngine


@dataclass
class AgentContext:
    mission: MissionConfig
    attack_graph: LivingAttackGraph
    evidence_engine: EvidenceEngine
