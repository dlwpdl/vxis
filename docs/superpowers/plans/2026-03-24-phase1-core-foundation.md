# VXIS CRT Phase 1: Core Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Director Agent + Living Attack Graph + Mission Config + Base Agent Framework + Evidence Engine + CLI Live Display가 동작하는 골격 완성. 모든 상위 Phase는 이 위에 올라간다.

**Architecture:** Director Agent가 Mission Config를 받아 Living Attack Graph를 유지하면서 Base Agent들을 동적으로 스폰하고, 각 에이전트의 발견을 Evidence Engine이 캡처하며 CLI Live Display로 실시간 출력한다.

**Tech Stack:** Python 3.12+, asyncio, Claude API (claude-opus-4-6), NetworkX, Rich, SQLite, Pydantic v2

**Spec:** `docs/superpowers/specs/2026-03-24-autonomous-ai-pentest-engine-design.md`

---

## File Map

```
src/vxis/
├── agent/
│   ├── __init__.py
│   ├── base.py               # BaseAgent 추상 클래스
│   ├── director.py           # Director Agent (핵심 AI 루프)
│   ├── registry.py           # 에이전트 등록/스폰 팩토리
│   └── context.py            # 에이전트 간 공유 컨텍스트
├── graph/
│   ├── __init__.py
│   ├── attack_graph.py       # Living Attack Graph (NetworkX)
│   ├── node.py               # 그래프 노드 타입 정의
│   └── hypothesis.py         # Hypothesis Queue + 생성 로직
├── mission/
│   ├── __init__.py
│   ├── config.py             # Mission Config 파서 (Pydantic)
│   └── selector.py           # Config → Agent 목록 매핑
├── evidence/
│   ├── __init__.py
│   ├── engine.py             # Evidence 수집/저장
│   └── schema.py             # Evidence 데이터 모델
├── display/
│   ├── __init__.py
│   └── live.py               # Rich 기반 Live Display (CRT 버전)
└── llm/
    ├── __init__.py
    └── client.py             # Claude API 클라이언트 래퍼

tests/
├── unit/
│   ├── test_attack_graph.py
│   ├── test_hypothesis.py
│   ├── test_mission_config.py
│   ├── test_base_agent.py
│   ├── test_evidence.py
│   └── test_director.py
└── integration/
    └── test_phase1_smoke.py
```

---

## Task 1: Mission Config 파서

**Files:**
- Create: `src/vxis/mission/config.py`
- Create: `src/vxis/mission/__init__.py`
- Create: `src/vxis/mission/selector.py`
- Test: `tests/unit/test_mission_config.py`

- [ ] **Step 1: 실패 테스트 작성**

```python
# tests/unit/test_mission_config.py
import pytest
from vxis.mission.config import MissionConfig, Depth, Perspective, Scope

def test_mission_config_defaults():
    cfg = MissionConfig(target="example.com")
    assert cfg.depth == Depth.NORMAL
    assert cfg.stealth == False
    assert cfg.perspective == Perspective.EXTERNAL

def test_mission_config_full():
    cfg = MissionConfig(
        target="*.acme.com",
        depth=Depth.ELITE,
        stealth=True,
        perspective=Perspective.BOTH,
        scope=Scope.FULL,
        client_id="acme-corp",
    )
    assert cfg.target == "*.acme.com"
    assert cfg.depth == Depth.ELITE
    assert cfg.stealth == True

def test_mission_config_from_toml(tmp_path):
    toml_content = """
[mission]
target = "*.acme.com"
depth = "elite"
stealth = true
perspective = "external"
scope = "full"

[memory]
client_id = "acme-corp"
learn = true
"""
    cfg_file = tmp_path / "mission.toml"
    cfg_file.write_text(toml_content)
    cfg = MissionConfig.from_file(str(cfg_file))
    assert cfg.target == "*.acme.com"
    assert cfg.depth == Depth.ELITE

def test_invalid_depth_raises():
    with pytest.raises(ValueError):
        MissionConfig(target="example.com", depth="ultra")
```

- [ ] **Step 2: 테스트 실패 확인**

```bash
pytest tests/unit/test_mission_config.py -v
```
Expected: ImportError 또는 4개 FAIL

- [ ] **Step 3: Mission Config 구현**

```python
# src/vxis/mission/config.py
from __future__ import annotations
from enum import Enum
from pathlib import Path
from typing import Optional
import tomllib
from pydantic import BaseModel, field_validator


class Depth(str, Enum):
    PASSIVE = "passive"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    ELITE = "elite"


class Perspective(str, Enum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    BOTH = "both"


class Scope(str, Enum):
    WEB = "web"
    CLOUD = "cloud"
    CODE = "code"
    NETWORK = "network"
    MOBILE = "mobile"
    FULL = "full"
    CUSTOM = "custom"


class MemoryConfig(BaseModel):
    client_id: str = "default"
    learn: bool = True


class MissionConfig(BaseModel):
    target: str
    depth: Depth = Depth.NORMAL
    stealth: bool = False
    perspective: Perspective = Perspective.EXTERNAL
    scope: Scope = Scope.FULL
    custom_agents: list[str] = []
    memory: MemoryConfig = MemoryConfig()

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target cannot be empty")
        return v.strip()

    @classmethod
    def from_file(cls, path: str) -> "MissionConfig":
        data = Path(path).read_bytes()
        parsed = tomllib.loads(data.decode())
        mission = parsed.get("mission", {})
        memory = parsed.get("memory", {})
        return cls(**mission, memory=MemoryConfig(**memory))
```

```python
# src/vxis/mission/__init__.py
from .config import MissionConfig, Depth, Perspective, Scope

__all__ = ["MissionConfig", "Depth", "Perspective", "Scope"]
```

- [ ] **Step 4: 테스트 통과 확인**

```bash
pytest tests/unit/test_mission_config.py -v
```
Expected: 4개 PASS

- [ ] **Step 5: Agent Selector 테스트 작성**

```python
# 같은 파일에 추가
from vxis.mission.selector import AgentSelector

def test_selector_web_scope():
    cfg = MissionConfig(target="example.com", scope=Scope.WEB)
    agents = AgentSelector.select(cfg)
    assert "web" in agents
    assert "api" in agents
    assert "ics_scada" not in agents

def test_selector_stealth_disables_dos():
    cfg = MissionConfig(target="example.com", stealth=True)
    agents = AgentSelector.select(cfg)
    assert "dos_resilience" not in agents
    assert "deception_detection" in agents

def test_selector_elite_enables_fuzzing():
    cfg = MissionConfig(target="example.com", depth=Depth.ELITE)
    agents = AgentSelector.select(cfg)
    assert "fuzzing_zerodday" in agents

def test_selector_internal_adds_ad():
    cfg = MissionConfig(target="10.0.0.0/8", perspective=Perspective.INTERNAL)
    agents = AgentSelector.select(cfg)
    assert "identity_ad" in agents
    assert "lateral_move" in agents
```

- [ ] **Step 6: AgentSelector 구현**

```python
# src/vxis/mission/selector.py
from __future__ import annotations
from .config import MissionConfig, Depth, Perspective, Scope

# 스코프별 기본 에이전트
SCOPE_AGENTS: dict[str, list[str]] = {
    "web": ["recon", "osint", "subdomain_takeover", "threat_intel",
            "web", "api", "http_protocol", "browser_client",
            "email_security", "crypto_tls", "compliance"],
    "cloud": ["recon", "cloud", "container_k8s", "supply_chain",
              "secrets_lifecycle", "iam_deep", "compliance"],
    "code": ["supply_chain", "secrets_lifecycle", "deserialization",
             "sast", "sbom", "compliance"],
    "network": ["recon", "network", "l2_network", "ipv6",
                "bgp_routing", "legacy_protocol", "voip"],
    "mobile": ["mobile", "web", "api", "crypto_tls"],
    "full": [],  # all agents
}

# 전체 에이전트 목록
ALL_AGENTS: list[str] = [
    # L1
    "physical_usb", "side_channel", "dma_attack",
    # L2
    "l2_network", "wireless", "bluetooth_deep",
    # L3
    "network", "bgp_routing", "ipv6",
    # L4
    "crypto_tls", "quic_http3", "dtls",
    # L5
    "identity_ad", "remote_access",
    # L6
    "deserialization", "encoding_attack",
    # L7
    "recon", "osint", "subdomain_takeover", "threat_intel",
    "web", "api", "http_protocol", "mobile", "browser_client",
    "web3_blockchain", "dns_deep", "email_security", "voip",
    "cloud", "container_k8s", "database", "supply_chain",
    "iot_firmware", "ics_scada", "legacy_protocol",
    "message_queue", "big_data_analytics", "cms_biz_platform",
    "collaboration", "monitoring_stack", "cdn_edge",
    "secrets_lifecycle", "third_party_webhook", "backup_dr",
    "game_realtime",
    # H
    "phishing_intel", "ss7_cellular", "ntp_time", "cold_boot_memory",
    # S
    "ai_llm", "adversarial_ai", "os_host", "lateral_move",
    "dos_resilience", "data_exfiltration", "fuzzing_zerodday",
    "business_logic", "deception_detection", "compliance",
    "quantum_risk", "virtualization",
]

# depth별 항상 비활성
DEPTH_DISABLED: dict[str, list[str]] = {
    "passive": ["dos_resilience", "fuzzing_zerodday", "side_channel",
                "dma_attack", "ss7_cellular", "cold_boot_memory",
                "deserialization", "data_exfiltration"],
    "normal": ["fuzzing_zerodday", "side_channel", "dma_attack",
               "ss7_cellular", "cold_boot_memory"],
    "aggressive": ["fuzzing_zerodday"],
    "elite": [],
}

# 내부 관점 추가 에이전트
INTERNAL_AGENTS = ["identity_ad", "remote_access", "os_host",
                   "lateral_move", "l2_network", "wireless",
                   "legacy_protocol", "ics_scada", "cold_boot_memory"]

STEALTH_DISABLED = ["dos_resilience", "fuzzing_zerodday",
                    "side_channel", "ss7_cellular"]
STEALTH_FORCED = ["deception_detection"]


class AgentSelector:
    @classmethod
    def select(cls, cfg: MissionConfig) -> list[str]:
        # 기본 풀
        if cfg.scope == Scope.FULL:
            pool = ALL_AGENTS.copy()
        elif cfg.scope == Scope.CUSTOM:
            pool = cfg.custom_agents.copy()
        else:
            pool = SCOPE_AGENTS.get(cfg.scope.value, ALL_AGENTS.copy())

        # depth 비활성
        disabled = set(DEPTH_DISABLED.get(cfg.depth.value, []))

        # stealth 조정
        if cfg.stealth:
            disabled.update(STEALTH_DISABLED)
            for agent in STEALTH_FORCED:
                if agent not in pool:
                    pool.append(agent)

        # 내부 관점 추가
        if cfg.perspective.value in ("internal", "both"):
            for agent in INTERNAL_AGENTS:
                if agent not in pool:
                    pool.append(agent)

        return [a for a in pool if a not in disabled]
```

- [ ] **Step 7: 테스트 통과 확인**

```bash
pytest tests/unit/test_mission_config.py -v
```
Expected: 8개 PASS

- [ ] **Step 8: 커밋**

```bash
git add src/vxis/mission/ tests/unit/test_mission_config.py
git commit -m "feat(crt): Mission Config 파서 + AgentSelector"
```

---

## Task 2: Evidence Engine

**Files:**
- Create: `src/vxis/evidence/schema.py`
- Create: `src/vxis/evidence/engine.py`
- Create: `src/vxis/evidence/__init__.py`
- Test: `tests/unit/test_evidence_engine.py`

- [ ] **Step 1: 실패 테스트 작성**

```python
# tests/unit/test_evidence_engine.py
import pytest
import asyncio
from datetime import datetime
from vxis.evidence.engine import EvidenceEngine
from vxis.evidence.schema import Evidence, Severity, EvidenceType

def test_evidence_schema():
    ev = Evidence(
        agent_id="web",
        title="SQL Injection in /login",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        description="Login endpoint vulnerable to SQLi",
        request="POST /login HTTP/1.1\n...",
        response="HTTP/1.1 500 Internal Server Error\n...",
        cvss_score=9.8,
    )
    assert ev.id is not None          # UUID 자동 생성
    assert ev.timestamp is not None   # 자동 타임스탬프
    assert ev.hash is not None        # SHA-256 자동 계산

def test_evidence_hash_immutable():
    ev = Evidence(
        agent_id="web",
        title="XSS",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        description="Reflected XSS",
    )
    original_hash = ev.hash
    # 같은 데이터면 같은 해시
    ev2 = Evidence(
        agent_id="web",
        title="XSS",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        description="Reflected XSS",
    )
    # 해시는 내용 기반 (타임스탬프 제외)
    assert ev.hash == ev2.hash

@pytest.mark.asyncio
async def test_engine_save_and_retrieve(tmp_path):
    engine = EvidenceEngine(db_path=str(tmp_path / "evidence.db"))
    await engine.init()

    ev = Evidence(
        agent_id="cloud",
        title="S3 Bucket Public",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 bucket acme-dev is publicly accessible",
    )
    await engine.save(ev)

    results = await engine.get_by_severity(Severity.CRITICAL)
    assert len(results) == 1
    assert results[0].title == "S3 Bucket Public"

@pytest.mark.asyncio
async def test_engine_chain_linking(tmp_path):
    engine = EvidenceEngine(db_path=str(tmp_path / "evidence.db"))
    await engine.init()

    parent = Evidence(
        agent_id="cloud",
        title="S3 Public",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 public access",
    )
    await engine.save(parent)

    child = Evidence(
        agent_id="secrets",
        title=".env found in S3",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="DB credentials in .env",
        chained_from=parent.id,
    )
    await engine.save(child)

    chain = await engine.get_chain(parent.id)
    assert len(chain) == 1
    assert chain[0].id == child.id
```

- [ ] **Step 2: 실패 확인**

```bash
pytest tests/unit/test_evidence_engine.py -v
```
Expected: ImportError

- [ ] **Step 3: Evidence 스키마 구현**

```python
# src/vxis/evidence/schema.py
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceType(str, Enum):
    HTTP_EXCHANGE = "http_exchange"
    MISCONFIGURATION = "misconfiguration"
    SECRET = "secret"
    CODE_FINDING = "code_finding"
    NETWORK = "network"
    OSINT = "osint"
    EXPLOIT = "exploit"
    OTHER = "other"


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    agent_id: str
    title: str
    severity: Severity
    evidence_type: EvidenceType
    description: str
    request: Optional[str] = None
    response: Optional[str] = None
    cvss_score: Optional[float] = None
    chained_from: Optional[str] = None   # 부모 Evidence ID
    poc_script: Optional[str] = None
    tags: list[str] = []
    hash: str = ""

    @model_validator(mode="after")
    def compute_hash(self) -> "Evidence":
        # 타임스탬프, id 제외한 내용 기반 해시
        content = (
            f"{self.agent_id}:{self.title}:{self.severity}:"
            f"{self.description}:{self.request}:{self.response}"
        )
        self.hash = hashlib.sha256(content.encode()).hexdigest()
        return self
```

- [ ] **Step 4: Evidence Engine 구현**

```python
# src/vxis/evidence/engine.py
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from typing import Optional
from .schema import Evidence, Severity


class EvidenceEngine:
    def __init__(self, db_path: str = "evidence.db"):
        self.db_path = db_path

    async def init(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                description TEXT NOT NULL,
                chained_from TEXT,
                hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    async def save(self, ev: Evidence) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """INSERT OR REPLACE INTO evidence
               (id, timestamp, agent_id, title, severity,
                evidence_type, description, chained_from, hash, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ev.id,
                ev.timestamp.isoformat(),
                ev.agent_id,
                ev.title,
                ev.severity.value,
                ev.evidence_type.value,
                ev.description,
                ev.chained_from,
                ev.hash,
                ev.model_dump_json(),
            ),
        )
        conn.commit()
        conn.close()

    async def get_by_severity(self, severity: Severity) -> list[Evidence]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT raw_json FROM evidence WHERE severity = ?",
            (severity.value,),
        ).fetchall()
        conn.close()
        return [Evidence.model_validate_json(r[0]) for r in rows]

    async def get_chain(self, parent_id: str) -> list[Evidence]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT raw_json FROM evidence WHERE chained_from = ?",
            (parent_id,),
        ).fetchall()
        conn.close()
        return [Evidence.model_validate_json(r[0]) for r in rows]

    async def get_all(self) -> list[Evidence]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT raw_json FROM evidence ORDER BY timestamp"
        ).fetchall()
        conn.close()
        return [Evidence.model_validate_json(r[0]) for r in rows]
```

```python
# src/vxis/evidence/__init__.py
from .schema import Evidence, Severity, EvidenceType
from .engine import EvidenceEngine

__all__ = ["Evidence", "Severity", "EvidenceType", "EvidenceEngine"]
```

- [ ] **Step 5: 테스트 통과 확인**

```bash
pytest tests/unit/test_evidence_engine.py -v
```
Expected: 4개 PASS

- [ ] **Step 6: 커밋**

```bash
git add src/vxis/evidence/ tests/unit/test_evidence_engine.py
git commit -m "feat(crt): Evidence Engine — 불변 해시 + 체인 링킹"
```

---

## Task 3: Living Attack Graph

**Files:**
- Create: `src/vxis/graph/node.py`
- Create: `src/vxis/graph/attack_graph.py`
- Create: `src/vxis/graph/hypothesis.py`
- Create: `src/vxis/graph/__init__.py`
- Test: `tests/unit/test_attack_graph.py`

- [ ] **Step 1: 실패 테스트 작성**

```python
# tests/unit/test_attack_graph.py
import pytest
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.graph.node import GraphNode, NodeType
from vxis.evidence.schema import Evidence, Severity, EvidenceType

def make_evidence(title, severity=Severity.HIGH, agent="web"):
    return Evidence(
        agent_id=agent,
        title=title,
        severity=severity,
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        description=title,
    )

def test_graph_add_node():
    graph = LivingAttackGraph()
    ev = make_evidence("S3 Public Access", Severity.HIGH, "cloud")
    graph.add_finding(ev)
    assert len(graph.nodes) == 1

def test_graph_chain_creates_edge():
    graph = LivingAttackGraph()
    ev1 = make_evidence("S3 Public", Severity.HIGH, "cloud")
    graph.add_finding(ev1)

    ev2 = Evidence(
        agent_id="secrets",
        title=".env in S3",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="DB creds found",
        chained_from=ev1.id,
    )
    graph.add_finding(ev2)

    assert len(graph.edges) == 1
    edges = graph.get_edges_from(ev1.id)
    assert len(edges) == 1
    assert edges[0].target_id == ev2.id

def test_graph_critical_chain_detection():
    graph = LivingAttackGraph()
    ev1 = make_evidence("S3 Public", Severity.HIGH, "cloud")
    graph.add_finding(ev1)

    ev2 = Evidence(
        agent_id="secrets",
        title=".env DB Creds",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="DB credentials",
        chained_from=ev1.id,
    )
    graph.add_finding(ev2)

    ev3 = Evidence(
        agent_id="database",
        title="Direct DB Access",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.EXPLOIT,
        description="Full DB access",
        chained_from=ev2.id,
    )
    graph.add_finding(ev3)

    chains = graph.find_critical_chains()
    assert len(chains) >= 1
    assert len(chains[0]) == 3  # 3단계 체인

def test_graph_attack_surface_summary():
    graph = LivingAttackGraph()
    for title in ["Finding A", "Finding B", "Finding C"]:
        graph.add_finding(make_evidence(title, Severity.HIGH))

    summary = graph.summary()
    assert summary["total_findings"] == 3
    assert summary["critical"] == 0
    assert summary["high"] == 3
```

- [ ] **Step 2: 실패 확인**

```bash
pytest tests/unit/test_attack_graph.py -v
```
Expected: ImportError

- [ ] **Step 3: GraphNode 구현**

```python
# src/vxis/graph/node.py
from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


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
```

- [ ] **Step 4: LivingAttackGraph 구현**

```python
# src/vxis/graph/attack_graph.py
from __future__ import annotations
from typing import Optional
import networkx as nx
from .node import GraphNode, GraphEdge, NodeType
from ..evidence.schema import Evidence, Severity


class LivingAttackGraph:
    def __init__(self):
        self._graph = nx.DiGraph()
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    @property
    def nodes(self) -> dict[str, GraphNode]:
        return self._nodes

    @property
    def edges(self) -> list[GraphEdge]:
        return self._edges

    def add_finding(self, evidence: Evidence) -> None:
        node = GraphNode(
            id=evidence.id,
            title=evidence.title,
            severity=evidence.severity.value,
            node_type=NodeType.VULNERABILITY,
            agent_id=evidence.agent_id,
            description=evidence.description,
        )
        self._nodes[node.id] = node
        self._graph.add_node(node.id, data=node)

        if evidence.chained_from and evidence.chained_from in self._nodes:
            edge = GraphEdge(
                source_id=evidence.chained_from,
                target_id=evidence.id,
            )
            self._edges.append(edge)
            self._graph.add_edge(
                evidence.chained_from,
                evidence.id,
                label="leads_to",
            )

    def get_edges_from(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self._edges if e.source_id == node_id]

    def find_critical_chains(self) -> list[list[GraphNode]]:
        """Critical severity 노드로 끝나는 공격 체인 탐색"""
        critical_ids = {
            nid for nid, node in self._nodes.items()
            if node.severity == Severity.CRITICAL.value
        }
        chains = []
        for cid in critical_ids:
            # 이 노드에 도달하는 모든 경로 탐색
            for source in self._nodes:
                if source == cid:
                    continue
                try:
                    paths = list(nx.all_simple_paths(
                        self._graph, source, cid
                    ))
                    for path in paths:
                        if len(path) >= 2:
                            chain = [self._nodes[nid] for nid in path]
                            chains.append(chain)
                except (nx.NetworkXError, nx.NodeNotFound):
                    continue
        # 중복 제거 (가장 긴 체인 우선)
        seen = set()
        unique = []
        for chain in sorted(chains, key=len, reverse=True):
            key = tuple(n.id for n in chain)
            if key not in seen:
                seen.add(key)
                unique.append(chain)
        return unique

    def summary(self) -> dict:
        severity_counts = {}
        for node in self._nodes.values():
            severity_counts[node.severity] = (
                severity_counts.get(node.severity, 0) + 1
            )
        return {
            "total_findings": len(self._nodes),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "total_chains": len(self.find_critical_chains()),
            "total_edges": len(self._edges),
        }
```

```python
# src/vxis/graph/__init__.py
from .attack_graph import LivingAttackGraph
from .node import GraphNode, GraphEdge, NodeType

__all__ = ["LivingAttackGraph", "GraphNode", "GraphEdge", "NodeType"]
```

- [ ] **Step 5: 테스트 통과 확인**

```bash
pytest tests/unit/test_attack_graph.py -v
```
Expected: 4개 PASS

- [ ] **Step 6: 커밋**

```bash
git add src/vxis/graph/ tests/unit/test_attack_graph.py
git commit -m "feat(crt): Living Attack Graph — 체인 탐지 + 체이닝"
```

---

## Task 4: Hypothesis Engine

**Files:**
- Create: `src/vxis/graph/hypothesis.py`
- Test: `tests/unit/test_hypothesis.py`

- [ ] **Step 1: 실패 테스트 작성**

```python
# tests/unit/test_hypothesis.py
import pytest
from vxis.graph.hypothesis import Hypothesis, HypothesisQueue, HypothesisStatus

def test_hypothesis_creation():
    h = Hypothesis(
        title="GraphQL introspection enabled",
        rationale="Target has /graphql endpoint",
        probability=0.75,
        impact=0.9,
        suggested_agent="api",
        suggested_tool="graphql_introspect",
    )
    assert h.priority_score == pytest.approx(0.75 * 0.9, rel=1e-3)
    assert h.status == HypothesisStatus.PENDING

def test_hypothesis_queue_ordering():
    queue = HypothesisQueue()
    h1 = Hypothesis(
        title="Low priority",
        rationale="test",
        probability=0.3,
        impact=0.3,
        suggested_agent="web",
    )
    h2 = Hypothesis(
        title="High priority",
        rationale="test",
        probability=0.9,
        impact=0.95,
        suggested_agent="cloud",
    )
    queue.push(h1)
    queue.push(h2)

    top = queue.pop()
    assert top.title == "High priority"

def test_hypothesis_accept_reject():
    queue = HypothesisQueue()
    h = Hypothesis(
        title="Test hypo",
        rationale="test",
        probability=0.5,
        impact=0.5,
        suggested_agent="web",
    )
    queue.push(h)
    top = queue.pop()
    top.accept(note="Confirmed XSS at /search")
    assert top.status == HypothesisStatus.CONFIRMED

def test_queue_generates_from_finding():
    from vxis.graph.hypothesis import HypothesisGenerator
    from vxis.evidence.schema import Evidence, Severity, EvidenceType

    ev = Evidence(
        agent_id="cloud",
        title="S3 bucket public",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 bucket acme-dev is public",
    )
    generated = HypothesisGenerator.from_finding(ev)
    assert len(generated) >= 1
    assert any("secret" in h.suggested_agent or
               "supply_chain" in h.suggested_agent
               for h in generated)
```

- [ ] **Step 2: 실패 확인**

```bash
pytest tests/unit/test_hypothesis.py -v
```

- [ ] **Step 3: Hypothesis 구현**

```python
# src/vxis/graph/hypothesis.py
from __future__ import annotations
import heapq
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from ..evidence.schema import Evidence, EvidenceType


class HypothesisStatus(str, Enum):
    PENDING = "pending"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


@dataclass
class Hypothesis:
    title: str
    rationale: str
    probability: float          # 0.0 ~ 1.0
    impact: float               # 0.0 ~ 1.0
    suggested_agent: str
    suggested_tool: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: HypothesisStatus = HypothesisStatus.PENDING
    note: str = ""

    @property
    def priority_score(self) -> float:
        return self.probability * self.impact

    def accept(self, note: str = "") -> None:
        self.status = HypothesisStatus.CONFIRMED
        self.note = note

    def reject(self, note: str = "") -> None:
        self.status = HypothesisStatus.REJECTED
        self.note = note

    # heapq는 최솟값 우선 → 음수로 저장
    def __lt__(self, other: "Hypothesis") -> bool:
        return self.priority_score > other.priority_score


class HypothesisQueue:
    def __init__(self):
        self._heap: list[Hypothesis] = []
        self._seen: set[str] = set()

    def push(self, h: Hypothesis) -> None:
        if h.title not in self._seen:
            self._seen.add(h.title)
            heapq.heappush(self._heap, h)

    def pop(self) -> Optional[Hypothesis]:
        while self._heap:
            h = heapq.heappop(self._heap)
            if h.status == HypothesisStatus.PENDING:
                h.status = HypothesisStatus.TESTING
                return h
        return None

    def size(self) -> int:
        return sum(1 for h in self._heap
                   if h.status == HypothesisStatus.PENDING)


# 발견물 → 새 가설 자동 생성
_FINDING_HYPOTHESIS_MAP: dict[str, list[dict]] = {
    "s3": [
        {"title": "Secrets in S3 bucket", "agent": "secrets_lifecycle",
         "probability": 0.85, "impact": 0.95},
        {"title": "S3 used in CI/CD pipeline", "agent": "supply_chain",
         "probability": 0.6, "impact": 0.7},
    ],
    "graphql": [
        {"title": "GraphQL allows unauthorized queries",
         "agent": "api", "probability": 0.8, "impact": 0.85},
    ],
    "credential": [
        {"title": "Credential reuse on other services",
         "agent": "identity_ad", "probability": 0.7, "impact": 0.9},
        {"title": "DB direct access via leaked creds",
         "agent": "database", "probability": 0.8, "impact": 0.95},
    ],
    "jwt": [
        {"title": "JWT algorithm confusion attack",
         "agent": "crypto_tls", "probability": 0.65, "impact": 0.9},
    ],
}


class HypothesisGenerator:
    @classmethod
    def from_finding(cls, evidence: Evidence) -> list[Hypothesis]:
        hypotheses = []
        title_lower = evidence.title.lower()
        desc_lower = evidence.description.lower()

        for keyword, templates in _FINDING_HYPOTHESIS_MAP.items():
            if keyword in title_lower or keyword in desc_lower:
                for t in templates:
                    hypotheses.append(Hypothesis(
                        title=t["title"],
                        rationale=f"Derived from: {evidence.title}",
                        probability=t["probability"],
                        impact=t["impact"],
                        suggested_agent=t["agent"],
                    ))
        return hypotheses
```

- [ ] **Step 4: 테스트 통과 확인**

```bash
pytest tests/unit/test_hypothesis.py -v
```
Expected: 4개 PASS

- [ ] **Step 5: 커밋**

```bash
git add src/vxis/graph/hypothesis.py tests/unit/test_hypothesis.py
git commit -m "feat(crt): Hypothesis Engine — 우선순위 큐 + 자동 생성"
```

---

## Task 5: Base Agent + LLM Client

**Files:**
- Create: `src/vxis/llm/client.py`
- Create: `src/vxis/llm/__init__.py`
- Create: `src/vxis/agent/base.py`
- Create: `src/vxis/agent/context.py`
- Create: `src/vxis/agent/__init__.py`
- Test: `tests/unit/test_base_agent.py`

- [ ] **Step 1: 실패 테스트 작성**

```python
# tests/unit/test_base_agent.py
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from vxis.agent.base import BaseAgent, AgentResult
from vxis.agent.context import AgentContext
from vxis.mission.config import MissionConfig
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.evidence.engine import EvidenceEngine

class ConcreteAgent(BaseAgent):
    agent_id = "test_agent"
    description = "Test agent"

    async def run(self, context: AgentContext) -> AgentResult:
        return AgentResult(
            agent_id=self.agent_id,
            findings=[],
            hypotheses=[],
            status="completed",
        )

@pytest.fixture
def context(tmp_path):
    cfg = MissionConfig(target="example.com")
    graph = LivingAttackGraph()
    engine = EvidenceEngine(db_path=str(tmp_path / "ev.db"))
    return AgentContext(
        mission=cfg,
        attack_graph=graph,
        evidence_engine=engine,
    )

def test_agent_has_required_attributes():
    agent = ConcreteAgent()
    assert agent.agent_id == "test_agent"
    assert agent.description == "Test agent"

@pytest.mark.asyncio
async def test_agent_run_returns_result(context):
    agent = ConcreteAgent()
    result = await agent.run(context)
    assert result.agent_id == "test_agent"
    assert result.status == "completed"

def test_agent_result_structure():
    result = AgentResult(
        agent_id="web",
        findings=[],
        hypotheses=[],
        status="completed",
        error=None,
    )
    assert result.is_success
```

- [ ] **Step 2: 실패 확인**

```bash
pytest tests/unit/test_base_agent.py -v
```

- [ ] **Step 3: AgentContext + BaseAgent 구현**

```python
# src/vxis/agent/context.py
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
```

```python
# src/vxis/agent/base.py
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from .context import AgentContext
from ..graph.hypothesis import Hypothesis
from ..evidence.schema import Evidence


@dataclass
class AgentResult:
    agent_id: str
    findings: list[Evidence]
    hypotheses: list[Hypothesis]
    status: str                         # "completed" | "error" | "partial"
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        return self.status == "completed"


class BaseAgent(ABC):
    agent_id: str = ""
    description: str = ""

    @abstractmethod
    async def run(self, context: AgentContext) -> AgentResult:
        """에이전트 실행. 발견물 + 새 가설 반환."""
        ...
```

```python
# src/vxis/llm/client.py
from __future__ import annotations
import os
from typing import Optional
import anthropic


class LLMClient:
    def __init__(self, model: str = "claude-opus-4-6"):
        self.model = model
        self._client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY", "")
        )

    async def think(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
    ) -> str:
        """Director Agent의 전략적 판단에 사용."""
        response = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

    async def think_with_tools(
        self,
        system: str,
        user: str,
        tools: list[dict],
        max_tokens: int = 8192,
    ) -> anthropic.types.Message:
        """Tool use 포함 판단."""
        return self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            tools=tools,
            messages=[{"role": "user", "content": user}],
        )
```

```python
# src/vxis/agent/__init__.py
from .base import BaseAgent, AgentResult
from .context import AgentContext

__all__ = ["BaseAgent", "AgentResult", "AgentContext"]
```

```python
# src/vxis/llm/__init__.py
from .client import LLMClient

__all__ = ["LLMClient"]
```

- [ ] **Step 4: 테스트 통과 확인**

```bash
pytest tests/unit/test_base_agent.py -v
```
Expected: 3개 PASS

- [ ] **Step 5: 커밋**

```bash
git add src/vxis/agent/ src/vxis/llm/ tests/unit/test_base_agent.py
git commit -m "feat(crt): BaseAgent + AgentContext + LLM Client"
```

---

## Task 6: Director Agent

**Files:**
- Create: `src/vxis/agent/director.py`
- Create: `src/vxis/agent/registry.py`
- Test: `tests/unit/test_director.py`

- [ ] **Step 1: 실패 테스트 작성**

```python
# tests/unit/test_director.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from vxis.agent.director import DirectorAgent
from vxis.agent.context import AgentContext
from vxis.agent.base import AgentResult
from vxis.mission.config import MissionConfig, Depth
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.evidence.engine import EvidenceEngine
from vxis.evidence.schema import Evidence, Severity, EvidenceType

@pytest.fixture
def context(tmp_path):
    cfg = MissionConfig(target="example.com", depth=Depth.NORMAL)
    graph = LivingAttackGraph()
    engine = EvidenceEngine(db_path=str(tmp_path / "ev.db"))
    return AgentContext(mission=cfg, attack_graph=graph, evidence_engine=engine)

@pytest.mark.asyncio
async def test_director_integrates_finding(context, tmp_path):
    await context.evidence_engine.init()
    director = DirectorAgent()

    ev = Evidence(
        agent_id="cloud",
        title="s3 bucket public",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 bucket is public",
    )
    await director.integrate_finding(ev, context)

    summary = context.attack_graph.summary()
    assert summary["total_findings"] == 1
    assert summary["high"] == 1

@pytest.mark.asyncio
async def test_director_spawns_hypotheses_on_finding(context, tmp_path):
    await context.evidence_engine.init()
    director = DirectorAgent()

    ev = Evidence(
        agent_id="cloud",
        title="s3 bucket with credential files",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="credential found in s3",
    )
    await director.integrate_finding(ev, context)

    # 발견에 따라 가설이 생성됐는지
    assert director.hypothesis_queue.size() >= 1

def test_director_select_agents(context):
    director = DirectorAgent()
    agents = director.select_initial_agents(context.mission)
    assert len(agents) > 0
```

- [ ] **Step 2: 실패 확인**

```bash
pytest tests/unit/test_director.py -v
```

- [ ] **Step 3: AgentRegistry 구현**

```python
# src/vxis/agent/registry.py
from __future__ import annotations
from .base import BaseAgent

_REGISTRY: dict[str, type[BaseAgent]] = {}


def register(agent_class: type[BaseAgent]) -> type[BaseAgent]:
    """에이전트 클래스 등록 데코레이터."""
    _REGISTRY[agent_class.agent_id] = agent_class
    return agent_class


def get_agent(agent_id: str) -> type[BaseAgent] | None:
    return _REGISTRY.get(agent_id)


def list_agents() -> list[str]:
    return list(_REGISTRY.keys())


def spawn(agent_id: str) -> BaseAgent | None:
    cls = get_agent(agent_id)
    return cls() if cls else None
```

- [ ] **Step 4: Director Agent 구현**

```python
# src/vxis/agent/director.py
from __future__ import annotations
import asyncio
from typing import Optional
from .base import BaseAgent, AgentResult
from .context import AgentContext
from .registry import spawn
from ..graph.hypothesis import HypothesisQueue, HypothesisGenerator
from ..evidence.schema import Evidence
from ..evidence.engine import EvidenceEngine
from ..mission.config import MissionConfig
from ..mission.selector import AgentSelector


class DirectorAgent:
    """
    전략적 판단 + 에이전트 동적 스폰.
    발견물 통합 → Attack Graph 업데이트 → 새 가설 생성 → 에이전트 재투입.
    """

    def __init__(self):
        self.hypothesis_queue = HypothesisQueue()
        self._active_agents: set[str] = set()

    def select_initial_agents(self, mission: MissionConfig) -> list[str]:
        return AgentSelector.select(mission)

    async def integrate_finding(
        self,
        evidence: Evidence,
        context: AgentContext,
    ) -> None:
        """발견물을 Attack Graph에 통합 + 새 가설 생성."""
        await context.evidence_engine.save(evidence)
        context.attack_graph.add_finding(evidence)

        # 발견 기반 새 가설 자동 생성
        new_hypotheses = HypothesisGenerator.from_finding(evidence)
        for h in new_hypotheses:
            self.hypothesis_queue.push(h)

    async def run_mission(self, context: AgentContext) -> None:
        """
        전체 미션 루프.
        초기 에이전트 스폰 → 결과 통합 → 가설 기반 추가 에이전트 스폰.
        """
        initial_agent_ids = self.select_initial_agents(context.mission)
        await self._run_agents(initial_agent_ids, context)

        # 가설 기반 추가 라운드
        while self.hypothesis_queue.size() > 0:
            hypothesis = self.hypothesis_queue.pop()
            if hypothesis and hypothesis.suggested_agent:
                await self._run_agents(
                    [hypothesis.suggested_agent], context
                )

    async def _run_agents(
        self,
        agent_ids: list[str],
        context: AgentContext,
    ) -> None:
        tasks = []
        for agent_id in agent_ids:
            if agent_id in self._active_agents:
                continue
            agent = spawn(agent_id)
            if agent:
                self._active_agents.add(agent_id)
                tasks.append(self._run_single(agent, context))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, AgentResult):
                    for finding in result.findings:
                        await self.integrate_finding(finding, context)

    async def _run_single(
        self,
        agent: BaseAgent,
        context: AgentContext,
    ) -> AgentResult:
        try:
            return await agent.run(context)
        except Exception as e:
            return AgentResult(
                agent_id=agent.agent_id,
                findings=[],
                hypotheses=[],
                status="error",
                error=str(e),
            )
```

- [ ] **Step 5: 테스트 통과 확인**

```bash
pytest tests/unit/test_director.py -v
```
Expected: 3개 PASS

- [ ] **Step 6: 커밋**

```bash
git add src/vxis/agent/director.py src/vxis/agent/registry.py tests/unit/test_director.py
git commit -m "feat(crt): Director Agent — 발견 통합 + 동적 에이전트 스폰"
```

---

## Task 7: CLI Live Display (CRT 버전)

**Files:**
- Create: `src/vxis/display/live.py`
- Create: `src/vxis/display/__init__.py`
- Test: (시각적 컴포넌트, 연기 테스트)

- [ ] **Step 1: CRT Live Display 구현**

```python
# src/vxis/display/live.py
from __future__ import annotations
import asyncio
from datetime import datetime, timezone
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box
from ..graph.attack_graph import LivingAttackGraph
from ..graph.hypothesis import HypothesisQueue
from ..evidence.schema import Severity

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class CRTLiveDisplay:
    """
    VXIS Cognitive Red Team 실시간 터미널 디스플레이.

    ┌─ VXIS CRT ──────────────────────── elite | stealth ─┐
    │ Target | Elapsed | Active Agents                     │
    │ Attack Graph | Hypothesis Queue                      │
    │ Findings Summary | Director Status                   │
    └─────────────────────────────────────────────────────┘
    """

    def __init__(
        self,
        target: str,
        depth: str,
        stealth: bool,
        attack_graph: LivingAttackGraph,
        hypothesis_queue: HypothesisQueue,
    ):
        self.target = target
        self.depth = depth
        self.stealth = stealth
        self.attack_graph = attack_graph
        self.hypothesis_queue = hypothesis_queue
        self._console = Console()
        self._start_time = datetime.now(timezone.utc)
        self._active_agents: dict[str, str] = {}  # id → status
        self._director_status = "Initializing..."
        self._live: Live | None = None

    def update_agent(self, agent_id: str, status: str) -> None:
        self._active_agents[agent_id] = status
        if self._live:
            self._live.update(self._render())

    def update_director(self, message: str) -> None:
        self._director_status = message
        if self._live:
            self._live.update(self._render())

    def _elapsed(self) -> str:
        delta = datetime.now(timezone.utc) - self._start_time
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _render_header(self) -> Panel:
        mode = f"[bold cyan]{self.depth}[/]"
        if self.stealth:
            mode += " [bold green]| stealth[/]"
        title = f"[bold white]VXIS CRT[/] — {mode}"
        content = (
            f"[dim]Target:[/] [bold]{self.target}[/]   "
            f"[dim]Elapsed:[/] [bold]{self._elapsed()}[/]"
        )
        return Panel(content, title=title, border_style="bright_blue")

    def _render_agents(self) -> Panel:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Status", width=2)
        table.add_column("Agent", width=20)
        table.add_column("State", width=12)

        for agent_id, status in list(self._active_agents.items())[-8:]:
            icon = "●" if status == "running" else "◎" if status == "spawning" else "✓"
            color = "green" if status == "running" else "yellow" if status == "spawning" else "dim"
            table.add_row(
                f"[{color}]{icon}[/]",
                f"[{color}]{agent_id}[/]",
                f"[dim]{status}[/]",
            )
        return Panel(table, title="[dim]AGENTS[/]", border_style="dim")

    def _render_graph(self) -> Panel:
        summary = self.attack_graph.summary()
        chains = self.attack_graph.find_critical_chains()

        lines = []
        for chain in chains[:3]:
            parts = [f"[bold]{n.title[:20]}[/]" for n in chain]
            lines.append(" → ".join(parts))

        if not lines:
            lines = ["[dim]No chains yet...[/]"]

        content = "\n".join(lines)
        title = f"[dim]ATTACK GRAPH[/] [dim]({summary['total_edges']} edges)[/]"
        return Panel(content, title=title, border_style="dim")

    def _render_hypotheses(self) -> Panel:
        pending = [
            h for h in self.hypothesis_queue._heap
            if h.status.value == "pending"
        ]
        pending_sorted = sorted(pending, key=lambda h: h.priority_score, reverse=True)

        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
        table.add_column("Score", width=6)
        table.add_column("Hypothesis", width=28)
        table.add_column("Agent", width=14)

        for h in pending_sorted[:5]:
            score_pct = int(h.priority_score * 100)
            table.add_row(
                f"[cyan]{score_pct}%[/]",
                h.title[:28],
                f"[dim]{h.suggested_agent}[/]",
            )
        return Panel(table, title="[dim]HYPOTHESIS QUEUE[/]", border_style="dim")

    def _render_findings(self) -> Panel:
        summary = self.attack_graph.summary()
        lines = [
            f"[bold red]CRITICAL  {summary['critical']:>4}[/]",
            f"[red]HIGH      {summary['high']:>4}[/]",
            f"[yellow]MEDIUM    {summary['medium']:>4}[/]",
            f"[cyan]LOW       {summary['low']:>4}[/]",
            "",
            f"[dim]CHAINS    {summary['total_chains']:>4}[/]",
        ]
        return Panel("\n".join(lines), title="[dim]FINDINGS[/]", border_style="dim")

    def _render_director(self) -> Panel:
        return Panel(
            f"[bold yellow]DIRECTOR:[/] {self._director_status}",
            border_style="bright_blue",
        )

    def _render(self):
        from rich.layout import Layout
        layout = Layout()
        layout.split_column(
            Layout(self._render_header(), size=3),
            Layout(name="middle"),
            Layout(self._render_director(), size=3),
        )
        layout["middle"].split_row(
            Layout(self._render_agents(), ratio=2),
            Layout(self._render_graph(), ratio=3),
            Layout(self._render_hypotheses(), ratio=3),
            Layout(self._render_findings(), ratio=2),
        )
        return layout

    def start(self) -> "CRTLiveDisplay":
        self._live = Live(
            self._render(),
            console=self._console,
            refresh_per_second=2,
            screen=False,
        )
        self._live.start()
        return self

    def stop(self) -> None:
        if self._live:
            self._live.stop()

    def __enter__(self) -> "CRTLiveDisplay":
        return self.start()

    def __exit__(self, *args) -> None:
        self.stop()
```

```python
# src/vxis/display/__init__.py
from .live import CRTLiveDisplay

__all__ = ["CRTLiveDisplay"]
```

- [ ] **Step 2: 시각적 확인 (수동)**

```bash
python -c "
import asyncio
from vxis.display.live import CRTLiveDisplay
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.graph.hypothesis import HypothesisQueue, Hypothesis

graph = LivingAttackGraph()
queue = HypothesisQueue()
queue.push(Hypothesis(
    title='GraphQL introspection enabled',
    rationale='test',
    probability=0.8,
    impact=0.9,
    suggested_agent='api',
))

display = CRTLiveDisplay(
    target='*.acme.com',
    depth='elite',
    stealth=True,
    attack_graph=graph,
    hypothesis_queue=queue,
)
with display:
    import time; time.sleep(3)
print('Display OK')
"
```
Expected: 3초간 CRT 대시보드 표시 후 종료

- [ ] **Step 3: 커밋**

```bash
git add src/vxis/display/
git commit -m "feat(crt): CLI Live Display — 실시간 Attack Graph + Hypothesis 시각화"
```

---

## Task 8: 통합 스모크 테스트

**Files:**
- Create: `tests/integration/test_phase1_smoke.py`

- [ ] **Step 1: 스모크 테스트 작성**

```python
# tests/integration/test_phase1_smoke.py
"""
Phase 1 전체 통합 테스트.
Director → Attack Graph → Evidence Engine → Hypothesis Queue 흐름 검증.
"""
import pytest
import asyncio
from vxis.mission.config import MissionConfig, Depth, Scope
from vxis.graph.attack_graph import LivingAttackGraph
from vxis.graph.hypothesis import HypothesisQueue
from vxis.evidence.engine import EvidenceEngine
from vxis.evidence.schema import Evidence, Severity, EvidenceType
from vxis.agent.director import DirectorAgent
from vxis.agent.context import AgentContext

@pytest.mark.asyncio
async def test_full_phase1_flow(tmp_path):
    """
    시나리오: S3 공개 → .env 크레덴셜 → DB 접근 체인
    검증: Director가 세 발견을 통합하고 체인을 탐지한다.
    """
    cfg = MissionConfig(
        target="*.acme.com",
        depth=Depth.AGGRESSIVE,
        scope=Scope.FULL,
    )
    graph = LivingAttackGraph()
    engine = EvidenceEngine(db_path=str(tmp_path / "ev.db"))
    await engine.init()

    context = AgentContext(
        mission=cfg,
        attack_graph=graph,
        evidence_engine=engine,
    )
    director = DirectorAgent()

    # Finding 1: S3 공개
    ev1 = Evidence(
        agent_id="cloud",
        title="S3 bucket acme-dev is public",
        severity=Severity.HIGH,
        evidence_type=EvidenceType.MISCONFIGURATION,
        description="S3 bucket public read access",
    )
    await director.integrate_finding(ev1, context)

    # Finding 2: .env 발견 (ev1에서 파생)
    ev2 = Evidence(
        agent_id="secrets_lifecycle",
        title=".env file with DB credentials",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.SECRET,
        description="DATABASE_URL=postgres://admin:secret@db:5432/prod",
        chained_from=ev1.id,
    )
    await director.integrate_finding(ev2, context)

    # Finding 3: DB 직접 접근 (ev2에서 파생)
    ev3 = Evidence(
        agent_id="database",
        title="Direct PostgreSQL access achieved",
        severity=Severity.CRITICAL,
        evidence_type=EvidenceType.EXPLOIT,
        description="Full read/write access to production DB (2.5M records)",
        chained_from=ev2.id,
    )
    await director.integrate_finding(ev3, context)

    # 검증
    summary = graph.summary()
    assert summary["total_findings"] == 3
    assert summary["critical"] == 2
    assert summary["high"] == 1

    chains = graph.find_critical_chains()
    assert len(chains) >= 1
    longest = max(chains, key=len)
    assert len(longest) == 3  # S3 → .env → DB

    # Evidence Engine 저장 확인
    all_ev = await engine.get_all()
    assert len(all_ev) == 3

    critical_ev = await engine.get_by_severity(Severity.CRITICAL)
    assert len(critical_ev) == 2

    # Hypothesis 자동 생성 확인
    assert director.hypothesis_queue.size() >= 1

    print("\n✅ Phase 1 통합 테스트 통과")
    print(f"   총 발견: {summary['total_findings']}")
    print(f"   체인 수: {len(chains)}")
    print(f"   최장 체인: {len(longest)}단계")
    print(f"   생성된 가설: {director.hypothesis_queue.size()}")
```

- [ ] **Step 2: 통합 테스트 실행**

```bash
pytest tests/integration/test_phase1_smoke.py -v -s
```
Expected: PASS + 통계 출력

- [ ] **Step 3: 전체 테스트 스위트 실행**

```bash
pytest tests/ -v --tb=short
```
Expected: 전체 PASS

- [ ] **Step 4: 최종 커밋**

```bash
git add tests/integration/test_phase1_smoke.py
git commit -m "test(crt): Phase 1 통합 스모크 테스트 — Director + Graph + Evidence 체인"
```

---

## Task 9: 패키지 의존성 업데이트

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: 의존성 추가**

`pyproject.toml`의 dependencies에 추가:

```toml
dependencies = [
  # ... 기존 의존성 ...
  "networkx>=3.3",
  "anthropic>=0.40.0",
  "pydantic>=2.7",
  "tomllib",        # Python 3.11+ 내장, 하위 버전은 tomli
  "pytest-asyncio>=0.23",
]
```

- [ ] **Step 2: 설치 확인**

```bash
pip install -e ".[dev]"
pip show networkx anthropic pydantic
```
Expected: 세 패키지 모두 설치 확인

- [ ] **Step 3: 전체 테스트 최종 확인**

```bash
pytest tests/ -v
```
Expected: 전체 PASS

- [ ] **Step 4: 커밋**

```bash
git add pyproject.toml
git commit -m "chore: Phase 1 의존성 추가 (networkx, anthropic, pydantic v2)"
```

---

## Phase 1 완료 기준

```
✅ MissionConfig — TOML 파싱 + 유효성 검사
✅ AgentSelector — scope/depth/stealth/perspective → agent 목록
✅ Evidence Engine — 불변 해시 + 체인 링킹 + SQLite 저장
✅ Living Attack Graph — 실시간 노드/엣지 + 체인 탐지
✅ Hypothesis Engine — 우선순위 큐 + 발견 기반 자동 생성
✅ BaseAgent + AgentContext — 모든 에이전트 공통 인터페이스
✅ Director Agent — 통합 + 동적 스폰 + 가설 루프
✅ LLM Client — Claude API 래퍼
✅ CLI Live Display — Rich 실시간 대시보드
✅ 통합 테스트 — S3→.env→DB 3단계 체인 검증
```

**다음 Phase:** `2026-03-24-phase2-core-agents.md`
- Recon, Web, API, Cloud 4개 에이전트 실제 구현
- 각 에이전트가 BaseAgent 상속 + 실제 툴 실행
- Director와 실제 연동 테스트
