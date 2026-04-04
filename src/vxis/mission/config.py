from __future__ import annotations

import tomllib
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, field_validator, model_validator


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
    proxy_pool: list[str] = []
    memory: MemoryConfig = MemoryConfig()
    # Convenience field: populates memory.client_id when provided directly.
    # Not stored as a persistent field — resolved via model_validator.
    client_id: Optional[str] = None

    @field_validator("target")
    @classmethod
    def target_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("target cannot be empty")
        return v.strip()

    @model_validator(mode="after")
    def apply_client_id_shorthand(self) -> "MissionConfig":
        if self.client_id is not None:
            # Propagate to memory.client_id, then clear the shorthand field.
            self.memory = MemoryConfig(
                client_id=self.client_id,
                learn=self.memory.learn,
            )
            self.client_id = None
        return self

    @classmethod
    def from_file(cls, path: str) -> "MissionConfig":
        data = Path(path).read_bytes()
        parsed = tomllib.loads(data.decode())
        mission = parsed.get("mission", {})
        memory_raw = parsed.get("memory", {})
        return cls(**mission, memory=MemoryConfig(**memory_raw))
