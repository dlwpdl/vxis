from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

from vxis.p1.models import Engagement, Policy, Scope, State, Window


def p1_home() -> Path:
    return Path(os.environ.get("VXIS_P1_HOME", Path.home() / ".vxis" / "p1")).expanduser()


class EngagementStore:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root is not None else p1_home() / "engagements"
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, engagement: Engagement) -> None:
        payload = asdict(engagement)
        payload["state"] = engagement.state.value
        path = self._path(engagement.id)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def load(self, engagement_id: str) -> Engagement:
        path = self._path(engagement_id)
        data = json.loads(path.read_text(encoding="utf-8"))
        return Engagement(
            id=data["id"],
            name=data["name"],
            operator=data["operator"],
            scope=Scope(**data["scope"]),
            window=Window(**data["window"]),
            policy=Policy(**data["policy"]),
            state=State(data.get("state", State.DRAFT.value)),
            attested=bool(data.get("attested", False)),
            authorization_ref=str(data.get("authorization_ref") or ""),
            operator_subject=str(data.get("operator_subject") or ""),
            beacons=[str(item) for item in data.get("beacons", [])],
        )

    def list_ids(self) -> list[str]:
        return sorted(path.stem for path in self.root.glob("*.json"))

    def exists(self, engagement_id: str) -> bool:
        return self._path(engagement_id).exists()

    def _path(self, engagement_id: str) -> Path:
        safe = "".join(ch for ch in engagement_id if ch.isalnum() or ch in {"-", "_"})
        if not safe:
            raise ValueError("engagement id is empty")
        return self.root / f"{safe}.json"
