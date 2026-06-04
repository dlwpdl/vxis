"""Filesystem-backed PTI store."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from vxis.pti.hashing import target_hash_for_url, validate_target_hash
from vxis.pti.models import Dossier, OutcomeStatus, TrajectoryRecord
from vxis.pti.query import FilterInput, QueryType, query_pti
from vxis.pti.trajectory import TrajectoryStore


class PTIStore:
    """Load and persist PTI dossiers under ``data/pti/<target_hash>``."""

    def __init__(self, root: Path | str = Path("data/pti")) -> None:
        self.root = Path(root)

    def target_dir(self, target_hash: str) -> Path:
        return self.root / validate_target_hash(target_hash)

    def dossier_path(self, target_hash: str) -> Path:
        return self.target_dir(target_hash) / "dossier.yaml"

    def load(
        self,
        target_hash: str,
        *,
        target_url: str | None = None,
        create: bool = False,
    ) -> Dossier:
        normalized_hash = validate_target_hash(target_hash)
        path = self.dossier_path(normalized_hash)
        if path.exists():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            dossier = Dossier.model_validate(data)
            if dossier.target_hash != normalized_hash:
                raise ValueError("dossier target_hash does not match directory")
            return dossier

        if not create:
            raise FileNotFoundError(path)
        if target_url is None:
            raise ValueError("target_url is required when creating a missing dossier")
        if target_hash_for_url(target_url) != normalized_hash:
            raise ValueError("target_url does not match target_hash")
        return Dossier(target_hash=normalized_hash, target_url=target_url)

    def load_for_target(self, target_url: str, *, create: bool = True) -> Dossier:
        target_hash = target_hash_for_url(target_url)
        return self.load(target_hash, target_url=target_url, create=create)

    def persist(self, dossier: Dossier | Mapping[str, Any]) -> Path:
        validated = Dossier.model_validate(dossier)
        path = self.dossier_path(validated.target_hash)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_name(f".{path.name}.tmp")
        data = validated.model_dump(mode="json")
        tmp_path.write_text(
            yaml.safe_dump(data, sort_keys=False, allow_unicode=False),
            encoding="utf-8",
        )
        tmp_path.replace(path)
        return path

    def query(
        self,
        dossier_or_target_hash: Dossier | str,
        query_type: QueryType,
        filters: FilterInput = None,
    ) -> list[Any]:
        dossier = (
            self.load(dossier_or_target_hash)
            if isinstance(dossier_or_target_hash, str)
            else dossier_or_target_hash
        )
        return query_pti(dossier, query_type, filters)

    def trajectory_store(self, target_hash: str) -> TrajectoryStore:
        return TrajectoryStore(self.target_dir(target_hash))

    def append_trajectory(
        self,
        record: TrajectoryRecord,
        *,
        privacy_mode: str | None = None,
    ) -> Path:
        return self.trajectory_store(record.target_hash).append(record, privacy_mode=privacy_mode)

    def load_trajectories(self, target_hash: str, scan_id: str) -> list[TrajectoryRecord]:
        return self.trajectory_store(target_hash).load(scan_id)

    def writeback_trajectory_outcome(
        self,
        target_hash: str,
        scan_id: str,
        *,
        iter: int,
        outcome_status: OutcomeStatus,
        outcome_evidence: str | None = None,
        led_to_finding_id: str | None = None,
        led_to_refutation: bool = False,
    ) -> TrajectoryRecord:
        return self.trajectory_store(target_hash).writeback_outcome(
            scan_id,
            iter=iter,
            outcome_status=outcome_status,
            outcome_evidence=outcome_evidence,
            led_to_finding_id=led_to_finding_id,
            led_to_refutation=led_to_refutation,
        )
