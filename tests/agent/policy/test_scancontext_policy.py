from unittest.mock import MagicMock

from vxis.agent.policy.scan_policy import resolve_policy
from vxis.config.schema import VXISConfig
from vxis.interaction.surface import TargetKind
from vxis.pipeline.context import ScanContext


def test_scancontext_policy_defaults_to_none():
    ctx = ScanContext(target="http://localhost", kind=TargetKind.WEB)
    assert ctx.policy is None


def test_resolve_policy_attaches_to_context_for_crown():
    cfg = VXISConfig()
    cfg.active_profile = "crown"
    ctx = ScanContext(target="http://localhost", kind=TargetKind.WEB)
    ctx.policy = resolve_policy(cfg)
    assert ctx.policy is not None
    assert ctx.policy.exploitation_ceiling == "lateral"


def test_pipeline_attaches_policy_when_flag_on(monkeypatch):
    from vxis.pipeline.scan_pipeline_v2 import ScanPipeline

    monkeypatch.setenv("VXIS_V3_POLICY", "1")
    cfg = VXISConfig()
    cfg.active_profile = "crown"
    pipeline = ScanPipeline(brain=MagicMock(), config=cfg)
    ctx = ScanContext(target="http://localhost", kind=TargetKind.WEB)
    pipeline._resolve_and_attach_policy(ctx)
    assert ctx.policy is not None
    assert ctx.policy.exploitation_ceiling == "lateral"


def test_pipeline_leaves_policy_none_when_flag_off(monkeypatch):
    from vxis.pipeline.scan_pipeline_v2 import ScanPipeline

    monkeypatch.delenv("VXIS_V3_POLICY", raising=False)
    monkeypatch.delenv("VXIS_V3", raising=False)
    cfg = VXISConfig()
    cfg.active_profile = "crown"
    pipeline = ScanPipeline(brain=MagicMock(), config=cfg)
    ctx = ScanContext(target="http://localhost", kind=TargetKind.WEB)
    pipeline._resolve_and_attach_policy(ctx)
    assert ctx.policy is None
