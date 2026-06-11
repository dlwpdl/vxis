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
