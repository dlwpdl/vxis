from vxis.interaction.surface import TargetKind
from vxis.pipeline.context import ScanContext


def test_scancontext_policy_defaults_to_none():
    ctx = ScanContext(target="http://localhost", kind=TargetKind.WEB)
    assert ctx.policy is None
