"""Mobile surface namespace — phase-H stubs.

Real iOS/Android attack pipelines (frida-mobile, objection, MobSF, drozer)
land in a follow-up plan. The stubs here let SurfaceFactory resolve
TargetKind.MOBILE so Brain · Director · Phase code can stay surface-agnostic.
"""
from vxis.interaction.mobile.mobile_surface import (
    MobileEyes,
    MobileHands,
    MobileRecon,
    MobileXRay,
)

__all__ = ["MobileHands", "MobileEyes", "MobileXRay", "MobileRecon"]
