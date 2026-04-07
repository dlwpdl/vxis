"""Individual PhaseGuide definitions, one module per Phase."""

from vxis.phases.guides.p0_foundation import PHASE_GUIDE as P0_FOUNDATION
from vxis.phases.guides.p1_director import PHASE_GUIDE as P1_DIRECTOR
from vxis.phases.guides.p2_agents import PHASE_GUIDE as P2_AGENTS
from vxis.phases.guides.p3_hypothesis import PHASE_GUIDE as P3_HYPOTHESIS
from vxis.phases.guides.p4_cpr import PHASE_GUIDE as P4_CPR
from vxis.phases.guides.p5_special import PHASE_GUIDE as P5_SPECIAL
from vxis.phases.guides.p6_report import PHASE_GUIDE as P6_REPORT
from vxis.phases.guides.p7_hardware import PHASE_GUIDE as P7_HARDWARE
from vxis.phases.guides.p8_synthesis import PHASE_GUIDE as P8_SYNTHESIS
from vxis.phases.guides.p11_mutation import PHASE_GUIDE as P11_MUTATION
from vxis.phases.guides.p12_evolution import PHASE_GUIDE as P12_EVOLUTION
from vxis.phases.guides.p13_biometrics import PHASE_GUIDE as P13_BIOMETRICS
from vxis.phases.guides.p15_digital_twin import PHASE_GUIDE as P15_DIGITAL_TWIN
from vxis.phases.guides.p18_collective import PHASE_GUIDE as P18_COLLECTIVE

__all__ = [
    "P0_FOUNDATION",
    "P1_DIRECTOR",
    "P2_AGENTS",
    "P3_HYPOTHESIS",
    "P4_CPR",
    "P5_SPECIAL",
    "P6_REPORT",
    "P7_HARDWARE",
    "P8_SYNTHESIS",
    "P11_MUTATION",
    "P12_EVOLUTION",
    "P13_BIOMETRICS",
    "P15_DIGITAL_TWIN",
    "P18_COLLECTIVE",
]
