"""VXIS Watchers — 11개 24/7 실시간 위협 감시 데몬.

워처 목록:
    1. dark_web_intel      — 다크웹 인텔리전스 (IntelX, Paste, GitHub)
    2. leaked_credential   — 유출 자격증명 (HIBP, Dehashed)
    3. ransomware_gang     — 랜섬웨어 그룹 피해자 감시
    4. exploit_market      — 익스플로잇 마켓 (PoC-in-GitHub, ExploitDB)
    5. cert_transparency   — 인증서 투명성 (crt.sh CT 로그)
    6. supply_chain        — 공급망 (npm/PyPI 타이포스쿼팅)
    7. infra_drift         — 인프라 변화 (포트/DNS/헤더)
    8. brand_impersonation — 브랜드 사칭 (유사 도메인)
    9. threat_actor        — 위협 행위자 (MITRE ATT&CK, CISA KEV)
"""

# BaseWatcher 기반 워처 자동 등록 — 임포트 시 @register_watcher 데코레이터 실행
from . import dark_web_intel  # noqa: F401
from . import leaked_credential  # noqa: F401
from . import ransomware_gang  # noqa: F401
from . import exploit_market  # noqa: F401
from . import cert_transparency  # noqa: F401
from . import supply_chain  # noqa: F401
from . import infra_drift  # noqa: F401
from . import brand_impersonation  # noqa: F401
from . import threat_actor  # noqa: F401
