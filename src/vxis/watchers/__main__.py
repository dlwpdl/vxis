"""python -m vxis.watchers 진입점.

사용법:
    python -m vxis.watchers             # 데몬 모드 (무한 루프, 15분 간격)
    python -m vxis.watchers --once      # 단발 실행 (GitHub Actions 용)
    python -m vxis.watchers --help      # 전체 옵션 확인
"""

from .cve_daemon import main

main()
