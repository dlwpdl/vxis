"""Allow running as: python -m tools.upstream_watch"""
import logging
import sys

# LLM 호출 디버깅을 위해 로깅 활성화
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)

from .main import main

sys.exit(main())
