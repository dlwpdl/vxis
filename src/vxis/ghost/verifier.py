"""GhostVerifier — 익명화 적용 여부 사전 검증."""
from __future__ import annotations

import json
import logging

from vxis.ghost.layer import ghost_layer
from vxis.interaction.hands import TargetSession

logger = logging.getLogger(__name__)

_IP_CHECK_URL = "https://api64.ipify.org?format=json"


class GhostVerifier:
    """Ghost 모드 활성화 후 실제 노출 IP 확인."""

    async def check(self) -> dict:
        result: dict = {
            "ghost_active": ghost_layer.is_active(),
            "detected_ip": None,
            "error": None,
        }

        session = TargetSession(_IP_CHECK_URL, verify_ssl=True)
        try:
            resp = await session.get("/")
            if resp.status == 200:
                data = json.loads(resp.text)
                result["detected_ip"] = data.get("ip")
                logger.info("[GhostVerifier] 노출 IP: %s", result["detected_ip"])
            else:
                result["error"] = f"HTTP {resp.status}"
        except Exception as exc:
            result["error"] = str(exc)
            logger.warning("[GhostVerifier] IP 확인 실패: %s", exc)
        finally:
            await session.close()

        return result

    def log_summary(self, result: dict) -> None:
        ip = result.get("detected_ip", "unknown")
        active = result.get("ghost_active", False)
        err = result.get("error")
        if err:
            logger.warning("[Ghost ✗] 검증 실패: %s", err)
        elif active and ip:
            logger.info("[Ghost ✓] 익명화 IP 확인: %s", ip)
        else:
            logger.info("[Ghost -] Ghost 비활성 — 직접 연결 IP: %s", ip)
