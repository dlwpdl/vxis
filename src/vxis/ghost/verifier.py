"""GhostVerifier — 익명화 적용 여부 사전 검증."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from vxis.ghost.layer import ghost_layer

# Lazy import to break circular dependency:
#   interaction.hands → ghost.layer → ghost.__init__ → ghost.verifier → interaction.hands
if TYPE_CHECKING:
    pass

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

        # Lazy import — see TYPE_CHECKING note above.
        from vxis.interaction.hands import TargetSession  # noqa: PLC0415

        # Route the IP probe through the Ghost transport when active, so we
        # verify the *proxied* exit IP — never the host's direct IP. A raw
        # TargetSession does NOT get GhostTransport (only SessionManager wires
        # it), which is why this probe used to report the direct IP as the
        # "anonymized" one. When active-but-no-proxy, GhostTransport fails
        # closed and check() records the error instead of a fake exit IP.
        transport = None
        if ghost_layer.is_active():
            from vxis.ghost.transport import GhostTransport  # noqa: PLC0415

            transport = GhostTransport(ghost_layer)
        session = TargetSession(_IP_CHECK_URL, verify_ssl=True, transport=transport)
        try:
            resp = await session.get("/")
            if resp.status == 200:
                text = resp.text.strip()
                try:
                    data = json.loads(text)
                    result["detected_ip"] = data.get("ip")
                except json.JSONDecodeError:
                    # plain text IP 응답 (쿼리스트링 누락 시)
                    result["detected_ip"] = text
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
