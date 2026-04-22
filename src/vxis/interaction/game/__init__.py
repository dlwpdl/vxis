"""Game surface namespace — phase-H stubs.

GameRecon does a partial delegate (URL parse) so Brain has structured fingerprint
material without a live capture; the other three ABCs raise bilingual
NotImplementedError pending the full game-pipeline plan.
"""
from vxis.interaction.game.game_surface import (
    GameEyes,
    GameHands,
    GameRecon,
    GameXRay,
)

__all__ = ["GameHands", "GameEyes", "GameXRay", "GameRecon"]
