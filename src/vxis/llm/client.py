from __future__ import annotations
import os
from typing import Optional
import anthropic


class LLMClient:
    def __init__(self, model: str = "claude-opus-4-6"):
        self.model = model
        self._client = anthropic.Anthropic(
            api_key=os.environ.get("ANTHROPIC_API_KEY", "")
        )

    async def think(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
    ) -> str:
        """Director Agent의 전략적 판단에 사용."""
        response = self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

    async def think_with_tools(
        self,
        system: str,
        user: str,
        tools: list[dict],
        max_tokens: int = 8192,
    ) -> anthropic.types.Message:
        """Tool use 포함 판단."""
        return self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            tools=tools,
            messages=[{"role": "user", "content": user}],
        )
