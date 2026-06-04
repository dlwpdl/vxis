from __future__ import annotations

import asyncio

import pytest

from vxis.agent.ask.queue import AskQueue, AskStatus
from vxis.agent.tools.ask_human import AskHumanTool


@pytest.mark.asyncio
async def test_ask_human_unattended_never_blocks_even_when_blocking_requested() -> None:
    queue = AskQueue()
    tool = AskHumanTool(queue=queue, attended=False)

    result = await tool.run(
        scan_id="scan-1",
        iter=1,
        question="Is this intended behavior?",
        context_summary="The app exports all team users.",
        options=["intended", "vulnerable"],
        default_when_skipped="intended",
        blocking=True,
        timeout_seconds=30,
    )

    assert result.ok is True
    assert result.data["answer"] == "intended"
    assert result.data["status"] == AskStatus.SKIPPED.value
    assert result.data["assumed_safe_default"] is True
    assert result.data["blocking_denied"] is True
    assert queue.all("scan-1")[0].status == AskStatus.SKIPPED


@pytest.mark.asyncio
async def test_ask_human_attended_blocking_receives_operator_answer() -> None:
    queue = AskQueue()
    tool = AskHumanTool(queue=queue, attended=True, poll_interval_seconds=0.01)

    async def answer_when_pending() -> None:
        for _ in range(100):
            pending = queue.pending("scan-1")
            if pending:
                queue.answer(pending[0].question_id, "vulnerable", by="operator")
                return
            await asyncio.sleep(0.01)
        raise AssertionError("ask question was not enqueued")

    answer_task = asyncio.create_task(answer_when_pending())
    result = await tool.run(
        scan_id="scan-1",
        iter=2,
        question="Is cross-tenant export intended?",
        context_summary="Tenant A can export Tenant B users.",
        options=["intended", "vulnerable"],
        default_when_skipped="intended",
        blocking=True,
        timeout_seconds=1,
    )
    await answer_task

    assert result.ok is True
    assert result.data["answer"] == "vulnerable"
    assert result.data["status"] == AskStatus.ANSWERED.value
    assert result.data["assumed_safe_default"] is False


@pytest.mark.asyncio
async def test_ask_human_attended_timeout_uses_default() -> None:
    queue = AskQueue()
    tool = AskHumanTool(queue=queue, attended=True, poll_interval_seconds=0.01)

    result = await tool.run(
        scan_id="scan-1",
        question="Is deletion expected?",
        context_summary="Delete endpoint returns 204.",
        options=["intended", "vulnerable"],
        default_when_skipped="intended",
        blocking=True,
        timeout_seconds=1,
    )

    assert result.ok is True
    assert result.data["answer"] == "intended"
    assert result.data["status"] == AskStatus.TIMEOUT.value
    assert result.data["assumed_safe_default"] is True
