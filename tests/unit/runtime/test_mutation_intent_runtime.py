# -*- coding: utf-8 -*-
"""Runtime orchestration coverage for the mutation intent hook."""

# pylint: disable=using-constant-test

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from qwenpaw.app.agent_context import set_current_request_principal
from qwenpaw.app.workspace.workspace_plugins import WorkspacePlugins
from qwenpaw.hooks.security.mutation_intent_hook import MutationIntentHook
from qwenpaw.hooks.session.session_hook import SessionLoadHook
from qwenpaw.runtime.runtime import Runtime
from qwenpaw.schemas import (
    AgentRequest,
    AgentResponse,
    Message,
    Role,
    RunStatus,
    TextContent,
)
from qwenpaw.security.mutation_guard import RequestPrincipal
from qwenpaw.security.mutation_guard.intent import IntentKind, IntentResult

pytestmark = [pytest.mark.unit, pytest.mark.p1]

_MEMBER = RequestPrincipal(
    user_id="member@example.com",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)


@pytest.fixture(autouse=True)
def _trusted_member(monkeypatch):
    set_current_request_principal(_MEMBER)
    monkeypatch.setattr(
        "qwenpaw.hooks.security.mutation_intent_hook.load_config",
        lambda: SimpleNamespace(
            security=SimpleNamespace(
                mutation_guard=SimpleNamespace(
                    enabled=True,
                    intent_precheck_enabled=True,
                    classifier_timeout_seconds=8,
                    deny_message="测试：无权执行变更。",
                ),
            ),
        ),
    )
    yield
    set_current_request_principal(None)


def _request(text: str) -> AgentRequest:
    return AgentRequest(
        input=[
            Message(
                role=Role.USER,
                content=[TextContent(text=text)],
            ),
        ],
        session_id="sess-runtime",
        user_id="member@example.com",
        channel="console",
    )


def _runtime(classifier) -> Runtime:
    plugins = WorkspacePlugins()
    plugins.hook_registry.register(SessionLoadHook())
    plugins.hook_registry.register(
        MutationIntentHook(classifier=classifier),
    )
    workspace = SimpleNamespace(
        agent_id="agent-1",
        workspace_dir=None,
        plugins=plugins,
        session=None,
    )
    return Runtime(workspace=workspace, app_services=None)


async def _collect(runtime: Runtime, text: str) -> list:
    return [event async for event in runtime.run(_request(text))]


async def test_mutation_short_circuit_emits_envelope_and_skips_agent():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="rename assistant",
        ),
    )
    runtime = _runtime(classifier)

    with (
        patch("qwenpaw.runtime.runtime.AgentBuilder") as builder_cls,
        patch("qwenpaw.runtime.runtime.AgentExecutor") as executor_cls,
    ):
        events = await _collect(runtime, "你叫小明")

    builder_cls.assert_not_called()
    executor_cls.assert_not_called()
    classifier.assert_awaited_once()
    assert len(events) == 4
    response = events[-1]
    assert isinstance(response, AgentResponse)
    assert response.status is RunStatus.Completed
    assert response.output[0].status is RunStatus.Completed
    assert response.output[0].content[0].text == "测试：无权执行变更。"
    assert events[1].sequence_number == 2
    assert events[2].sequence_number == 3
    assert response.sequence_number == 4


async def test_read_only_intent_reaches_agent_build_and_execute(monkeypatch):
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.READ_ONLY,
            reason="asking for explanation",
        ),
    )
    runtime = _runtime(classifier)
    built_contexts = []
    executed_inputs = []
    agent = SimpleNamespace(close=AsyncMock())

    class _Builder:
        def __init__(self, *, app_services):
            assert app_services is None

        async def build(self, ctx):
            built_contexts.append(ctx)
            return agent

    class _Executor:
        def __init__(self, built_agent, envelope):
            assert built_agent is agent
            assert envelope is not None

        async def run(self, inputs):
            executed_inputs.append(inputs)
            if False:
                yield None

    monkeypatch.setattr("qwenpaw.runtime.runtime.AgentBuilder", _Builder)
    monkeypatch.setattr("qwenpaw.runtime.runtime.AgentExecutor", _Executor)

    events = await _collect(runtime, "如何修改名称？")

    classifier.assert_awaited_once()
    assert len(built_contexts) == 1
    assert len(executed_inputs) == 1
    agent.close.assert_awaited_once()
    assert isinstance(events[-1], AgentResponse)
    assert events[-1].status is RunStatus.Completed
