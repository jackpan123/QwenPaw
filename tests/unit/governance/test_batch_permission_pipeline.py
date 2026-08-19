# -*- coding: utf-8 -*-
"""Nested batch calls must use the same pre-execution permission pipeline."""

# pylint: disable=protected-access

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import get_type_hints

import pytest
from agentscope.permission import (
    PermissionBehavior,
    PermissionDecision,
    PermissionMode,
)
from agentscope.state import AgentState
from agentscope.tool import ToolChunk, ToolResponse, Toolkit

from qwenpaw.agents.tools.run_tool_batch import run_tool_batch
from qwenpaw.config.context import (
    set_current_agent_state,
    set_current_toolkit,
)
from qwenpaw.governance import PolicyGuardedTool, tool_adapter
from qwenpaw.governance.policy import (
    GovernanceAction,
    GovernanceDecision,
)
from qwenpaw.runtime.tool_guard import GuardedFunctionTool
from qwenpaw.runtime.tool_registry import ToolEffectSpec
from qwenpaw.security.mutation_guard import ActionEffect, tool_gate


def test_batch_helpers_accept_final_and_streaming_tool_responses() -> None:
    module = importlib.import_module(
        "qwenpaw.agents.tools.run_tool_batch",
    )
    result_type = ToolChunk | ToolResponse

    assert get_type_hints(module._call_tool)["return"] == result_type
    assert get_type_hints(module._response_payload)["response"] == result_type


def _principal(role: str, *, can_mutate: bool) -> dict:
    return {
        "request_principal": {
            "user_id": role,
            "roles": [role],
            "source": "nocobase",
            "guarded": True,
            "can_mutate": can_mutate,
        },
    }


def _patch_mutation_guard(monkeypatch) -> None:
    config = SimpleNamespace(
        security=SimpleNamespace(
            mutation_guard=SimpleNamespace(
                enabled=True,
                privileged_roles=["admin", "root"],
                deny_message="Permission denied.",
            ),
        ),
    )
    monkeypatch.setattr(tool_gate, "load_config", lambda: config)


class _Governor:
    def __init__(self, decision: GovernanceDecision) -> None:
        self.workspace_dir = "/tmp"
        self._decision = decision
        self.audits: list[tuple[object, object]] = []

    def assert_policy(self, _spec):
        return self._decision

    def audit(self, spec, decision):
        self.audits.append((spec, decision))


async def _run_nested(tool) -> object:
    toolkit = Toolkit(tools=[tool])
    state = AgentState()
    # QwenPawAgent uses BYPASS because its wrappers own approval/governance.
    state.permission_context.mode = PermissionMode.BYPASS
    set_current_toolkit(toolkit)
    set_current_agent_state(state)
    try:
        return await run_tool_batch(
            actions=[{"tool_name": tool.name, "arguments": {}}],
        )
    finally:
        set_current_agent_state(None)
        set_current_toolkit(None)


@pytest.mark.parametrize("role", ["admin", "root"])
@pytest.mark.asyncio
async def test_privileged_batch_call_honors_governance_deny(
    monkeypatch,
    role,
) -> None:
    _patch_mutation_guard(monkeypatch)
    calls = 0

    async def mutate() -> str:
        nonlocal calls
        calls += 1
        return "executed"

    tool = PolicyGuardedTool(
        mutate,
        governor=_Governor(
            GovernanceDecision(GovernanceAction.DENY, "policy denied"),
        ),
        request_context=_principal(role, can_mutate=True),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    result = await _run_nested(tool)

    assert calls == 0
    assert "denied by policy" in str(result)


@pytest.mark.parametrize(
    ("effect", "expected_execution_count"),
    [
        (ActionEffect.READ, 1),
        (ActionEffect.MUTATE, 0),
    ],
)
@pytest.mark.asyncio
async def test_member_batch_call_always_runs_wrapper_permission_check(
    monkeypatch,
    effect,
    expected_execution_count,
) -> None:
    _patch_mutation_guard(monkeypatch)
    checks = 0
    calls = 0

    async def operation() -> str:
        nonlocal calls
        calls += 1
        return "executed"

    tool = GuardedFunctionTool(
        operation,
        request_context=_principal("member", can_mutate=False),
        effect_spec=ToolEffectSpec(default=effect),
    )
    original_check = tool.check_permissions

    async def checked(*args, **kwargs):
        nonlocal checks
        checks += 1
        return await original_check(*args, **kwargs)

    tool.check_permissions = checked

    await _run_nested(tool)

    assert checks == 1
    assert calls == expected_execution_count


@pytest.mark.asyncio
async def test_batch_governance_ask_approves_once_before_execution(
    monkeypatch,
) -> None:
    _patch_mutation_guard(monkeypatch)
    approvals = 0
    calls = 0

    async def mutate() -> str:
        nonlocal calls
        calls += 1
        return "executed"

    async def approve_once(**_kwargs):
        nonlocal approvals
        approvals += 1
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="approved",
        )

    monkeypatch.setattr(tool_adapter, "_ask_user_approval", approve_once)
    tool = PolicyGuardedTool(
        mutate,
        governor=_Governor(
            GovernanceDecision(GovernanceAction.ASK, "approval needed"),
        ),
        request_context=_principal("admin", can_mutate=True),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    await _run_nested(tool)

    assert approvals == 1
    assert calls == 1


@pytest.mark.asyncio
async def test_batch_precheck_prepares_sandbox_for_execution(monkeypatch):
    _patch_mutation_guard(monkeypatch)
    received_sandbox = None
    sandbox = object()

    async def mutate(sandbox_config=None) -> str:
        nonlocal received_sandbox
        received_sandbox = sandbox_config
        return "executed"

    tool = PolicyGuardedTool(
        mutate,
        governor=_Governor(
            GovernanceDecision(
                GovernanceAction.SANDBOX_FALLBACK,
                "sandbox required",
                sandbox_config=sandbox,
            ),
        ),
        request_context=_principal("admin", can_mutate=True),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    await _run_nested(tool)

    assert received_sandbox is sandbox
