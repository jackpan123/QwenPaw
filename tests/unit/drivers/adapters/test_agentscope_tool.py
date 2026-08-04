# -*- coding: utf-8 -*-
"""Unit tests for the DriverCapabilityTool mutation gate (Task 7).

A non-privileged member must be denied any Driver/MCP capability whose
effect is not READ/CHAT_INFRASTRUCTURE.  The gate is a no-op for local
operation (no principal / not guarded / can_mutate).
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from agentscope.message import ToolCallBlock, ToolResultState
from agentscope.permission import PermissionBehavior
from agentscope.state import AgentState
from agentscope.tool import Toolkit

from qwenpaw.drivers.adapters.agentscope_tool import DriverCapabilityTool
from qwenpaw.drivers.capabilities import (
    CapabilityExposure,
    DriverCapability,
    DriverInvocationResult,
)
from qwenpaw.security.mutation_guard import ActionEffect, tool_gate

MEMBER_CONTEXT = {
    "request_principal": {
        "user_id": "member",
        "roles": ["member"],
        "source": "nocobase",
        "guarded": True,
        "can_mutate": False,
    },
}

ADMIN_CONTEXT = {
    "request_principal": {
        "user_id": "admin",
        "roles": ["admin"],
        "source": "nocobase",
        "guarded": True,
        "can_mutate": True,
    },
}

ROOT_CONTEXT = {
    "request_principal": {
        "user_id": "root",
        "roles": ["root"],
        "source": "nocobase",
        "guarded": True,
        "can_mutate": True,
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


def _capability(
    effect: ActionEffect = ActionEffect.UNKNOWN,
) -> DriverCapability:
    return DriverCapability(
        capability_id="driver://mcp/demo/tools/write#invoke",
        driver_name="demo",
        protocol="mcp",
        kind="tool",
        action="invoke",
        name="write",
        input_schema={"type": "object", "properties": {}},
        effect=effect,
        exposure=CapabilityExposure(as_tool=True, tool_name="write"),
    )


def _invoker_tracker() -> tuple:
    """Return (invoker, state_dict) where state['invoked'] flips on call."""
    state = {"invoked": False, "calls": []}

    async def _invoke(invocation):
        state["invoked"] = True
        state["calls"].append(invocation)
        return DriverInvocationResult(ok=True, value="unexpected")

    return _invoke, state


@pytest.mark.asyncio
async def test_unknown_driver_capability_denied_for_member() -> None:
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.UNKNOWN),
        invoke,
        request_context=MEMBER_CONTEXT,
    )
    decision = await tool.check_permissions()

    assert decision.behavior is PermissionBehavior.DENY
    assert state["invoked"] is False


@pytest.mark.asyncio
async def test_mutate_driver_capability_denied_for_member() -> None:
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.MUTATE),
        invoke,
        request_context=MEMBER_CONTEXT,
    )
    decision = await tool.check_permissions()

    assert decision.behavior is PermissionBehavior.DENY
    assert state["invoked"] is False


@pytest.mark.asyncio
async def test_external_driver_capability_denied_for_member() -> None:
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.EXTERNAL_SIDE_EFFECT),
        invoke,
        request_context=MEMBER_CONTEXT,
    )
    decision = await tool.check_permissions()

    assert decision.behavior is PermissionBehavior.DENY
    assert state["invoked"] is False


@pytest.mark.asyncio
async def test_readonly_driver_capability_allowed_for_member() -> None:
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.READ),
        invoke,
        request_context=MEMBER_CONTEXT,
    )
    decision = await tool.check_permissions()

    assert decision.behavior is PermissionBehavior.ALLOW
    assert state["invoked"] is False


@pytest.mark.asyncio
async def test_chat_infrastructure_driver_capability_allowed_for_member() -> (
    None
):
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.CHAT_INFRASTRUCTURE),
        invoke,
        request_context=MEMBER_CONTEXT,
    )
    decision = await tool.check_permissions()

    assert decision.behavior is PermissionBehavior.ALLOW


@pytest.mark.asyncio
async def test_admin_not_denied_for_unknown_capability() -> None:
    # An admin (can_mutate=True) must fall through to the original
    # "Driver capability policy is handled by Driver" ALLOW.
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.UNKNOWN),
        invoke,
        request_context=ADMIN_CONTEXT,
    )
    decision = await tool.check_permissions()

    assert decision.behavior is PermissionBehavior.ALLOW


@pytest.mark.asyncio
async def test_local_no_principal_not_denied() -> None:
    # Local operation (no request principal) is a no-op for the gate.
    invoke, _state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.UNKNOWN),
        invoke,
        request_context={},
    )
    decision = await tool.check_permissions()

    assert decision.behavior is PermissionBehavior.ALLOW
    assert "Driver capability policy is handled by Driver" in decision.message


@pytest.mark.parametrize(
    ("effect", "request_context"),
    [
        (ActionEffect.MUTATE, MEMBER_CONTEXT),
        (ActionEffect.UNKNOWN, MEMBER_CONTEXT),
        (
            ActionEffect.MUTATE,
            {"request_principal": "malformed-principal"},
        ),
    ],
)
@pytest.mark.asyncio
async def test_direct_driver_call_cannot_bypass_role_gate(
    monkeypatch,
    effect,
    request_context,
) -> None:
    _patch_mutation_guard(monkeypatch)
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(effect),
        invoke,
        request_context=request_context,
    )

    result = await tool(api_token="must-not-execute")

    assert result.state is ToolResultState.DENIED
    assert state["invoked"] is False


@pytest.mark.asyncio
async def test_direct_member_read_invokes_driver_policy_once(
    monkeypatch,
) -> None:
    _patch_mutation_guard(monkeypatch)
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.READ),
        invoke,
        request_context=MEMBER_CONTEXT,
    )

    result = await tool(query="safe")

    assert result.state is ToolResultState.SUCCESS
    assert len(state["calls"]) == 1


@pytest.mark.parametrize(
    "request_context",
    [ADMIN_CONTEXT, ROOT_CONTEXT, {}],
)
@pytest.mark.asyncio
async def test_privileged_and_local_driver_policy_runs_once_after_precheck(
    monkeypatch,
    request_context,
) -> None:
    _patch_mutation_guard(monkeypatch)
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(ActionEffect.UNKNOWN),
        invoke,
        request_context=request_context,
    )

    decision = await tool.check_permissions({"action": "write"})
    result = await tool(action="write")

    assert decision.behavior is PermissionBehavior.ALLOW
    assert result.state is ToolResultState.SUCCESS
    assert len(state["calls"]) == 1


@pytest.mark.parametrize(
    ("effect", "request_context", "expected_calls"),
    [
        (ActionEffect.MUTATE, MEMBER_CONTEXT, 0),
        (ActionEffect.UNKNOWN, MEMBER_CONTEXT, 0),
        (
            ActionEffect.MUTATE,
            {"request_principal": "malformed-principal"},
            0,
        ),
        (ActionEffect.READ, MEMBER_CONTEXT, 1),
    ],
)
@pytest.mark.asyncio
async def test_toolkit_driver_call_enforces_role_gate(
    monkeypatch,
    effect,
    request_context,
    expected_calls,
) -> None:
    _patch_mutation_guard(monkeypatch)
    invoke, state = _invoker_tracker()
    tool = DriverCapabilityTool(
        _capability(effect),
        invoke,
        request_context=request_context,
    )
    toolkit = Toolkit(tools=[tool])

    chunks = [
        chunk
        async for chunk in toolkit.call_tool(
            ToolCallBlock(
                id="driver-call",
                name=tool.name,
                input=json.dumps({"api_token": "must-not-execute"}),
            ),
            AgentState(),
        )
    ]

    assert len(state["calls"]) == expected_calls
    denied = any(chunk.state is ToolResultState.DENIED for chunk in chunks)
    assert denied is (expected_calls == 0)


@pytest.mark.asyncio
async def test_driver_denial_audit_is_structured_and_parameter_free(
    monkeypatch,
    caplog,
) -> None:
    _patch_mutation_guard(monkeypatch)
    invoke, state = _invoker_tracker()
    secret = "driver-secret-token-value"
    request_context = {
        "request_principal": {
            "user_id": "member-7",
            "roles": "admin",
            "source": "nocobase",
            "guarded": "true",
            "can_mutate": "false",
        },
        "agent_id": "agent-7",
        "session_id": "session-9",
        "channel": "console",
    }
    tool = DriverCapabilityTool(
        _capability(ActionEffect.MUTATE),
        invoke,
        request_context=request_context,
    )

    with caplog.at_level(
        "INFO",
        logger="qwenpaw.security.mutation_guard.audit",
    ):
        result = await tool(api_token=secret, payload="do not log")

    assert result.state is ToolResultState.DENIED
    assert state["invoked"] is False
    messages = [
        record.getMessage()
        for record in caplog.records
        if "[MUTATION AUDIT]" in record.getMessage()
    ]
    assert len(messages) == 1
    payload = json.loads(messages[0].split("[MUTATION AUDIT] ", 1)[1])
    assert payload == {
        "agent_id": "agent-7",
        "channel": "console",
        "decision": "deny",
        "event": "driver_tool_denied",
        "reason": "effect_mutate_requires_privileged_role",
        "roles": [],
        "session_id": "session-9",
        "source": "nocobase",
        "tool": "write",
        "user_id": "member-7",
    }
    assert secret not in caplog.text
    assert "api_token" not in caplog.text
    assert "do not log" not in caplog.text
