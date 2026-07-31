# -*- coding: utf-8 -*-
"""Unit tests for the DriverCapabilityTool mutation gate (Task 7).

A non-privileged member must be denied any Driver/MCP capability whose
effect is not READ/CHAT_INFRASTRUCTURE.  The gate is a no-op for local
operation (no principal / not guarded / can_mutate).
"""
from __future__ import annotations

import pytest
from agentscope.permission import PermissionBehavior

from qwenpaw.drivers.adapters.agentscope_tool import DriverCapabilityTool
from qwenpaw.drivers.capabilities import (
    CapabilityExposure,
    DriverCapability,
    DriverInvocationResult,
)
from qwenpaw.security.mutation_guard import ActionEffect


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
