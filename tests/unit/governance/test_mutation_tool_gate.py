# -*- coding: utf-8 -*-
"""UT for the authoritative mutation gate in the tool execution path.

The role-based mutation gate must run FIRST in ``check_permissions``, before
approval_level / governance / sandbox / tool-guard. A non-privileged member
denied by the mutation guard must be rejected even when ``approval_level=off``
so closing approval can never bypass role restrictions.

The gate is a no-op for local / unauthenticated operation: with no
``request_principal`` in the request context, or ``principal.guarded`` is
False, or ``principal.can_mutate`` is True, the gate allows and falls through
to the rest of governance.
"""
from __future__ import annotations

# pylint: disable=protected-access

from types import SimpleNamespace

import pytest

from qwenpaw.governance import PolicyGuardedTool
from qwenpaw.governance import tool_adapter
from qwenpaw.runtime.tool_registry import ToolEffectSpec
from qwenpaw.security.mutation_guard import (
    ActionEffect,
    MutationDecision,
    RequestPrincipal,
    authorize_effect,
)
from qwenpaw.security.mutation_guard import tool_gate


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_DENY_MESSAGE = "Permission denied."


def _mutation_guard_config(*, enabled: bool = True):
    """A ``MutationGuardConfig``-shaped namespace for ``authorize_effect``."""
    return SimpleNamespace(
        enabled=enabled,
        privileged_roles=["admin", "root"],
        intent_precheck_enabled=True,
        classifier_timeout_seconds=8,
        deny_message=_DENY_MESSAGE,
    )


def _patch_mutation_guard(monkeypatch, *, enabled: bool = True):
    """Make ``tool_gate.load_config`` return a config whose mutation guard
    is enabled (or not). Avoids touching disk."""

    fake_config = SimpleNamespace(
        security=SimpleNamespace(
            mutation_guard=_mutation_guard_config(enabled=enabled),
        ),
    )
    monkeypatch.setattr(
        tool_gate,
        "load_config",
        lambda *a, **k: fake_config,
    )


def _member_request_context() -> dict:
    return {
        "request_principal": {
            "user_id": "member",
            "roles": ["member"],
            "source": "nocobase",
            "guarded": True,
            "can_mutate": False,
        },
    }


def _admin_request_context() -> dict:
    return {
        "request_principal": {
            "user_id": "admin",
            "roles": ["admin"],
            "source": "nocobase",
            "guarded": True,
            "can_mutate": True,
        },
    }


async def _noop():
    """Placeholder mutating tool fn — never reached in deny tests."""


# ---------------------------------------------------------------------------
# authorize_tool_call unit tests
# ---------------------------------------------------------------------------


class TestAuthorizeToolCall:
    def test_member_mutate_is_denied(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is False

    def test_member_read_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.READ),
            input_data={},
        )
        assert decision.allowed is True

    def test_admin_mutate_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_admin_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is True

    def test_no_principal_is_allowed_local_mode(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=None,
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is True

    def test_request_context_without_principal_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context={},
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is True

    def test_disabled_guard_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch, enabled=False)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is True

    def test_member_unknown_effect_is_denied_fail_closed(self, monkeypatch):
        # UNKNOWN is not READ/CHAT_INFRASTRUCTURE → denied for members.
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.UNKNOWN),
            input_data={},
        )
        assert decision.allowed is False

    def test_member_chat_infrastructure_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(
                default=ActionEffect.CHAT_INFRASTRUCTURE,
            ),
            input_data={},
        )
        assert decision.allowed is True

    def test_resolves_effect_from_input(self, monkeypatch):
        """A per-action spec must read the param value from input_data."""
        _patch_mutation_guard(monkeypatch)
        spec = ToolEffectSpec(
            default=ActionEffect.MUTATE,
            selector_param="action",
            read_values=("snapshot",),
        )
        allowed = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=spec,
            input_data={"action": "snapshot"},
        )
        assert allowed.allowed is True

        denied = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=spec,
            input_data={"action": "click"},
        )
        assert denied.allowed is False


# ---------------------------------------------------------------------------
# PolicyGuardedTool integration — gate runs BEFORE the OFF check
# ---------------------------------------------------------------------------


class TestGateShortCircuitsBeforeGovernance:
    @pytest.mark.asyncio
    async def test_member_denied_before_governance_off(self, monkeypatch):
        """A member+MUTATE call must DENY even when approval_level=off.

        Without the mutation gate the OFF short-circuit would ALLOW this
        call. The gate must run first and deny it.
        """
        _patch_mutation_guard(monkeypatch)
        # Make governance think approval is off (the OFF short-circuit).
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )

        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.DENY
        assert "mutation_permission_denied" in decision.message

    @pytest.mark.asyncio
    async def test_member_read_falls_through_off(self, monkeypatch):
        """A READ tool for a member is allowed by the gate, then the OFF
        short-circuit returns ALLOW."""
        _patch_mutation_guard(monkeypatch)
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )

        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.READ),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.ALLOW

    @pytest.mark.asyncio
    async def test_admin_mutate_falls_through_off(self, monkeypatch):
        """Admin (can_mutate=True) is not denied by the gate — falls through
        to the OFF short-circuit ALLOW."""
        _patch_mutation_guard(monkeypatch)
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )

        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context=_admin_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.ALLOW

    @pytest.mark.asyncio
    async def test_local_no_principal_falls_through_off(self, monkeypatch):
        """No request_principal → gate no-op → OFF short-circuit ALLOW.

        This is the path the existing governance regression tests rely on.
        """
        _patch_mutation_guard(monkeypatch)
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )

        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context={},
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.ALLOW

    @pytest.mark.asyncio
    async def test_unannotated_tool_denied_for_member_off(self, monkeypatch):
        """Fail-closed: an unannotated tool (default UNKNOWN) is denied for a
        member even when approval_level=off."""
        _patch_mutation_guard(monkeypatch)
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )

        # No effect_spec → defaults to UNKNOWN.
        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context=_member_request_context(),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.DENY
        assert "mutation_permission_denied" in decision.message
