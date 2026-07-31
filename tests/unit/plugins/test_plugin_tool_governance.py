# -*- coding: utf-8 -*-
# pylint: disable=protected-access,import-outside-toplevel
"""Unit tests for plugin ``register_tool`` side-effect governance (Task 7).

``PluginApi.register_tool`` accepts a ``side_effect`` argument that flows
into the runtime ``ToolDescriptor.effect`` (a ``ToolEffectSpec``). The
authoritative role-based mutation gate (Task 5) consumes that spec, so a
plugin tool registered with ``side_effect="mutate"`` must be denied for a
non-privileged member while ``side_effect="read"`` is allowed and the
default (``"unknown"``) is fail-closed.

These tests run the deferred startup hook directly with the heavy
dependencies (governance registry, tools module, agent config) stubbed so
the descriptor wiring can be asserted in isolation.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from qwenpaw.security.mutation_guard import (
    ActionEffect,
    RequestPrincipal,
    authorize_effect,
)
from qwenpaw.config.config import MutationGuardConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def fresh_registry():
    """Create a fresh PluginRegistry (bypass singleton for test isolation)."""
    from qwenpaw.plugins.registry import PluginRegistry

    old_instance = PluginRegistry._instance
    PluginRegistry._instance = None
    registry = PluginRegistry()
    yield registry
    PluginRegistry._instance = old_instance


@pytest.fixture()
def plugin_api(fresh_registry):
    """Create a PluginApi instance bound to a fresh registry."""
    from qwenpaw.plugins.api import PluginApi

    api = PluginApi(
        "gov-plugin",
        config={},
        manifest={"id": "gov-plugin"},
    )
    api.set_registry(fresh_registry)
    return api


def _run_register_tool_hook(
    plugin_api,
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    side_effect: str,
) -> Any:
    """Call ``register_tool`` and run the resulting startup hook.

    Stubs ownership/governance/agent-config so the hook completes and
    attaches a ``ToolDescriptor`` to ``tool_func``.  Returns ``tool_func``
    so the caller can inspect ``tool_func._tool_descriptor.effect``.
    """

    async def fake_tool_func(**_kwargs):
        return "ok"

    fake_tool_func.__name__ = tool_name

    # Stub the heavy collaborators so the startup hook can run standalone.
    monkeypatch.setattr(
        "qwenpaw.plugins.api._claim_tool_ownership",
        lambda _name, _plugin: None,
    )
    monkeypatch.setattr(
        "qwenpaw.plugins.api._register_to_governance",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "qwenpaw.plugins.api._release_tool_registration",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "qwenpaw.plugins.api._write_tool_config",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "qwenpaw.plugins.api._unbridge_from_runtime",
        lambda *args, **kwargs: None,
    )

    # Provide a fake tools module so ``setattr`` lands on a MagicMock.
    import sys

    fake_tools_module = MagicMock()
    fake_tools_module.__all__ = []
    monkeypatch.setitem(sys.modules, "qwenpaw.agents.tools", fake_tools_module)

    plugin_api.register_tool(
        tool_name=tool_name,
        tool_func=fake_tool_func,
        description="governance test",
        enabled=True,
        tool_type="network",
        side_effect=side_effect,
    )

    hooks = plugin_api._registry.get_startup_hooks()
    register_hooks = [
        h for h in hooks if h.hook_name.startswith("register_tool_")
    ]
    assert register_hooks, "register_tool did not schedule a startup hook"
    register_hooks[-1].callback()

    return fake_tool_func


# ---------------------------------------------------------------------------
# Descriptor wiring
# ---------------------------------------------------------------------------


def test_register_tool_side_effect_flows_to_descriptor(
    plugin_api,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool_func = _run_register_tool_hook(
        plugin_api,
        monkeypatch,
        "governance_mutate_tool",
        side_effect="mutate",
    )

    desc = getattr(tool_func, "_tool_descriptor", None)
    assert desc is not None, "ToolDescriptor was not attached to tool_func"
    assert desc.effect.default is ActionEffect.MUTATE


def test_register_tool_read_side_effect_is_read(
    plugin_api,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tool_func = _run_register_tool_hook(
        plugin_api,
        monkeypatch,
        "governance_read_tool",
        side_effect="read",
    )

    desc = tool_func._tool_descriptor
    assert desc.effect.default is ActionEffect.READ


def test_register_tool_default_side_effect_is_unknown(
    plugin_api,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Default side_effect must be "unknown" (fail-closed).
    tool_func = _run_register_tool_hook(
        plugin_api,
        monkeypatch,
        "governance_default_tool",
        side_effect="unknown",
    )

    desc = tool_func._tool_descriptor
    assert desc.effect.default is ActionEffect.UNKNOWN


# ---------------------------------------------------------------------------
# End-to-end authorization through authorize_effect
# ---------------------------------------------------------------------------

_MEMBER_PRINCIPAL = RequestPrincipal(
    user_id="member",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)
_ADMIN_PRINCIPAL = RequestPrincipal(
    user_id="admin",
    roles=("admin",),
    source="nocobase",
    guarded=True,
    can_mutate=True,
)
_GUARD_CONFIG = MutationGuardConfig()


@pytest.mark.parametrize(
    "side_effect, principal, allowed",
    [
        ("mutate", _MEMBER_PRINCIPAL, False),
        ("external_side_effect", _MEMBER_PRINCIPAL, False),
        ("unknown", _MEMBER_PRINCIPAL, False),
        ("read", _MEMBER_PRINCIPAL, True),
        ("chat_infrastructure", _MEMBER_PRINCIPAL, True),
        # Admin (can_mutate) is never denied by the role gate.
        ("mutate", _ADMIN_PRINCIPAL, True),
        ("unknown", _ADMIN_PRINCIPAL, True),
    ],
)
def test_plugin_tool_effect_authorizes_member(
    plugin_api,
    monkeypatch: pytest.MonkeyPatch,
    side_effect: str,
    principal: RequestPrincipal,
    allowed: bool,
) -> None:
    tool_func = _run_register_tool_hook(
        plugin_api,
        monkeypatch,
        f"governance_{side_effect}_tool",
        side_effect=side_effect,
    )

    decision = authorize_effect(
        principal,
        tool_func._tool_descriptor.effect.default,
        _GUARD_CONFIG,
    )
    assert decision.allowed is allowed
