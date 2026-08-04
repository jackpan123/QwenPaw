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
from agentscope.message import ToolResultState

from qwenpaw.runtime.tool_guard import GuardedFunctionTool
from qwenpaw.runtime.tool_registry import (
    ToolEffectSpec,
    ToolRegistry,
    tool_descriptor,
)
from qwenpaw.security.mutation_guard import (
    ActionEffect,
    RequestPrincipal,
    authorize_effect,
)
from qwenpaw.security.mutation_guard import tool_gate
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


def _patch_mutation_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    config = MagicMock()
    config.security.mutation_guard = MutationGuardConfig(
        enabled=True,
        privileged_roles=["admin", "root"],
        deny_message="Permission denied.",
    )
    monkeypatch.setattr(tool_gate, "load_config", lambda: config)


def _run_register_tool_hook(
    plugin_api,
    monkeypatch: pytest.MonkeyPatch,
    tool_name: str,
    side_effect: str,
    tool_func: Any = None,
) -> Any:
    """Call ``register_tool`` and run the resulting startup hook.

    Stubs ownership/governance/agent-config so the hook completes and
    attaches a ``ToolDescriptor`` to ``tool_func``.  Returns ``tool_func``
    so the caller can inspect ``tool_func._tool_descriptor.effect``.
    """

    if tool_func is None:

        async def fake_tool_func(**_kwargs):
            return "ok"

        tool_func = fake_tool_func

    tool_func.__name__ = tool_name

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
        tool_func=tool_func,
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

    return tool_func


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


def test_register_tool_side_effect_overrides_decorator_and_preserves_fields(
    plugin_api,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @tool_descriptor(
        name="decorated_plugin_tool",
        enabled_by_default=False,
        requires_modes=("coding",),
        description="decorated description",
        tool_type="internal",
        ui_description="decorated ui",
        side_effect="read",
        custom_metadata="keep-me",
    )
    async def decorated_plugin_tool() -> str:
        return "ok"

    original = decorated_plugin_tool._tool_descriptor

    _run_register_tool_hook(
        plugin_api,
        monkeypatch,
        "decorated_plugin_tool",
        side_effect="mutate",
        tool_func=decorated_plugin_tool,
    )

    rebuilt = decorated_plugin_tool._tool_descriptor
    assert rebuilt is not original
    assert rebuilt.effect.default is ActionEffect.MUTATE
    assert rebuilt.requires_modes == original.requires_modes
    assert rebuilt.enabled_by_default is original.enabled_by_default
    assert rebuilt.description == original.description
    assert rebuilt.governance == original.governance
    assert rebuilt.ui == original.ui
    assert rebuilt.metadata == original.metadata


def test_runtime_bridge_replaces_stale_effect_on_hot_reload() -> None:
    from qwenpaw.plugins.api import _bridge_to_runtime

    runtime_registry = ToolRegistry()
    bootstrap: dict[str, list] = {"builtin_tool_funcs": []}

    class Plugins:
        tool_registry = runtime_registry

    class Workspace:
        agent_id = "default"
        plugins = Plugins()

    class Manager:
        agents = {"default": Workspace()}
        _bootstrap_kwargs = bootstrap

    class Registry:
        @staticmethod
        def get_workspace_manager():
            return Manager()

    @tool_descriptor(side_effect="read")
    async def hot_reload_tool() -> str:
        return "ok"

    mutate = ToolEffectSpec(default=ActionEffect.MUTATE)
    read = ToolEffectSpec(default=ActionEffect.READ)

    _bridge_to_runtime(
        "hot_reload_tool",
        hot_reload_tool,
        True,
        "hot reload",
        Registry(),
        effect=mutate,
    )
    stale = runtime_registry.get("hot_reload_tool")
    assert stale is not None
    assert stale.effect.default is ActionEffect.MUTATE

    async def reloaded_tool() -> str:
        return "reloaded"

    reloaded_tool._tool_descriptor = stale

    _bridge_to_runtime(
        "hot_reload_tool",
        reloaded_tool,
        True,
        "hot reload",
        Registry(),
        effect=read,
    )
    current = runtime_registry.get("hot_reload_tool")
    assert current is not None
    assert current is not stale
    assert current.func is reloaded_tool
    assert current.effect.default is ActionEffect.READ
    assert bootstrap["builtin_tool_funcs"] == [reloaded_tool]


@pytest.mark.parametrize(
    ("side_effect", "decorated_effect", "expected_calls"),
    [
        ("mutate", "read", 0),
        ("read", "mutate", 1),
    ],
)
@pytest.mark.asyncio
async def test_registered_side_effect_controls_real_runtime_wrapper(
    plugin_api,
    monkeypatch: pytest.MonkeyPatch,
    side_effect,
    decorated_effect,
    expected_calls,
) -> None:
    _patch_mutation_guard(monkeypatch)
    calls = 0

    @tool_descriptor(side_effect=decorated_effect)
    async def runtime_plugin_tool() -> str:
        nonlocal calls
        calls += 1
        return "executed"

    registered = _run_register_tool_hook(
        plugin_api,
        monkeypatch,
        "runtime_plugin_tool",
        side_effect=side_effect,
        tool_func=runtime_plugin_tool,
    )
    tool = GuardedFunctionTool(
        registered,
        request_context={
            "request_principal": {
                "user_id": "member",
                "roles": ["member"],
                "source": "nocobase",
                "guarded": True,
                "can_mutate": False,
            },
        },
    )

    result = await tool()

    assert calls == expected_calls
    assert (result.state is ToolResultState.DENIED) is (expected_calls == 0)


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
