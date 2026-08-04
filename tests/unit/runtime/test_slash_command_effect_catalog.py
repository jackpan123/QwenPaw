# -*- coding: utf-8 -*-
"""Production slash-command side-effect catalog coverage."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from qwenpaw.api_action import ManagerBase, ManagerRegistry, api_action
from qwenpaw.app._api_action_routes import (
    collect_slash_specs_from_api_actions,
)
from qwenpaw.app.app_services._builtin_tool_commands import (
    build_tool_command_specs,
)
from qwenpaw.app.crons.manager import CronManager
from qwenpaw.modes.goal.goal_mode import GoalMode
from qwenpaw.modes.mission import MissionMode
from qwenpaw.modes.custom_loop.mode import (
    CustomLoopController,
    LoopModeActivationStore,
)
from qwenpaw.runtime.builtin_commands import collect_builtin_command_specs
from qwenpaw.runtime.slash_command_registry import SlashCommandRegistry
from qwenpaw.security.mutation_guard import ActionEffect


def _effects(specs) -> dict[str, ActionEffect]:
    return {spec.name: spec.effect for spec in specs}


def test_all_fixed_builtin_commands_are_explicitly_classified() -> None:
    effects = _effects(collect_builtin_command_specs())

    assert effects
    assert ActionEffect.UNKNOWN not in effects.values()


def test_goal_and_mission_commands_are_mutating() -> None:
    effects = _effects([*GoalMode().commands(), *MissionMode().commands()])

    assert effects == {
        "goal": ActionEffect.MUTATE,
        "mission": ActionEffect.MUTATE,
    }


def test_fixed_custom_loop_control_is_mutating() -> None:
    controller = CustomLoopController(LoopModeActivationStore())

    assert _effects(controller.commands()) == {
        "mode": ActionEffect.MUTATE,
    }


def test_hitl_tool_commands_have_real_effects() -> None:
    effects = _effects(build_tool_command_specs(MagicMock()))

    assert effects == {
        "tools": ActionEffect.READ,
        "tool-bg": ActionEffect.MUTATE,
        "tool-cancel": ActionEffect.MUTATE,
    }


def test_cron_api_action_commands_have_real_effects() -> None:
    registry = ManagerRegistry()
    registry.register(CronManager, lambda _state: None)

    effects = _effects(collect_slash_specs_from_api_actions(registry))

    assert effects == {
        "cron-list": ActionEffect.READ,
        "cron-create": ActionEffect.MUTATE,
        "cron-delete": ActionEffect.MUTATE,
    }


def test_custom_api_actions_default_unknown_but_can_declare_read() -> None:
    class CustomManager(ManagerBase):
        @api_action(methods={"slash"}, slash_command="custom-default")
        async def default_action(self) -> None:
            return None

        @api_action(
            methods={"slash"},
            slash_command="custom-read",
            side_effect="read",
        )
        async def read_action(self) -> None:
            return None

    registry = ManagerRegistry()
    registry.register(CustomManager, lambda _state: None)

    assert _effects(collect_slash_specs_from_api_actions(registry)) == {
        "custom-default": ActionEffect.UNKNOWN,
        "custom-read": ActionEffect.READ,
    }


def _member_context() -> SimpleNamespace:
    return SimpleNamespace(
        request=SimpleNamespace(
            channel="console",
            channel_meta={
                "acl_principal": {
                    "user_id": "member-1",
                    "roles": ["member"],
                    "source": "nocobase",
                    "guarded": True,
                    "can_mutate": False,
                },
            },
        ),
        agent_id="agent-1",
        session_id="session-1",
    )


@pytest.mark.parametrize(
    ("side_effect", "should_run"),
    [("read", True), ("unknown", False)],
)
@pytest.mark.asyncio
async def test_plugin_command_explicit_read_and_default_unknown_end_to_end(
    monkeypatch,
    side_effect: str,
    should_run: bool,
) -> None:
    from qwenpaw.plugins.api import PluginApi

    captured = []
    api = PluginApi("catalog-plugin", config={}, manifest={})
    monkeypatch.setattr(
        api,
        "_register_spec_to_all_workspaces",
        captured.append,
    )
    monkeypatch.setattr(
        api,
        "register_startup_hook",
        lambda *, callback, **_kwargs: callback(),
    )
    monkeypatch.setattr(
        api,
        "register_workspace_created_hook",
        lambda **_kwargs: None,
    )
    handler = AsyncMock(return_value=None)
    kwargs = {} if side_effect == "unknown" else {"side_effect": side_effect}

    api.register_slash_command("plugin-command", handler, **kwargs)
    registry = SlashCommandRegistry()
    registry.register(captured[0])
    result = await registry.dispatch("/plugin-command", _member_context())

    if should_run:
        handler.assert_awaited_once()
        assert result is None
    else:
        handler.assert_not_awaited()
        assert result is not None
