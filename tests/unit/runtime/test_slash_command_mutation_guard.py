# -*- coding: utf-8 -*-
"""Tests for the slash-command mutation guard gate (Task 6).

``SlashCommandRegistry.dispatch`` must authorize the command's
:class:`ActionEffect` against the request principal BEFORE calling the
handler: read/chat_infrastructure commands run for members; mutate/unknown
commands are denied (handler never invoked) for guarded non-privileged
members. The gate is a no-op when there is no authenticated principal
(local mode), and the ``/<skill_name>`` fallback path is never gated.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from agentscope.message import Msg, TextBlock

from qwenpaw.runtime.slash_command_registry import (
    CommandSpec,
    SlashCommandRegistry,
)
from qwenpaw.security.mutation_guard import ActionEffect


def _ctx(*, acl_principal=None) -> SimpleNamespace:
    """Build a minimal ctx with an optional guarded member principal."""
    channel_meta = {}
    if acl_principal is not None:
        channel_meta["acl_principal"] = acl_principal
    request = SimpleNamespace(channel_meta=channel_meta)
    return SimpleNamespace(request=request)


def _member_principal() -> dict:
    """A guarded, non-privileged member principal (cannot mutate)."""
    return {
        "user_id": "member-1",
        "roles": ["member"],
        "source": "nocobase",
        "guarded": True,
        "can_mutate": False,
    }


def _deny_msg() -> Msg:
    return Msg(
        name="assistant",
        role="assistant",
        content=[TextBlock(type="text", text="handler should not run")],
    )


@pytest.mark.asyncio
async def test_read_command_runs_for_member() -> None:
    expected = _deny_msg()
    handler = AsyncMock(return_value=expected)
    registry = SlashCommandRegistry()
    registry.register(
        CommandSpec(
            name="status",
            handler=handler,
            effect=ActionEffect.READ,
        ),
    )

    msg = await registry.dispatch(
        "/status",
        _ctx(acl_principal=_member_principal()),
    )

    handler.assert_awaited_once()
    assert msg is expected  # the handler's own return value


@pytest.mark.asyncio
async def test_chat_infrastructure_command_runs_for_member() -> None:
    handler = AsyncMock(return_value=_deny_msg())
    registry = SlashCommandRegistry()
    registry.register(
        CommandSpec(
            name="skills",
            handler=handler,
            effect=ActionEffect.CHAT_INFRASTRUCTURE,
        ),
    )

    await registry.dispatch(
        "/skills",
        _ctx(acl_principal=_member_principal()),
    )

    handler.assert_awaited_once()


@pytest.mark.asyncio
async def test_mutate_command_denied_for_member() -> None:
    handler = AsyncMock(return_value=_deny_msg())
    registry = SlashCommandRegistry()
    registry.register(
        CommandSpec(
            name="clear",
            handler=handler,
            effect=ActionEffect.MUTATE,
        ),
    )

    msg = await registry.dispatch(
        "/clear",
        _ctx(acl_principal=_member_principal()),
    )

    handler.assert_not_awaited()
    assert msg is not None
    text = msg.get_text_content()
    # Deny message references the guard, not the handler's body.
    assert "handler should not run" not in text
    assert "mutation" in text.lower() or "denied" in text.lower()


@pytest.mark.asyncio
async def test_unknown_command_denied_for_member_fail_closed() -> None:
    handler = AsyncMock(return_value=_deny_msg())
    registry = SlashCommandRegistry()
    registry.register(
        CommandSpec(
            name="ambiguous",
            handler=handler,
            effect=ActionEffect.UNKNOWN,
        ),
    )

    msg = await registry.dispatch(
        "/ambiguous",
        _ctx(acl_principal=_member_principal()),
    )

    handler.assert_not_awaited()
    assert msg is not None


@pytest.mark.asyncio
async def test_mutate_command_runs_without_principal_local_mode() -> None:
    """No authenticated principal (local mode) -> gate is a no-op."""
    handler = AsyncMock(return_value=_deny_msg())
    registry = SlashCommandRegistry()
    registry.register(
        CommandSpec(
            name="clear",
            handler=handler,
            effect=ActionEffect.MUTATE,
        ),
    )

    await registry.dispatch("/clear", _ctx())  # no acl_principal

    handler.assert_awaited_once()


@pytest.mark.asyncio
async def test_skill_fallback_not_gated_for_member() -> None:
    """The /<skill_name> fallback path is never gated (chat entry)."""
    fallback = AsyncMock(return_value=None)
    registry = SlashCommandRegistry()
    registry.register_fallback(fallback)

    await registry.dispatch(
        "/my-skill do something",
        _ctx(acl_principal=_member_principal()),
    )

    fallback.assert_awaited_once()


@pytest.mark.asyncio
async def test_unregistered_command_no_match_returns_none() -> None:
    """Unregistered command with no fallback returns None unchanged."""
    registry = SlashCommandRegistry()
    msg = await registry.dispatch(
        "/nope",
        _ctx(acl_principal=_member_principal()),
    )
    assert msg is None
