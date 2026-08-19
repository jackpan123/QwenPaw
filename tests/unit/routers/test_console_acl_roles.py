# -*- coding: utf-8 -*-
"""acl_roles injection into the console native payload."""

# pylint: disable=protected-access,using-constant-test

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from qwenpaw.app.chats.manager import ChatManager
from qwenpaw.app.chats.repo import JsonChatRepository
from qwenpaw.app.routers import console as console_router
from qwenpaw.app.routers.console import (
    _extract_authenticated_session_and_payload,
    _extract_session_and_payload,
)
from qwenpaw.security.mutation_guard import RequestPrincipal


@pytest.fixture(name="chat_manager")
def chat_manager_fixture(tmp_path):
    return ChatManager(repo=JsonChatRepository(tmp_path / "chats.json"))


class _ConsoleChannel:
    def resolve_session_id(self, sender_id, channel_meta):
        return channel_meta.get("session_id") or f"console:{sender_id}"

    async def stream_one(self, _payload):
        yield ""


class _ChannelManager:
    async def get_channel(self, _channel):
        return _ConsoleChannel()


class _TaskTracker:
    async def attach_or_start(
        self,
        _chat_id,
        payload,
        _stream,
        **_kwargs,
    ):
        self.payload = payload
        return object(), True


def _workspace(chat_manager):
    return SimpleNamespace(
        channel_manager=_ChannelManager(),
        chat_manager=chat_manager,
        task_tracker=_TaskTracker(),
        # Upstream resolves an effective project dir on the chat path.
        agent_id="default",
        workspace_dir=Path(tempfile.gettempdir()),
    )


def _request(username="alice"):
    return SimpleNamespace(
        state=SimpleNamespace(
            user=username,
            user_roles=["member"],
        ),
    )


def _request_data(session_id):
    return {
        "user_id": "default",
        "session_id": session_id,
        "channel": "console",
        "input": [],
    }


def test_acl_roles_injected_into_meta():
    payload = _extract_session_and_payload(
        {"user_id": "x", "session_id": "s", "input": []},
        acl_sender_id="u@x.io",
        acl_roles=["admin", "member"],
    )
    assert payload["acl_sender_id"] == "u@x.io"
    assert payload["meta"]["acl_sender_id"] == "u@x.io"
    assert payload["meta"]["acl_roles"] == ["admin", "member"]


def test_no_roles_absent_from_meta():
    payload = _extract_session_and_payload(
        {"user_id": "x", "session_id": "s", "input": []},
        acl_sender_id="u@x.io",
    )
    assert payload["meta"].get("acl_roles", []) == []


def test_roles_without_sender_still_injected():
    payload = _extract_session_and_payload(
        {"user_id": "x", "session_id": "s", "input": []},
        acl_roles=["admin"],
    )
    assert payload["meta"]["acl_roles"] == ["admin"]


# ── Server-trusted request principal propagation ─────────────────────


_MEMBER_PRINCIPAL = RequestPrincipal(
    user_id="alice",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)


def test_console_payload_contains_server_principal():
    payload = _extract_session_and_payload(
        {"user_id": "forged", "input": []},
        acl_sender_id="alice",
        acl_roles=["member"],
        request_principal=_MEMBER_PRINCIPAL,
    )
    assert payload["meta"]["acl_principal"] == _MEMBER_PRINCIPAL.to_context()
    assert payload["meta"]["acl_principal"]["user_id"] == "alice"


def test_console_payload_drops_client_forged_principal():
    payload = _extract_session_and_payload(
        {
            "input": [],
            "request_context": {
                "request_principal": {
                    "user_id": "mallory",
                    "roles": ["root"],
                    "can_mutate": True,
                },
                "acl_principal": {
                    "user_id": "attacker",
                    "roles": ["root"],
                    "can_mutate": True,
                },
            },
        },
    )
    request_context = payload["meta"].get("request_context", {})
    assert "request_principal" not in request_context
    assert "acl_principal" not in request_context
    assert "acl_principal" not in payload["meta"]


def test_console_payload_preserves_other_request_context_when_dropping():
    payload = _extract_session_and_payload(
        {
            "input": [],
            "request_context": {
                "request_principal": {"user_id": "mallory"},
                "approval_level": "strict",
            },
        },
        request_principal=_MEMBER_PRINCIPAL,
    )
    rc = payload["meta"].get("request_context", {})
    assert rc.get("approval_level") == "strict"
    assert "request_principal" not in rc
    assert payload["meta"]["acl_principal"] == _MEMBER_PRINCIPAL.to_context()


async def test_background_endpoint_injects_server_principal(monkeypatch):
    captured = {}

    class FakeChannel:
        def resolve_session_id(self, sender_id, channel_meta):
            del sender_id, channel_meta
            return "session-1"

        async def stream_one(self, native_payload):
            captured["stream_payload"] = native_payload
            if False:
                yield ""

    class FakeChannelManager:
        async def get_channel(self, _name):
            return FakeChannel()

    class FakeChatManager:
        async def get_chat_by_identity(self, *_args, **_kwargs):
            return None

        async def get_or_create_chat(self, *_args, **_kwargs):
            # Upstream reads chat.meta to resolve the session project dir.
            return SimpleNamespace(id="chat-1", name="chat", meta={})

    workspace = SimpleNamespace(
        channel_manager=FakeChannelManager(),
        chat_manager=FakeChatManager(),
        agent_id="default",
        workspace_dir=Path(tempfile.gettempdir()),
    )

    async def fake_get_agent(_request):
        return workspace

    original_extract = (
        console_router._extract_authenticated_session_and_payload
    )

    async def spy_extract(
        request_data,
        *,
        chat_manager,
        acl_sender_id="",
        acl_roles=None,
        request_principal=None,
    ):
        captured["principal"] = request_principal
        return await original_extract(
            request_data,
            chat_manager=chat_manager,
            acl_sender_id=acl_sender_id,
            acl_roles=acl_roles,
            request_principal=request_principal,
        )

    monkeypatch.setattr(
        console_router,
        "get_agent_for_request",
        fake_get_agent,
    )
    monkeypatch.setattr(
        console_router,
        "_extract_authenticated_session_and_payload",
        spy_extract,
    )
    request = SimpleNamespace(
        state=SimpleNamespace(
            user="alice",
            user_roles=["member"],
            request_principal=_MEMBER_PRINCIPAL,
        ),
    )

    response = await console_router.post_console_chat_task(
        {"user_id": "forged", "session_id": "session-1", "input": []},
        request,
    )
    task = console_router._bg_tasks[response["task_id"]].asyncio_task
    assert task is not None
    await asyncio.wait_for(task, timeout=1)

    assert captured["principal"] is _MEMBER_PRINCIPAL
    assert captured["stream_payload"]["meta"]["acl_principal"] == (
        _MEMBER_PRINCIPAL.to_context()
    )


@pytest.mark.asyncio
async def test_authenticated_new_console_session_uses_trusted_username(
    chat_manager,
):
    payload = await _extract_authenticated_session_and_payload(
        {
            "user_id": "default",
            "session_id": "new-session",
            "channel": "console",
            "input": [],
        },
        chat_manager=chat_manager,
        acl_sender_id="alice",
        acl_roles=["member"],
        request_principal=_MEMBER_PRINCIPAL,
    )

    assert payload["sender_id"] == "alice"
    assert payload["meta"]["user_id"] == "alice"
    assert payload["acl_sender_id"] == "alice"
    assert payload["meta"]["acl_roles"] == ["member"]
    assert payload["meta"]["acl_principal"] == _MEMBER_PRINCIPAL.to_context()


@pytest.mark.asyncio
async def test_authenticated_existing_default_session_keeps_legacy_user_id(
    chat_manager,
):
    legacy = await chat_manager.get_or_create_chat(
        session_id="legacy-session",
        user_id="default",
        channel="console",
    )

    payload = await _extract_authenticated_session_and_payload(
        {
            "user_id": "client-supplied-user",
            "session_id": "legacy-session",
            "channel": "console",
            "input": [],
        },
        chat_manager=chat_manager,
        acl_sender_id="alice",
    )
    existing = await chat_manager.get_or_create_chat(
        session_id=payload["meta"]["session_id"],
        user_id=payload["sender_id"],
        channel=payload["channel_id"],
    )

    assert payload["sender_id"] == "default"
    assert payload["meta"]["user_id"] == "default"
    assert payload["acl_sender_id"] == "alice"
    assert existing.id == legacy.id
    assert len(await chat_manager.list_chats()) == 1


@pytest.mark.asyncio
async def test_unauthenticated_console_session_keeps_client_user_id(
    chat_manager,
):
    payload = await _extract_authenticated_session_and_payload(
        {
            "user_id": "local-user",
            "session_id": "local-session",
            "channel": "console",
            "input": [],
        },
        chat_manager=chat_manager,
    )

    assert payload["sender_id"] == "local-user"
    assert payload["meta"]["user_id"] == "local-user"
    assert "acl_sender_id" not in payload


@pytest.mark.asyncio
async def test_authenticated_external_channel_keeps_channel_user_id(
    chat_manager,
):
    payload = await _extract_authenticated_session_and_payload(
        {
            "user_id": "ding-user-id",
            "session_id": "dingtalk:ding-user-id",
            "channel": "dingtalk",
            "input": [],
        },
        chat_manager=chat_manager,
        acl_sender_id="alice",
    )

    assert payload["sender_id"] == "ding-user-id"
    assert payload["meta"]["user_id"] == "ding-user-id"
    assert payload["acl_sender_id"] == "alice"


@pytest.mark.asyncio
async def test_streaming_chat_route_persists_authenticated_username(
    chat_manager,
    monkeypatch,
):
    workspace = _workspace(chat_manager)

    async def get_workspace(_request):
        return workspace

    monkeypatch.setattr(
        console_router,
        "get_agent_for_request",
        get_workspace,
    )

    await console_router.post_console_chat(
        _request_data("stream-session"),
        _request(),
    )

    chats = await chat_manager.list_chats()
    assert len(chats) == 1
    assert chats[0].user_id == "alice"
    assert workspace.task_tracker.payload["sender_id"] == "alice"
    assert workspace.task_tracker.payload["meta"]["user_id"] == "alice"


@pytest.mark.asyncio
async def test_background_chat_route_persists_authenticated_username(
    chat_manager,
    monkeypatch,
):
    workspace = _workspace(chat_manager)

    async def get_workspace(_request):
        return workspace

    monkeypatch.setattr(
        console_router,
        "get_agent_for_request",
        get_workspace,
    )

    result = await console_router.post_console_chat_task(
        _request_data("task-session"),
        _request(),
    )
    await asyncio.sleep(0)

    chats = await chat_manager.list_chats()
    assert len(chats) == 1
    assert chats[0].user_id == "alice"
    assert result["task_id"].startswith("task-")
    task = console_router._bg_tasks[result["task_id"]].asyncio_task
    assert task is not None
    await asyncio.wait_for(task, timeout=1)
    console_router._bg_tasks.pop(result["task_id"], None)
