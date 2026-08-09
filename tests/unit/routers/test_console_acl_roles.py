# -*- coding: utf-8 -*-
"""acl_roles injection into the console native payload."""

# pylint: disable=protected-access,using-constant-test

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from qwenpaw.app.routers import console as console_router
from qwenpaw.app.routers.console import _extract_session_and_payload
from qwenpaw.security.mutation_guard import RequestPrincipal


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
        async def get_or_create_chat(self, *_args, **_kwargs):
            return None

    workspace = SimpleNamespace(
        channel_manager=FakeChannelManager(),
        chat_manager=FakeChatManager(),
    )

    async def fake_get_agent(_request):
        return workspace

    original_extract = console_router._extract_session_and_payload

    def spy_extract(*args, **kwargs):
        captured["principal"] = kwargs.get("request_principal")
        return original_extract(*args, **kwargs)

    monkeypatch.setattr(
        console_router,
        "get_agent_for_request",
        fake_get_agent,
    )
    monkeypatch.setattr(
        console_router,
        "_extract_session_and_payload",
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
