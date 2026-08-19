# -*- coding: utf-8 -*-
"""Security boundaries for Console routes with mixed chat side effects."""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from qwenpaw.app.mutation_authorization import MutationAuthorizationMiddleware
from qwenpaw.app.routers import console
from qwenpaw.app.task_tracker import RunOwnershipError
from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.security.mutation_guard import RequestPrincipal


MEMBER = RequestPrincipal(
    user_id="alice",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)
ADMIN = RequestPrincipal(
    user_id="admin-user",
    roles=("admin",),
    source="nocobase",
    guarded=True,
    can_mutate=True,
)


def _request(principal: RequestPrincipal) -> Request:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/console/chat/task",
            "headers": [],
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 1234),
            "scheme": "http",
        },
    )
    request.state.request_principal = principal
    request.state.user = principal.user_id
    request.state.user_roles = list(principal.roles)
    return request


def _chat_body(*, request_context: dict | None = None) -> dict:
    body = {
        "channel": "console",
        "user_id": "client-session-user",
        "session_id": "session-1",
        "input": [
            {
                "role": "user",
                "type": "message",
                "content": [{"type": "text", "text": "hello"}],
            },
        ],
    }
    if request_context is not None:
        body["request_context"] = request_context
    return body


class _ConsoleChannel:
    @staticmethod
    def resolve_session_id(*, sender_id, channel_meta):
        del sender_id
        return channel_meta["session_id"]

    @staticmethod
    async def stream_one(_payload):
        yield "data: " + json.dumps({"type": "message"}) + "\n\n"


class _ChatManager:
    calls = 0

    async def get_chat_by_identity(self, **_kwargs):
        return None

    async def get_or_create_chat(self, *_args, **_kwargs):
        self.calls += 1
        # Upstream reads chat.meta to resolve the session project dir.
        return SimpleNamespace(id="chat-1", name="existing-chat", meta={})


class _ChannelManager:
    async def get_channel(self, _channel):
        return _ConsoleChannel()


def _workspace():
    return SimpleNamespace(
        channel_manager=_ChannelManager(),
        chat_manager=_ChatManager(),
        # Upstream resolves an effective project dir on the chat path.
        agent_id="default",
        workspace_dir=Path(tempfile.gettempdir()),
    )


@pytest.mark.asyncio
async def test_member_fork_chat_task_is_denied_before_workspace_or_finalize(
    monkeypatch,
):
    workspace_calls = 0
    finalize_calls = 0

    async def get_workspace(_request):
        nonlocal workspace_calls
        workspace_calls += 1
        return _workspace()

    def finalize(*_args, **_kwargs):
        nonlocal finalize_calls
        finalize_calls += 1

    monkeypatch.setattr(console, "get_agent_for_request", get_workspace)
    monkeypatch.setattr(
        "qwenpaw.agents.fork_project.finalize_fork_worktree_or_fail",
        finalize,
    )

    response = await console.post_console_chat_task(
        _chat_body(
            request_context={
                "fork_project_dir": "/tmp/member-worktree",
                "fork_worktree_branch": "member-branch",
                "fork_scope_id": "scope-1",
            },
        ),
        _request(MEMBER),
    )

    assert response.status_code == 403
    assert workspace_calls == 0
    assert finalize_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("principal", [MEMBER, ADMIN])
async def test_member_and_admin_can_submit_normal_background_chat(
    monkeypatch,
    principal,
):
    workspace = _workspace()

    async def get_workspace(_request):
        return workspace

    monkeypatch.setattr(console, "get_agent_for_request", get_workspace)

    response = await console.post_console_chat_task(
        _chat_body(),
        _request(principal),
    )
    await asyncio.sleep(0)

    assert response["task_id"].startswith("task-")
    assert workspace.chat_manager.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["admin", "root"])
async def test_privileged_roles_can_submit_fork_background_chat(
    monkeypatch,
    role,
):
    principal = RequestPrincipal(
        user_id=f"{role}-user",
        roles=(role,),
        source="nocobase",
        guarded=True,
        can_mutate=True,
    )
    workspace = _workspace()

    async def get_workspace(_request):
        return workspace

    monkeypatch.setattr(console, "get_agent_for_request", get_workspace)

    response = await console.post_console_chat_task(
        _chat_body(request_context={"fork_project_dir": ""}),
        _request(principal),
    )
    await asyncio.sleep(0)

    assert response["task_id"].startswith("task-")
    assert workspace.chat_manager.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("principal", "expected_requester"),
    [(MEMBER, "alice"), (ADMIN, None)],
)
async def test_chat_stop_passes_trusted_owner_for_member_only(
    monkeypatch,
    principal,
    expected_requester,
):
    calls = []

    class Tracker:
        async def request_stop(self, chat_id, *, requester_id=None):
            calls.append((chat_id, requester_id))
            return True

    workspace = SimpleNamespace(task_tracker=Tracker(), chat_manager=None)

    async def get_workspace(_request):
        return workspace

    monkeypatch.setattr(console, "get_agent_for_request", get_workspace)

    result = await console.post_console_chat_stop(
        _request(principal),
        chat_id="chat-1",
    )

    assert result == {"stopped": True}
    assert calls == [("chat-1", expected_requester)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("principal", "expected_requester"),
    [(MEMBER, "alice"), (ADMIN, None)],
)
async def test_chat_reconnect_passes_trusted_requester_for_member_only(
    monkeypatch,
    principal,
    expected_requester,
):
    attach_calls = []

    class Tracker:
        async def attach(self, chat_id, *, requester_id=None):
            attach_calls.append((chat_id, requester_id))
            return object()

        async def stream_from_queue(self, _queue, _chat_id):
            yield 'data: {"type":"message"}\n\n'

    workspace = _workspace()
    workspace.task_tracker = Tracker()

    async def get_workspace(_request):
        return workspace

    monkeypatch.setattr(console, "get_agent_for_request", get_workspace)
    body = _chat_body()
    body["reconnect"] = True

    response = await console.post_console_chat(body, _request(principal))

    assert response.status_code == 200
    assert attach_calls == [("chat-1", expected_requester)]


@pytest.mark.asyncio
async def test_owner_mismatch_cannot_schedule_title_side_effect(
    monkeypatch,
):
    title_calls = 0

    class Tracker:
        async def attach_or_start(self, *_args, **_kwargs):
            raise RunOwnershipError("run owner mismatch")

    class ChatManager:
        async def get_chat_by_identity(self, **_kwargs):
            return None

        async def get_or_create_chat(self, *_args, **kwargs):
            return SimpleNamespace(
                id="victim-chat",
                name=kwargs["name"],
                meta={},
            )

    workspace = _workspace()
    workspace.task_tracker = Tracker()
    workspace.chat_manager = ChatManager()

    async def get_workspace(_request):
        return workspace

    async def generate_title(**_kwargs):
        nonlocal title_calls
        title_calls += 1

    monkeypatch.setattr(console, "get_agent_for_request", get_workspace)
    monkeypatch.setattr(console, "generate_and_update_title", generate_title)

    with pytest.raises(HTTPException) as exc_info:
        await console.post_console_chat(_chat_body(), _request(MEMBER))
    await asyncio.sleep(0)

    assert exc_info.value.status_code == 403
    assert title_calls == 0


@pytest.mark.asyncio
async def test_member_stop_session_fallback_is_scoped_to_trusted_owner(
    monkeypatch,
):
    lookups = []
    stop_calls = 0

    class Tracker:
        async def request_stop(self, _chat_id, *, requester_id=None):
            nonlocal stop_calls
            stop_calls += 1
            return stop_calls > 1 and requester_id == "alice"

    class ChatManager:
        async def get_chat_id_by_session(self, **kwargs):
            lookups.append(kwargs)
            return "owned-chat"

    workspace = SimpleNamespace(
        task_tracker=Tracker(),
        chat_manager=ChatManager(),
    )

    async def get_workspace(_request):
        return workspace

    monkeypatch.setattr(console, "get_agent_for_request", get_workspace)

    result = await console.post_console_chat_stop(
        _request(MEMBER),
        chat_id="shared-session",
    )

    assert result == {"stopped": True}
    assert lookups == [
        {
            "session_id": "shared-session",
            "channel": "console",
            "user_id": "alice",
        },
    ]


@pytest.mark.parametrize("principal,expected", [(MEMBER, 403), (ADMIN, 200)])
def test_inbox_read_is_a_mutation_before_handler(
    monkeypatch,
    principal,
    expected,
):
    calls = []

    async def mark_read(event_ids):
        calls.append(event_ids)
        return len(event_ids)

    monkeypatch.setattr("qwenpaw.app.inbox_store.mark_read", mark_read)
    app = FastAPI()
    app.include_router(console.router, prefix="/api")
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=MutationGuardConfig,
        principal_loader=lambda _request: principal,
    )

    response = TestClient(app).post(
        "/api/console/inbox/read",
        json={"event_ids": ["event-1"]},
    )

    assert response.status_code == expected
    assert calls == ([] if expected == 403 else [["event-1"]])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "endpoint",
    ["post_console_chat", "post_console_chat_task"],
)
async def test_member_cannot_persist_session_project_dir(
    monkeypatch,
    tmp_path,
    endpoint,
):
    """Selecting a session project dir is a mutation, not chat.

    ``session_project_dir`` arrives on the CHAT-capability chat routes, so
    the route-level gate does not cover it. It persists chat state and
    redirects where the agent reads from, so a guarded member must be
    refused before ``set_project_dir`` runs.
    """
    target = tmp_path / "elsewhere"
    target.mkdir()
    set_calls = []

    class ProjectDirChatManager(_ChatManager):
        async def set_project_dir(self, chat_id, path):
            set_calls.append((chat_id, path))
            return SimpleNamespace(id=chat_id, name="c", meta={})

    class _NoRunTracker:
        async def attach_or_start(self, *_args, **_kwargs):
            raise AssertionError("must be denied before dispatch")

    workspace = _workspace()
    workspace.chat_manager = ProjectDirChatManager()
    workspace.task_tracker = _NoRunTracker()

    async def get_workspace(_request):
        return workspace

    monkeypatch.setattr(console, "get_agent_for_request", get_workspace)

    body = _chat_body(
        request_context={"session_project_dir": str(target)},
    )
    response = await getattr(console, endpoint)(body, _request(MEMBER))

    status = getattr(response, "status_code", None)
    assert status == 403, f"expected denial, got {response}"
    assert set_calls == [], f"member persisted a project dir: {set_calls}"
