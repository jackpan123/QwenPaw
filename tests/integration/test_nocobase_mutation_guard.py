# -*- coding: utf-8 -*-
# pylint: disable=not-callable,protected-access,redefined-outer-name
# pylint: disable=using-constant-test
"""End-to-end permission matrix for guarded NocoBase identities.

The tests deliberately cross real production boundaries instead of repeating
the lower-level policy assertions:

* external identity resolver -> auth middleware -> route capability middleware
  -> the registered mutation-guard configuration route;
* trusted request principal -> runtime HookRegistry -> mutation intent hook ->
  Envelope, followed by the authoritative tool wrapper when classification
  degrades to read-only;
* nested batch and Driver tool adapters, which are common bypass surfaces.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from agentscope.message import ToolCallBlock, ToolResultState
from agentscope.state import AgentState
from agentscope.tool import Toolkit
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.testclient import TestClient

import qwenpaw.agents.tools  # noqa: F401  pylint: disable=unused-import
from qwenpaw.agents.tools.run_tool_batch import run_tool_batch
from qwenpaw.app import auth as auth_mod
from qwenpaw.app.agent_context import (
    get_current_request_principal,
    set_current_request_principal,
)
from qwenpaw.app.mutation_authorization import (
    MutationAuthorizationMiddleware,
    api_capability,
)
from qwenpaw.app.routers import console as console_router_mod
from qwenpaw.app.routers import config as config_router_mod
from qwenpaw.app.workspace.workspace_plugins import WorkspacePlugins
from qwenpaw.app.workspace.workspace import Workspace
from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.config.context import (
    set_current_agent_state,
    set_current_toolkit,
)
from qwenpaw.drivers.adapters.agentscope_tool import DriverCapabilityTool
from qwenpaw.drivers.capabilities import (
    CapabilityExposure,
    DriverCapability,
    DriverInvocationResult,
)
from qwenpaw.hooks.security.mutation_intent_hook import MutationIntentHook
from qwenpaw.hooks.request_setup.contextvars_hook import ContextVarsSetupHook
from qwenpaw.hooks.session.session_hook import SessionLoadHook
from qwenpaw.runtime.builder import AgentBuilder
from qwenpaw.runtime.hooks import HookContext
from qwenpaw.runtime.phases import Phase
from qwenpaw.runtime.runtime import Runtime
from qwenpaw.runtime.tool_guard import GuardedFunctionTool
from qwenpaw.runtime.tool_registry import (
    ToolDescriptor,
    ToolEffectSpec,
    get_builtin_tool_funcs,
)
from qwenpaw.schemas import (
    AgentRequest,
    AgentResponse,
    Message,
    Role,
    RunStatus,
    TextContent,
)
from qwenpaw.security.mutation_guard import (
    ActionEffect,
    RequestPrincipal,
    RouteCapability,
)
from qwenpaw.security.mutation_guard.intent import IntentKind, IntentResult

pytestmark = [pytest.mark.integration, pytest.mark.p0]

_MEMBER = RequestPrincipal(
    user_id="member@example.com",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)


def _principal_context(principal: RequestPrincipal) -> dict:
    return {"request_principal": principal.to_context()}


@pytest.fixture(autouse=True)
def _restore_identity_registry():
    """Preserve resolver order and contents across this integration module."""
    original = list(auth_mod._external_identity_resolvers)
    auth_mod._external_identity_resolvers.clear()
    try:
        yield
    finally:
        auth_mod._external_identity_resolvers.clear()
        auth_mod._external_identity_resolvers.extend(original)
        set_current_request_principal(None)


@pytest.fixture
def nocobase_http_client(monkeypatch, tmp_path: Path):
    """Real auth/authorization/router stack with repeatable NB identities."""
    mutation_config = MutationGuardConfig()
    config = SimpleNamespace(
        security=SimpleNamespace(
            allow_no_auth_hosts=[],
            mutation_guard=mutation_config,
        ),
    )
    transactions: list[MutationGuardConfig] = []
    tool_calls: list[dict] = []
    identities = {
        "member-token": ("member@example.com", ["member"]),
        "viewer-token": ("viewer@example.com", ["viewer"]),
        "empty-token": ("empty@example.com", []),
        "admin-token": ("admin@example.com", ["AdMiN"]),
        "root-token": ("root@example.com", ["rOoT"]),
    }

    async def resolver(request):
        bearer = request.headers.get("Authorization", "").removeprefix(
            "Bearer ",
        )
        token = request.headers.get("X-NocoBase-Token") or bearer
        resolved = identities.get(token)
        if token == "legacy-token":
            return auth_mod.ResolvedIdentity(
                sender_id="legacy@example.com",
                roles=["member"],
                source="external",
            )
        if resolved is None:
            return None
        sender_id, roles = resolved
        return auth_mod.ResolvedIdentity(
            sender_id=sender_id,
            roles=roles,
            source="nocobase",
        )

    def update_transaction(update):
        update(config)
        transactions.append(config.security.mutation_guard)
        return config

    async def persist_matrix_target(target: str, value: str) -> str:
        tool_calls.append({"target": target, "value": value})
        Path(target).write_text(value, encoding="utf-8")
        return "written"

    workspace = Workspace("matrix-agent", str(tmp_path / "workspace"))
    workspace.plugins.hook_registry.register(ContextVarsSetupHook())
    workspace.plugins.tool_registry.register(
        ToolDescriptor(
            name="persist_matrix_target",
            func=persist_matrix_target,
            effect=ToolEffectSpec(default=ActionEffect.MUTATE),
        ),
    )
    pruning = SimpleNamespace(pruning_recent_msg_max_bytes=4096)
    agent_profile = SimpleNamespace(
        tools=SimpleNamespace(builtin_tools={}),
        running=SimpleNamespace(
            light_context_config=SimpleNamespace(
                tool_result_pruning_config=pruning,
            ),
            shell_command_timeout=30,
            shell_command_executable="",
        ),
        coding_mode=None,
    )

    monkeypatch.setattr(auth_mod, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "_get_config_cached",
        lambda: (config, []),
    )
    monkeypatch.setattr(
        config_router_mod,
        "mutate_config",
        update_transaction,
    )
    monkeypatch.setattr(
        "qwenpaw.config.config.load_agent_config",
        lambda _agent_id: agent_profile,
    )
    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.tool_gate.load_config",
        lambda: config,
    )
    auth_mod.register_external_identity_resolver(resolver)

    app = FastAPI()
    app.include_router(config_router_mod.router, prefix="/api")

    @app.post("/api/test/mutation-tool")
    @api_capability(RouteCapability.CHAT)
    async def invoke_registered_tool(request: Request) -> dict:
        body = await request.json()
        principal = request.state.request_principal
        agent_request = AgentRequest(
            session_id="builder-tool-chain",
            user_id=str(body.get("user_id") or "client-claimed-user"),
            channel="console",
            channel_meta={
                "acl_sender_id": principal.user_id,
                "acl_principal": principal.to_context(),
            },
            request_context={"approval_level": "OFF"},
        )
        ctx = HookContext(
            request=agent_request,
            session_id="builder-tool-chain",
            agent_id="matrix-agent",
            root_session_id="builder-tool-chain",
            root_agent_id="matrix-agent",
            workspace_dir=workspace.workspace_dir,
            workspace=workspace,
            app_services=None,
        )
        await workspace.plugins.hook_registry.run(Phase.PRE_DISPATCH, ctx)
        published = get_current_request_principal()
        builder = AgentBuilder(app_services=None)
        request_context = builder._build_request_context(ctx)
        toolkit = await builder.build_toolkit(
            agent_profile,
            agent_id="matrix-agent",
            request_context=request_context,
            ctx=ctx,
            workspace_dir=str(workspace.workspace_dir),
        )
        chunks = [
            chunk
            async for chunk in toolkit.call_tool(
                ToolCallBlock(
                    id="matrix-tool-call",
                    name="persist_matrix_target",
                    input=json.dumps(
                        {
                            "target": body["target"],
                            "value": body["value"],
                        },
                    ),
                ),
                AgentState(),
            )
        ]
        return {
            "principal": published.to_context() if published else None,
            "states": [
                getattr(getattr(chunk, "state", None), "value", None)
                for chunk in chunks
            ],
            "tool_calls": len(tool_calls),
        }

    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=lambda: config.security.mutation_guard,
    )
    app.add_middleware(auth_mod.AuthMiddleware)
    return TestClient(app), transactions, config


def _mutation_body(*, enabled: bool = True) -> dict:
    return {
        "enabled": enabled,
        "privileged_roles": ["admin", "root"],
        "intent_precheck_enabled": True,
        "classifier_timeout_seconds": 8,
        "deny_message": "Mutation denied.",
    }


@pytest.mark.parametrize(
    "token",
    ["member-token", "viewer-token", "empty-token"],
)
def test_direct_config_mutation_denies_read_only_identities_before_save(
    nocobase_http_client,
    token,
) -> None:
    client, transactions, _config = nocobase_http_client

    response = client.put(
        "/api/config/security/mutation-guard",
        headers={"Authorization": f"Bearer {token}"},
        json=_mutation_body(enabled=False),
    )

    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"
    assert transactions == []


@pytest.mark.parametrize("token", ["admin-token", "root-token"])
def test_direct_config_mutation_allows_casefolded_privileged_roles(
    nocobase_http_client,
    token,
) -> None:
    client, transactions, _config = nocobase_http_client

    response = client.put(
        "/api/config/security/mutation-guard",
        headers={"Authorization": f"Bearer {token}"},
        json=_mutation_body(),
    )

    assert response.status_code == 200
    assert len(transactions) == 1


def test_direct_config_mutation_requires_token_when_auth_enabled(
    nocobase_http_client,
) -> None:
    client, transactions, _config = nocobase_http_client

    response = client.put(
        "/api/config/security/mutation-guard",
        json=_mutation_body(enabled=False),
    )

    assert response.status_code == 401
    assert transactions == []


@pytest.mark.parametrize(
    "spoof",
    [
        {"roles": ["root"], "can_mutate": True, "user_id": "root"},
        {"request_principal": {"roles": ["root"], "can_mutate": True}},
    ],
)
def test_body_and_query_role_spoofing_cannot_upgrade_member(
    nocobase_http_client,
    spoof,
) -> None:
    client, transactions, _config = nocobase_http_client
    body = {**_mutation_body(enabled=False), **spoof}

    response = client.put(
        "/api/config/security/mutation-guard",
        params={
            "roles": "root",
            "can_mutate": "true",
            "user_id": "forged-root",
        },
        headers={
            "Authorization": "Bearer member-token",
            "X-User-Roles": "root",
            "X-Can-Mutate": "true",
        },
        json=body,
    )

    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"
    assert transactions == []


def test_auth_disabled_local_config_mutation_still_uses_real_handler(
    monkeypatch,
) -> None:
    config = SimpleNamespace(
        security=SimpleNamespace(
            allow_no_auth_hosts=[],
            mutation_guard=MutationGuardConfig(),
        ),
    )
    transactions = []

    def update_transaction(update):
        update(config)
        transactions.append(config.security.mutation_guard)
        return config

    monkeypatch.setattr(auth_mod, "is_auth_enabled", lambda: False)
    monkeypatch.setattr(
        config_router_mod,
        "mutate_config",
        update_transaction,
    )
    app = FastAPI()
    app.include_router(config_router_mod.router, prefix="/api")
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=lambda: config.security.mutation_guard,
    )
    app.add_middleware(auth_mod.AuthMiddleware)

    response = TestClient(app).put(
        "/api/config/security/mutation-guard",
        json=_mutation_body(),
    )

    assert response.status_code == 200
    assert len(transactions) == 1


def test_legacy_external_identity_remains_unguarded(
    nocobase_http_client,
) -> None:
    client, transactions, _config = nocobase_http_client

    response = client.put(
        "/api/config/security/mutation-guard",
        headers={"Authorization": "Bearer legacy-token"},
        json=_mutation_body(),
    )

    assert response.status_code == 200
    assert len(transactions) == 1


def test_real_identity_hook_builder_toolkit_chain_enforces_mutation_role(
    nocobase_http_client,
    tmp_path: Path,
) -> None:
    client, _transactions, _config = nocobase_http_client
    member_target = tmp_path / "member-builder-chain.txt"
    admin_target = tmp_path / "admin-builder-chain.txt"

    member = client.post(
        "/api/test/mutation-tool",
        headers={"Authorization": "Bearer member-token"},
        json={
            "target": str(member_target),
            "value": "member must not write",
            "user_id": "forged-root",
            "request_principal": {
                "roles": ["root"],
                "can_mutate": True,
            },
        },
    )
    admin = client.post(
        "/api/test/mutation-tool",
        headers={"Authorization": "Bearer admin-token"},
        json={
            "target": str(admin_target),
            "value": "admin may write",
        },
    )

    assert member.status_code == 200
    assert member.json()["principal"] == _MEMBER.to_context()
    assert "denied" in member.json()["states"]
    assert member.json()["tool_calls"] == 0
    assert not member_target.exists()
    assert admin.status_code == 200
    assert admin.json()["principal"]["can_mutate"] is True
    assert "success" in admin.json()["states"]
    assert admin.json()["tool_calls"] == 1
    assert admin_target.read_text(encoding="utf-8") == "admin may write"


async def _restore_console_background_tasks(original: dict) -> None:
    """Reap only tasks owned by this fixture, then restore the snapshot."""
    original_tasks = {
        id(background.asyncio_task)
        for background in original.values()
        if background.asyncio_task is not None
    }
    owned_tasks = []
    seen_tasks: set[int] = set()
    for key, background in list(console_router_mod._bg_tasks.items()):
        if background is original.get(key):
            continue
        task = background.asyncio_task
        if (
            task is None
            or id(task) in original_tasks
            or id(task) in seen_tasks
        ):
            continue
        owned_tasks.append(task)
        seen_tasks.add(id(task))

    for task in owned_tasks:
        if not task.done():
            task.cancel()
    if owned_tasks:
        await asyncio.gather(*owned_tasks, return_exceptions=True)

    async with console_router_mod._bg_lock:
        console_router_mod._bg_tasks.clear()
        console_router_mod._bg_tasks.update(original)


@pytest.fixture
def nocobase_console_client(monkeypatch):
    """HTTP console router driven by the same external identity fixture."""
    original_bg_tasks = dict(console_router_mod._bg_tasks)
    config = SimpleNamespace(
        security=SimpleNamespace(
            allow_no_auth_hosts=[],
            mutation_guard=MutationGuardConfig(),
        ),
    )
    captured: dict = {
        "streams": [],
        "extracts": [],
        "requests": [],
        "attach_calls": [],
        "start_calls": [],
        "stream_event": threading.Event(),
    }

    async def resolver(request):
        identities = {
            "Bearer member-token": ("member@example.com", ["member"]),
            "Bearer other-member-token": (
                "other@example.com",
                ["member"],
            ),
            "Bearer admin-token": ("admin@example.com", ["admin"]),
            "Bearer root-token": ("root@example.com", ["root"]),
        }
        identity = identities.get(request.headers.get("Authorization"))
        if identity is None:
            return None
        return auth_mod.ResolvedIdentity(
            sender_id=identity[0],
            roles=identity[1],
            source="nocobase",
        )

    class Channel:
        @staticmethod
        def resolve_session_id(sender_id, channel_meta):
            del sender_id
            return str(channel_meta.get("session_id") or "matrix-session")

        async def stream_one(self, native_payload):
            captured["streams"].append(native_payload)
            captured["stream_event"].set()
            yield 'data: {"type":"response","status":"completed"}\n\n'

    class ChannelManager:
        @staticmethod
        async def get_channel(_name):
            return Channel()

    class ChatManager:
        @staticmethod
        async def get_chat_by_identity(**_kwargs):
            return None

        @staticmethod
        async def get_or_create_chat(*_args, **kwargs):
            # Upstream reads chat.meta to resolve the session project dir.
            return SimpleNamespace(
                id="matrix-chat",
                name=kwargs["name"],
                meta={},
            )

    class TaskTracker:
        @staticmethod
        async def attach(chat_id, *, requester_id=None):
            captured["attach_calls"].append(chat_id)
            captured["attach_requester"] = requester_id
            return object()

        @staticmethod
        async def stream_from_queue(_queue, _chat_id):
            yield 'data: {"type":"response","status":"completed"}\n\n'

        @staticmethod
        async def attach_or_start(
            chat_id,
            payload,
            producer,
            *,
            owner_id="",
            requester_id=None,
            # Upstream added an object-identity owner alongside owner_id.
            owner=None,
        ):
            captured["start_calls"].append(
                (chat_id, payload, producer, owner_id, requester_id),
            )
            return object(), True

    workspace = SimpleNamespace(
        channel_manager=ChannelManager(),
        chat_manager=ChatManager(),
        task_tracker=TaskTracker(),
        # Upstream resolves an effective project dir on the chat path.
        agent_id="default",
        workspace_dir=Path(tempfile.gettempdir()),
    )

    async def get_workspace(_request):
        return workspace

    original_extract = console_router_mod._extract_session_and_payload

    def capture_extract(*args, **kwargs):
        payload = original_extract(*args, **kwargs)
        captured["extracts"].append(payload)
        return payload

    class PrincipalCaptureMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            principal = getattr(request.state, "request_principal", None)
            captured["requests"].append(
                (
                    request.url.path,
                    principal.to_context() if principal is not None else None,
                ),
            )
            return await call_next(request)

    monkeypatch.setattr(auth_mod, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "_get_config_cached",
        lambda: (config, []),
    )
    monkeypatch.setattr(
        console_router_mod,
        "get_agent_for_request",
        get_workspace,
    )
    monkeypatch.setattr(
        console_router_mod,
        "_extract_session_and_payload",
        capture_extract,
    )
    auth_mod.register_external_identity_resolver(resolver)
    app = FastAPI()
    app.include_router(console_router_mod.router, prefix="/api")
    app.add_middleware(PrincipalCaptureMiddleware)
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=lambda: config.security.mutation_guard,
    )
    app.add_middleware(auth_mod.AuthMiddleware)

    with TestClient(app) as client:
        try:
            yield client, captured
        finally:
            assert client.portal is not None
            client.portal.call(
                _restore_console_background_tasks,
                original_bg_tasks,
            )


def test_console_task_lifecycle_keeps_same_server_member_principal(
    nocobase_console_client,
) -> None:
    client, captured = nocobase_console_client
    body = {
        "channel": "console",
        "user_id": "forged-root",
        "session_id": "matrix-task",
        "input": [],
        "request_context": {
            "request_principal": {
                "roles": ["root"],
                "can_mutate": True,
            },
        },
    }

    submitted = client.post(
        "/api/console/chat/task",
        headers={"Authorization": "Bearer member-token"},
        json=body,
    )
    assert submitted.status_code == 200
    task_id = submitted.json()["task_id"]
    assert task_id in console_router_mod._bg_tasks

    deadline = time.monotonic() + 2.0
    status = None
    while time.monotonic() < deadline:
        status = client.get(
            f"/api/console/chat/task/{task_id}",
            headers={"Authorization": "Bearer member-token"},
        )
        if (
            status.json().get("status") == "finished"
            and captured["stream_event"].is_set()
        ):
            break
        time.sleep(0.01)
    assert status is not None
    anonymous = client.get(f"/api/console/chat/task/{task_id}")

    assert status.status_code == 200
    assert status.json()["status"] == "finished"
    assert captured["stream_event"].is_set()
    assert anonymous.status_code == 401
    payload = captured["extracts"][-1]
    assert payload["acl_sender_id"] == "member@example.com"
    assert payload["meta"]["acl_principal"] == _MEMBER.to_context()
    assert captured["streams"][-1]["meta"]["acl_principal"] == (
        _MEMBER.to_context()
    )
    assert "request_principal" not in payload["meta"].get(
        "request_context",
        {},
    )
    member_requests = [
        principal
        for path, principal in captured["requests"]
        if path
        in {
            "/api/console/chat/task",
            f"/api/console/chat/task/{task_id}",
        }
        and principal is not None
    ]
    assert member_requests == [_MEMBER.to_context(), _MEMBER.to_context()]


def test_console_task_status_is_visible_only_to_owner_or_privileged_roles(
    nocobase_console_client,
) -> None:
    client, _captured = nocobase_console_client
    submitted = client.post(
        "/api/console/chat/task",
        headers={"Authorization": "Bearer member-token"},
        json={
            "channel": "console",
            "user_id": "client-user",
            "session_id": "owned-task",
            "input": [],
        },
    )
    task_id = submitted.json()["task_id"]

    other = client.get(
        f"/api/console/chat/task/{task_id}",
        headers={"Authorization": "Bearer other-member-token"},
    )
    admin = client.get(
        f"/api/console/chat/task/{task_id}",
        headers={"Authorization": "Bearer admin-token"},
    )
    root = client.get(
        f"/api/console/chat/task/{task_id}",
        headers={"Authorization": "Bearer root-token"},
    )

    assert other.status_code == 404
    assert admin.status_code == 200
    assert root.status_code == 200


async def test_console_task_fixture_cleanup_preserves_snapshot_tasks() -> None:
    outer_store = dict(console_router_mod._bg_tasks)
    release_originals = asyncio.Event()

    async def wait_for_release() -> None:
        await release_originals.wait()

    original_task = asyncio.create_task(wait_for_release())
    original_replaced_task = asyncio.create_task(wait_for_release())
    new_task = asyncio.create_task(asyncio.Event().wait())
    replacement_task = asyncio.create_task(asyncio.Event().wait())
    all_tasks = [
        original_task,
        original_replaced_task,
        new_task,
        replacement_task,
    ]
    await asyncio.sleep(0)
    original = {
        "preexisting": console_router_mod._BackgroundTask(
            asyncio_task=original_task,
        ),
        "replaced": console_router_mod._BackgroundTask(
            asyncio_task=original_replaced_task,
        ),
    }
    console_router_mod._bg_tasks.clear()
    console_router_mod._bg_tasks.update(original)
    snapshot = dict(console_router_mod._bg_tasks)
    console_router_mod._bg_tasks["new"] = console_router_mod._BackgroundTask(
        asyncio_task=new_task,
    )
    console_router_mod._bg_tasks[
        "replaced"
    ] = console_router_mod._BackgroundTask(asyncio_task=replacement_task)

    try:
        await _restore_console_background_tasks(snapshot)

        assert not original_task.done()
        assert not original_replaced_task.done()
        assert new_task.cancelled()
        assert replacement_task.cancelled()
        assert console_router_mod._bg_tasks == snapshot
    finally:
        release_originals.set()
        for task in all_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*all_tasks, return_exceptions=True)
        async with console_router_mod._bg_lock:
            console_router_mod._bg_tasks.clear()
            console_router_mod._bg_tasks.update(outer_store)


def test_console_reconnect_propagates_member_and_drops_body_forgery(
    nocobase_console_client,
) -> None:
    client, captured = nocobase_console_client
    body = {
        "channel": "console",
        "user_id": "forged-root",
        "session_id": "matrix-chat",
        "input": [],
        "reconnect": True,
        "request_context": {
            "acl_principal": {
                "roles": ["root"],
                "can_mutate": True,
            },
        },
    }

    response = client.post(
        "/api/console/chat",
        headers={"Authorization": "Bearer member-token"},
        json=body,
    )

    assert response.status_code == 200
    payload = captured["extracts"][-1]
    assert payload["meta"]["acl_principal"] == _MEMBER.to_context()
    assert "acl_principal" not in payload["meta"].get(
        "request_context",
        {},
    )
    assert captured["attach_calls"] == ["matrix-chat"]
    assert captured["start_calls"] == []


@pytest.mark.parametrize(
    ("request_data", "expected_reconnect"),
    [
        (AgentRequest(reconnect=True), True),
        ({"reconnect": True}, True),
        (AgentRequest(reconnect=False), False),
        ({"reconnect": False}, False),
        (AgentRequest(), False),
        ({}, False),
        (AgentRequest(reconnect="true"), False),
        ({"reconnect": "true"}, False),
        (AgentRequest(reconnect={"malformed": True}), False),
        ({"reconnect": {"malformed": True}}, False),
    ],
)
def test_reconnect_field_requires_literal_true_for_object_and_dict(
    request_data,
    expected_reconnect,
) -> None:
    actual = (
        console_router_mod._read_request_field(request_data, "reconnect")
        is True
    )

    assert actual is expected_reconnect


@pytest.mark.parametrize(
    "reconnect_value",
    [None, False, "true", {"malformed": True}],
)
def test_console_non_true_reconnect_starts_instead_of_attaching(
    nocobase_console_client,
    reconnect_value,
) -> None:
    client, captured = nocobase_console_client
    body = {
        "channel": "console",
        "session_id": "matrix-chat",
        "input": [],
    }
    if reconnect_value is not None:
        body["reconnect"] = reconnect_value

    response = client.post(
        "/api/console/chat",
        headers={"Authorization": "Bearer member-token"},
        json=body,
    )

    assert response.status_code == 200
    assert captured["attach_calls"] == []
    assert len(captured["start_calls"]) == 1


class _Session:
    def __init__(self, state: dict | None = None) -> None:
        self.state = state

    async def load_session_state(self, **kwargs) -> None:
        kwargs["agent"].data = self.state


def _request(text: str) -> AgentRequest:
    return AgentRequest(
        input=[
            Message(
                role=Role.USER,
                content=[TextContent(text=text)],
            ),
        ],
        session_id="matrix-session",
        user_id="member@example.com",
        channel="console",
    )


def _runtime(classifier, *, session_state: dict | None = None) -> Runtime:
    plugins = WorkspacePlugins()
    plugins.hook_registry.register(SessionLoadHook())
    plugins.hook_registry.register(MutationIntentHook(classifier=classifier))
    workspace = SimpleNamespace(
        agent_id="matrix-agent",
        workspace_dir=None,
        plugins=plugins,
        session=_Session(session_state),
    )
    return Runtime(workspace=workspace, app_services=None)


async def _run(runtime: Runtime, text: str) -> list:
    return [event async for event in runtime.run(_request(text))]


def _patch_runtime_agent(monkeypatch, *, on_execute=None):
    state = {"built": 0, "executed": 0, "inputs": []}
    agent = SimpleNamespace(close=AsyncMock())

    class Builder:
        def __init__(self, *, app_services):
            assert app_services is None

        async def build(self, _ctx):
            state["built"] += 1
            return agent

    class Executor:
        def __init__(self, built_agent, envelope):
            assert built_agent is agent
            assert envelope is not None

        async def run(self, inputs):
            state["executed"] += 1
            state["inputs"].append(inputs)
            if on_execute is not None:
                await on_execute(inputs)
            if False:
                yield None

    monkeypatch.setattr("qwenpaw.runtime.runtime.AgentBuilder", Builder)
    monkeypatch.setattr("qwenpaw.runtime.runtime.AgentExecutor", Executor)
    return state


@pytest.fixture
def runtime_guard_config(monkeypatch):
    config = SimpleNamespace(
        security=SimpleNamespace(
            mutation_guard=MutationGuardConfig(
                deny_message="测试：无权执行变更。",
            ),
        ),
    )
    monkeypatch.setattr(
        "qwenpaw.hooks.security.mutation_intent_hook.load_config",
        lambda: config,
    )
    monkeypatch.setattr(
        "qwenpaw.security.mutation_guard.tool_gate.load_config",
        lambda: config,
    )
    return config


@pytest.mark.parametrize("text", ["如何修改名称？", "给我一个配置示例"])
async def test_member_read_only_chat_reaches_original_agent_flow(
    monkeypatch,
    runtime_guard_config,
    text,
) -> None:
    del runtime_guard_config
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.READ_ONLY,
            reason="explanation only",
        ),
    )
    state = _patch_runtime_agent(monkeypatch)
    set_current_request_principal(_MEMBER)

    events = await _run(_runtime(classifier), text)

    assert state["built"] == state["executed"] == 1
    classifier.assert_awaited_once()
    assert isinstance(events[-1], AgentResponse)
    assert events[-1].status is RunStatus.Completed


async def test_member_mutation_short_circuits_and_preserves_targets(
    monkeypatch,
    runtime_guard_config,
    tmp_path: Path,
) -> None:
    del runtime_guard_config
    targets = [tmp_path / "config.json", tmp_path / "memory.md"]
    for target in targets:
        target.write_text(f"original:{target.name}\n", encoding="utf-8")
    before = {
        target: hashlib.sha256(target.read_bytes()).hexdigest()
        for target in targets
    }
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="persistent rename",
        ),
    )

    async def mutate_targets(_inputs) -> None:
        for target in targets:
            target.write_text("mutated\n", encoding="utf-8")

    state = _patch_runtime_agent(monkeypatch, on_execute=mutate_targets)
    set_current_request_principal(_MEMBER)

    events = await _run(_runtime(classifier), "你叫小明")

    assert state["built"] == state["executed"] == 0
    assert events[-1].output[0].content[0].text == "测试：无权执行变更。"
    assert {
        target: hashlib.sha256(target.read_bytes()).hexdigest()
        for target in targets
    } == before


async def test_member_followup_uses_recent_context_and_is_denied(
    monkeypatch,
    runtime_guard_config,
    tmp_path: Path,
) -> None:
    del runtime_guard_config
    captured = {}
    targets = [tmp_path / "config.json", tmp_path / "memory.md"]
    for target in targets:
        target.write_text(f"original:{target.name}\n", encoding="utf-8")
    before = {
        target: hashlib.sha256(target.read_bytes()).hexdigest()
        for target in targets
    }

    async def classifier(**kwargs):
        captured.update(kwargs)
        return IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="executes prior rename plan",
        )

    session_state = {
        "state": {
            "context": [
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "如何改名称？"}],
                },
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "可以修改 config.json。"},
                    ],
                },
            ],
        },
    }

    async def mutate_targets(_inputs) -> None:
        for target in targets:
            target.write_text("mutated\n", encoding="utf-8")

    state = _patch_runtime_agent(monkeypatch, on_execute=mutate_targets)
    set_current_request_principal(_MEMBER)

    events = await _run(
        _runtime(classifier, session_state=session_state),
        "按刚才方案执行",
    )

    assert state["built"] == state["executed"] == 0
    assert any("config.json" in item for item in captured["recent_context"])
    assert events[-1].output[0].content[0].text == "测试：无权执行变更。"
    assert {
        target: hashlib.sha256(target.read_bytes()).hexdigest()
        for target in targets
    } == before


@pytest.mark.parametrize("role", ["AdMiN", "rOoT"])
async def test_privileged_chat_mutation_reaches_original_agent_flow(
    monkeypatch,
    runtime_guard_config,
    role,
) -> None:
    del runtime_guard_config
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="must not classify privileged users",
        ),
    )
    state = _patch_runtime_agent(monkeypatch)
    set_current_request_principal(
        RequestPrincipal(
            user_id=f"{role}@example.com",
            roles=(role,),
            source="nocobase",
            guarded=True,
            can_mutate=True,
        ),
    )

    await _run(_runtime(classifier), "你叫小明")

    assert state["built"] == state["executed"] == 1
    classifier.assert_not_called()


@pytest.mark.parametrize("classifier_result", ["timeout", "ambiguous"])
async def test_degraded_intent_still_hits_authoritative_tool_wrapper(
    monkeypatch,
    runtime_guard_config,
    nocobase_http_client,
    tmp_path: Path,
    classifier_result,
) -> None:
    del runtime_guard_config
    client, _transactions, _config = nocobase_http_client
    target = tmp_path / f"{classifier_result}.txt"
    observed = {}

    async def classifier(**_kwargs):
        if classifier_result == "timeout":
            raise asyncio.TimeoutError
        return IntentResult(
            intent=IntentKind.AMBIGUOUS,
            reason="insufficient context",
        )

    async def execute(inputs):
        response = await asyncio.to_thread(
            client.post,
            "/api/test/mutation-tool",
            headers={"Authorization": "Bearer member-token"},
            json={
                "target": str(target),
                "value": "should never exist",
            },
        )
        observed["result"] = response.json()
        observed["injected"] = any(
            "不得执行变更" in getattr(block, "text", "")
            for message in inputs
            # Upstream now injects dynamic context as a user-role message
            # named "system" (some providers reject mid-conversation system
            # turns), so match on the name rather than the role.
            if getattr(message, "name", None) == "system"
            for block in getattr(message, "content", [])
        )

    state = _patch_runtime_agent(monkeypatch, on_execute=execute)
    set_current_request_principal(_MEMBER)

    await _run(_runtime(classifier), "按刚才方案处理")

    assert state["executed"] == 1
    assert observed["injected"] is True
    assert "denied" in observed["result"]["states"]
    assert observed["result"]["tool_calls"] == 0
    assert not target.exists()


async def _run_nested_batch(tools: list) -> object:
    toolkit = Toolkit(tools=tools)
    state = AgentState()
    set_current_toolkit(toolkit)
    set_current_agent_state(state)
    try:
        return await run_tool_batch(
            actions=[
                {"tool_name": tool.name, "arguments": {}} for tool in tools
            ],
        )
    finally:
        set_current_agent_state(None)
        set_current_toolkit(None)


async def test_member_batch_reads_but_denies_write_substep(
    runtime_guard_config,
) -> None:
    del runtime_guard_config
    calls = {"read": 0, "write": 0}

    async def read_matrix() -> str:
        calls["read"] += 1
        return "safe"

    async def write_matrix() -> str:
        calls["write"] += 1
        return "unsafe"

    context = _principal_context(_MEMBER)
    tools = [
        GuardedFunctionTool(
            read_matrix,
            request_context=context,
            effect_spec=ToolEffectSpec(default=ActionEffect.READ),
        ),
        GuardedFunctionTool(
            write_matrix,
            request_context=context,
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        ),
    ]

    result = await _run_nested_batch(tools)

    assert calls == {"read": 1, "write": 0}
    assert "mutation_permission_denied" in str(result)


@pytest.mark.parametrize(
    "tool_name",
    ["spawn_subagent", "delegate_external_agent"],
)
async def test_member_cannot_bypass_via_spawn_or_acp_tool(
    runtime_guard_config,
    tool_name,
) -> None:
    del runtime_guard_config
    funcs = {
        func._tool_descriptor.name: func for func in get_builtin_tool_funcs()
    }
    func = funcs[tool_name]
    tool = GuardedFunctionTool(
        func,
        request_context=_principal_context(_MEMBER),
        effect_spec=func._tool_descriptor.effect,
    )

    result = await tool()

    assert result.state is ToolResultState.DENIED
    assert result.metadata["mutation_guard_denied"] is True


@pytest.mark.parametrize(
    "effect",
    [ActionEffect.MUTATE, ActionEffect.UNKNOWN],
)
async def test_member_driver_mutation_and_unknown_capability_never_invoke(
    runtime_guard_config,
    effect,
) -> None:
    del runtime_guard_config
    invoker = AsyncMock(
        return_value=DriverInvocationResult(ok=True, value="unexpected"),
    )
    capability = DriverCapability(
        capability_id="driver://mcp/matrix/tools/write#invoke",
        driver_name="matrix",
        protocol="mcp",
        kind="tool",
        action="invoke",
        name="write",
        effect=effect,
        exposure=CapabilityExposure(as_tool=True, tool_name="matrix_write"),
    )
    tool = DriverCapabilityTool(
        capability,
        invoker,
        request_context=_principal_context(_MEMBER),
    )

    result = await tool()

    assert result.state is ToolResultState.DENIED
    invoker.assert_not_awaited()
