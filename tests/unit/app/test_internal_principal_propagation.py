# -*- coding: utf-8 -*-
"""AuthMiddleware + inter-agent header behavior for the internal credential."""

# pylint: disable=protected-access

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request as _Req
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from qwenpaw.app import auth as auth_mod
from qwenpaw.app import internal_auth
from qwenpaw.agents.tools import agent_management
from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.security.mutation_guard import RequestPrincipal

MEMBER_PRINCIPAL = RequestPrincipal(
    user_id="alice",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)


def _default_config() -> MutationGuardConfig:
    return MutationGuardConfig()


def _make_request(path: str = "/api/console/chat", headers=None) -> _Req:
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [
            (k.lower().encode(), v.encode())
            for k, v in (headers or {}).items()
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8088),
        "scheme": "http",
        "app": Starlette(),
    }
    return _Req(scope)


# ── AuthMiddleware internal-credential handling ──────────────────────


async def _capture_principal(request, call_next):
    """Middleware app accessor: stash request.state for assertions."""
    return await call_next(request)


@pytest.fixture(autouse=True)
def _auth_enabled():
    with patch.object(auth_mod, "is_auth_enabled", return_value=True):
        yield


@pytest.fixture(autouse=True)
def _clear_resolvers():
    auth_mod._external_identity_resolvers.clear()
    yield
    auth_mod._external_identity_resolvers.clear()


def _build_app():
    async def handler(request):
        # Echo what AuthMiddleware left on request.state.
        principal = getattr(
            request.state,
            "request_principal",
            None,
        )
        return JSONResponse(
            {
                "user": getattr(request.state, "user", None),
                "roles": getattr(request.state, "user_roles", None),
                "source": getattr(request.state, "auth_source", None),
                "principal": (principal.to_context() if principal else None),
            },
        )

    app = Starlette(routes=[Route("/api/console/chat", handler)])
    app.add_middleware(auth_mod.AuthMiddleware)
    return app


def test_valid_internal_credential_authenticates_without_resolver():
    """A valid internal credential authenticates the request and the
    resolver is never consulted (the NocoBase token is not forwarded)."""
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child-agent",
    )
    # Register a resolver that would FAIL the test if called.
    calls = {"count": 0}

    async def _resolver(_request):
        calls["count"] += 1
        return None

    auth_mod.register_external_identity_resolver(_resolver)

    with patch.object(internal_auth, "_load_mutation_config", _default_config):
        client = TestClient(_build_app())
        resp = client.get(
            "/api/console/chat",
            headers={
                internal_auth.INTERNAL_PRINCIPAL_HEADER: credential,
                "X-Agent-Id": "child-agent",
            },
        )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"] == "alice"
    assert body["roles"] == ["member"]
    assert body["source"] == "nocobase"
    principal = body["principal"]
    assert principal["user_id"] == "alice"
    # Recomputed from config: member is read-only.
    assert principal["can_mutate"] is False
    assert calls["count"] == 0


def test_invalid_internal_credential_returns_401():
    """An invalid credential must 401, never degrade to anonymous/allowlist."""
    with patch.object(internal_auth, "_load_mutation_config", _default_config):
        client = TestClient(_build_app())
        resp = client.get(
            "/api/console/chat",
            headers={
                internal_auth.INTERNAL_PRINCIPAL_HEADER: "garbage",
                "X-Agent-Id": "child-agent",
            },
        )
    assert resp.status_code == 401, resp.text


def test_expired_internal_credential_returns_401():
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child-agent",
    )
    with patch.object(internal_auth, "_load_mutation_config", _default_config):
        with patch(
            "time.time",
            return_value=10_000_000.0,
        ):
            client = TestClient(_build_app())
            resp = client.get(
                "/api/console/chat",
                headers={
                    internal_auth.INTERNAL_PRINCIPAL_HEADER: credential,
                    "X-Agent-Id": "child-agent",
                },
            )
    assert resp.status_code == 401, resp.text


def test_wrong_target_internal_credential_returns_401():
    """Target binding: credential minted for child-A fails on child-B."""
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child-agent",
    )
    with patch.object(internal_auth, "_load_mutation_config", _default_config):
        client = TestClient(_build_app())
        resp = client.get(
            "/api/console/chat",
            headers={
                internal_auth.INTERNAL_PRINCIPAL_HEADER: credential,
                "X-Agent-Id": "other-agent",
            },
        )
    assert resp.status_code == 401, resp.text


# ── _request_headers local-only credential attachment ────────────────


@pytest.fixture(autouse=True)
def _reset_principal_cv():
    from qwenpaw.app.agent_context import (
        set_current_request_principal,
    )

    set_current_request_principal(MEMBER_PRINCIPAL)
    yield
    set_current_request_principal(None)


def test_request_headers_attaches_credential_for_loopback():
    headers = agent_management._request_headers(
        "child-agent",
        base_url="http://127.0.0.1:8088",
    )
    assert headers["X-Agent-Id"] == "child-agent"
    assert internal_auth.INTERNAL_PRINCIPAL_HEADER in headers
    credential = headers[internal_auth.INTERNAL_PRINCIPAL_HEADER]
    verified = internal_auth.verify_internal_principal(
        credential,
        target_agent_id="child-agent",
    )
    assert verified is not None
    assert verified.user_id == "alice"


def test_request_headers_attaches_credential_for_localhost():
    headers = agent_management._request_headers(
        "child-agent",
        base_url="http://localhost:8088",
    )
    assert internal_auth.INTERNAL_PRINCIPAL_HEADER in headers


@pytest.mark.parametrize(
    "url",
    [
        "http://[::]:8088",
        "https://[::1]:8443/api",
        "http://127.0.0.2:8088",
    ],
)
def test_request_headers_attaches_credential_for_local_ip_targets(url):
    headers = agent_management._request_headers("child-agent", base_url=url)
    assert internal_auth.INTERNAL_PRINCIPAL_HEADER in headers


@pytest.mark.parametrize(
    "url",
    [
        "file://localhost/tmp/qwenpaw",
        "ftp://127.0.0.1:8088/api",
        "http:///api",
        "not-a-url",
        "http://[::1",
        "http://localhost:invalid/api",
        "http://user@localhost:8088/api",
    ],
)
def test_request_headers_rejects_malformed_or_non_http_targets(url):
    headers = agent_management._request_headers("child-agent", base_url=url)
    assert internal_auth.INTERNAL_PRINCIPAL_HEADER not in headers


def test_request_headers_omits_credential_for_remote_url():
    """A remote target must NEVER receive the internal credential."""
    headers = agent_management._request_headers(
        "child-agent",
        base_url="http://10.0.0.5:8088",
    )
    assert headers["X-Agent-Id"] == "child-agent"
    assert internal_auth.INTERNAL_PRINCIPAL_HEADER not in headers


def test_request_headers_omits_credential_without_principal():
    """No current principal -> no credential header (never mint anonymous)."""
    from qwenpaw.app.agent_context import set_current_request_principal

    set_current_request_principal(None)
    headers = agent_management._request_headers(
        "child-agent",
        base_url="http://127.0.0.1:8088",
    )
    assert internal_auth.INTERNAL_PRINCIPAL_HEADER not in headers
    assert headers["X-Agent-Id"] == "child-agent"


def _recording_client(monkeypatch, handler):
    transport = httpx.MockTransport(handler)

    def factory(base_url, default_timeout=30.0):
        del default_timeout
        return httpx.Client(
            base_url=agent_management._normalize_api_base_url(base_url),
            transport=transport,
        )

    monkeypatch.setattr(
        agent_management,
        "create_agent_api_client",
        factory,
    )


def _assert_signed_for(request, target_agent):
    assert request.headers["X-Agent-Id"] == target_agent
    credential = request.headers[internal_auth.INTERNAL_PRINCIPAL_HEADER]
    verified = internal_auth.verify_internal_principal(
        credential,
        target_agent_id=target_agent,
    )
    assert verified is not None
    assert verified.user_id == "alice"


def test_stream_agent_chat_sends_target_bound_principal(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            text='data: {"output": []}\n\n',
            headers={"content-type": "text/event-stream"},
        )

    _recording_client(monkeypatch, handler)
    agent_management.stream_agent_chat(
        None,
        {"session_id": "sid", "input": []},
        "stream-child",
        30,
    )
    _assert_signed_for(seen[0], "stream-child")


def test_collect_agent_chat_sends_target_bound_principal(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            text='data: {"output": []}\n\n',
            headers={"content-type": "text/event-stream"},
        )

    _recording_client(monkeypatch, handler)
    agent_management.collect_final_agent_chat_response(
        None,
        {"session_id": "sid", "input": []},
        "collect-child",
        30,
    )
    _assert_signed_for(seen[0], "collect-child")


def test_submit_and_status_send_target_bound_principal(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"task_id": "task-signed"})
        return httpx.Response(200, json={"status": "running"})

    _recording_client(monkeypatch, handler)
    result = agent_management.submit_agent_chat_task(
        None,
        {"session_id": "sid", "input": []},
        "task-child",
        30,
    )
    agent_management.get_agent_chat_task_status(
        None,
        result["task_id"],
        to_agent="task-child",
    )
    assert len(seen) == 2
    _assert_signed_for(seen[0], "task-child")
    _assert_signed_for(seen[1], "task-child")
    assert agent_management._background_task_agent("task-signed") == (
        "task-child"
    )


def test_terminal_status_cleans_task_target_after_signed_request(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"status": "finished"})

    _recording_client(monkeypatch, handler)
    assert agent_management._remember_background_task_agent(
        "task-finished",
        "terminal-child",
    )

    result = agent_management.get_agent_chat_task_status(
        None,
        "task-finished",
    )

    assert result == {"status": "finished"}
    _assert_signed_for(seen[0], "terminal-child")
    assert agent_management._background_task_agent("task-finished") is None


def test_status_error_preserves_task_target_for_retry(monkeypatch):
    def handler(request):
        return httpx.Response(503, request=request)

    _recording_client(monkeypatch, handler)
    assert agent_management._remember_background_task_agent(
        "task-retry",
        "retry-child",
    )

    with pytest.raises(httpx.HTTPStatusError):
        agent_management.get_agent_chat_task_status(None, "task-retry")

    assert agent_management._background_task_agent("task-retry") == (
        "retry-child"
    )


def test_submit_fails_closed_on_cross_agent_task_id_collision(monkeypatch):
    def handler(_request):
        return httpx.Response(200, json={"task_id": "task-collision"})

    _recording_client(monkeypatch, handler)
    assert agent_management._remember_background_task_agent(
        "task-collision",
        "agent-a",
    )

    with pytest.raises(RuntimeError, match="target binding collision"):
        agent_management.submit_agent_chat_task(
            None,
            {"session_id": "sid", "input": []},
            "agent-b",
            30,
        )

    assert agent_management._background_task_agent("task-collision") == (
        "agent-a"
    )
