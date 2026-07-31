# -*- coding: utf-8 -*-
"""AuthMiddleware + inter-agent header behavior for the internal credential."""

from __future__ import annotations

from unittest.mock import patch

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
