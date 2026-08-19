# -*- coding: utf-8 -*-
"""Unit tests for provider OAuth router registration."""
# pylint: disable=protected-access

from __future__ import annotations

from urllib.parse import parse_qs, unquote, urlparse

from fastapi import FastAPI
from fastapi.testclient import TestClient

from qwenpaw.app.auth import AuthMiddleware
from qwenpaw.app.mutation_authorization import MutationAuthorizationMiddleware
from qwenpaw.app.routers import router as api_router
from qwenpaw.app.routers import mcp_oauth, provider_oauth
from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.providers.oauth.base import OAuthTokenResult
from qwenpaw.security.mutation_guard import RequestPrincipal, RouteCapability


def test_openrouter_oauth_start_is_registered() -> None:
    """POST /api/providers/openrouter/oauth/start must not 405."""
    app = FastAPI()
    app.include_router(api_router, prefix="/api")
    client = TestClient(app)

    response = client.post("/api/providers/openrouter/oauth/start")

    assert response.status_code == 200
    payload = response.json()
    assert payload["flow_type"] == "browser_redirect"
    assert payload["authorize_url"].startswith("https://openrouter.ai/auth")
    assert payload["state"]


def test_openrouter_callback_url_carries_the_exact_state() -> None:
    app = FastAPI()
    app.include_router(api_router, prefix="/api")
    response = TestClient(app).post(
        "/api/providers/openrouter/oauth/start",
    )

    payload = response.json()
    authorize_query = parse_qs(urlparse(payload["authorize_url"]).query)
    callback_url = unquote(authorize_query["callback_url"][0])
    callback_query = parse_qs(urlparse(callback_url).query)

    assert callback_query["state"] == [payload["state"]]


def test_provider_oauth_routes_have_explicit_security_capabilities() -> None:
    assert (
        provider_oauth.start_oauth.__qwenpaw_api_capability__
        is RouteCapability.MUTATE
    )
    assert (
        provider_oauth.oauth_callback.__qwenpaw_api_capability__
        is RouteCapability.PUBLIC
    )
    assert (
        provider_oauth.oauth_status.__qwenpaw_api_capability__
        is RouteCapability.READ
    )


def test_provider_callback_requires_one_time_state_before_persisting(
    monkeypatch,
) -> None:
    updates = []

    class Manager:
        def update_provider(self, provider_id, credential):
            updates.append((provider_id, credential))
            return True

        async def fetch_provider_models(self, _provider_id):
            return None

    class Flow:
        async def exchange(self, **_kwargs):
            return OAuthTokenResult(api_key="secret-key")

        @staticmethod
        def get_credential_dict(result):
            return {"api_key": result.api_key}

    monkeypatch.setattr(
        provider_oauth,
        "_session_store",
        provider_oauth.OAuthSessionStore(),
    )
    monkeypatch.setitem(provider_oauth._OAUTH_FLOWS, "test", Flow())
    app = FastAPI()
    app.state.provider_manager = Manager()
    app.include_router(provider_oauth.router, prefix="/api")
    client = TestClient(app)
    session = provider_oauth._session_store.create(
        provider_id="test",
        state="one-time-state",
        code_verifier="",
        callback_url="http://testserver/api/providers/test/oauth/callback",
    )

    missing = client.get(
        "/api/providers/test/oauth/callback",
        params={"code": "attacker-code"},
    )
    valid = client.get(
        "/api/providers/test/oauth/callback",
        params={"code": "valid-code", "state": session.state},
    )
    replay = client.get(
        "/api/providers/test/oauth/callback",
        params={"code": "replay-code", "state": session.state},
    )

    assert missing.status_code == 400
    assert valid.status_code == 200
    assert replay.status_code == 400
    assert updates == [("test", {"api_key": "secret-key"})]


def test_oauth_callbacks_are_public_but_status_is_not(monkeypatch) -> None:
    monkeypatch.setattr("qwenpaw.app.auth.is_auth_enabled", lambda: True)
    app = FastAPI()
    app.state.provider_manager = object()
    app.include_router(api_router, prefix="/api")
    app.add_middleware(AuthMiddleware)
    client = TestClient(app)

    provider_callback = client.get(
        "/api/providers/openrouter/oauth/callback",
        params={"code": "x", "state": "invalid"},
    )
    mcp_callback = client.get(
        "/api/mcp/oauth/callback",
        params={"code": "x", "state": "invalid"},
    )
    provider_status = client.get(
        "/api/providers/openrouter/oauth/status",
        params={"state": "invalid"},
    )

    assert provider_callback.status_code == 400
    assert mcp_callback.status_code == 400
    assert provider_status.status_code == 401


def test_member_cannot_create_provider_or_mcp_oauth_delegation(
    monkeypatch,
) -> None:
    member = RequestPrincipal(
        user_id="member-user",
        roles=("member",),
        source="nocobase",
        guarded=True,
        can_mutate=False,
    )
    provider_store = provider_oauth.OAuthSessionStore()
    mcp_store = {}
    monkeypatch.setattr(provider_oauth, "_session_store", provider_store)
    monkeypatch.setattr(mcp_oauth, "_state_store", mcp_store)
    app = FastAPI()
    app.include_router(api_router, prefix="/api")
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=MutationGuardConfig,
        principal_loader=lambda _request: member,
    )
    client = TestClient(app)

    provider = client.post("/api/providers/openrouter/oauth/start")
    mcp = client.post(
        "/api/mcp/oauth/start/client-1",
        json={
            "url": "https://mcp.example/api",
            "auth_endpoint": "https://auth.example/authorize",
            "token_endpoint": "https://auth.example/token",
        },
    )

    assert provider.status_code == 403
    assert mcp.status_code == 403
    assert provider_store.get_by_provider("openrouter") is None
    assert not mcp_store
