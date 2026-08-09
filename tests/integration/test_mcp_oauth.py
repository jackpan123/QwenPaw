# -*- coding: utf-8 -*-
"""Integration tests for the MCP OAuth 2.1 router."""
# pylint: disable=protected-access
from __future__ import annotations

from types import SimpleNamespace

import pytest
from helpers import default_http_timeout

from fastapi import FastAPI
from fastapi.testclient import TestClient

from qwenpaw.app.routers import mcp_oauth
from qwenpaw.security.mutation_guard import RouteCapability

_MCP_OAUTH_HTTP_TIMEOUT = default_http_timeout(15.0)


@pytest.mark.integration
@pytest.mark.p2
def test_mcp_oauth_status_returns_404_for_missing_client(app_server) -> None:
    """Test purpose:
    - Verify GET /api/mcp/oauth/status/{client_key} returns 404 when the
      MCP client does not exist for the active agent, so Console doesn't
      silently treat an unknown client as unauthorised.

    Test flow:
    1. GET /api/mcp/oauth/status/<unknown-client>.
    2. Assert 404 status with detail mentioning the missing client.

    API endpoints:
    - GET /api/mcp/oauth/status/{client_key:path}
    """
    unknown_client = "integ_oauth_status_missing_client"
    resp = app_server.api_request(
        "GET",
        f"/api/mcp/oauth/status/{unknown_client}",
        timeout=_MCP_OAUTH_HTTP_TIMEOUT,
    )
    assert resp.status_code == 404, app_server.logs_tail()
    detail = resp.json().get("detail", "")
    assert unknown_client in detail or "not found" in detail.lower()


@pytest.mark.integration
@pytest.mark.p2
def test_mcp_oauth_revoke_returns_404_for_missing_client(app_server) -> None:
    """Test purpose:
    - Verify DELETE /api/mcp/oauth/{client_key} returns 404 when the MCP
      client does not exist (logout / re-auth prep should fail loudly
      rather than appearing to succeed).

    Test flow:
    1. DELETE /api/mcp/oauth/<unknown-client>.
    2. Assert 404 status with detail mentioning the missing client.

    API endpoints:
    - DELETE /api/mcp/oauth/{client_key:path}
    """
    unknown_client = "integ_oauth_revoke_missing_client"
    resp = app_server.api_request(
        "DELETE",
        f"/api/mcp/oauth/{unknown_client}",
        timeout=_MCP_OAUTH_HTTP_TIMEOUT,
    )
    assert resp.status_code == 404, app_server.logs_tail()
    detail = resp.json().get("detail", "")
    assert unknown_client in detail or "not found" in detail.lower()


@pytest.mark.integration
@pytest.mark.p2
def test_mcp_oauth_callback_with_error_param_returns_html_400(
    app_server,
) -> None:
    """Test purpose:
    - Verify GET /api/mcp/oauth/callback returns an HTML error page with
      400 status when the IdP redirected back with ``error=...``. The
      popup uses localStorage + postMessage to notify the opener; the
      body should expose the error description for visibility.

    Test flow:
    1. GET /api/mcp/oauth/callback?error=access_denied&error_description=...
    2. Assert 400 status, HTML content type, and the error description
       is rendered in the body.

    API endpoints:
    - GET /api/mcp/oauth/callback
    """
    resp = app_server.api_request(
        "GET",
        "/api/mcp/oauth/callback",
        params={
            "error": "access_denied",
            "error_description": "Test denied by user",
        },
        timeout=_MCP_OAUTH_HTTP_TIMEOUT,
    )
    assert resp.status_code == 400, app_server.logs_tail()
    content_type = resp.headers.get("content-type", "")
    assert "html" in content_type.lower(), content_type
    assert "Test denied by user" in resp.text


def test_mcp_oauth_routes_have_explicit_security_capabilities() -> None:
    assert (
        mcp_oauth.oauth_start.__qwenpaw_api_capability__
        is RouteCapability.MUTATE
    )
    assert (
        mcp_oauth.oauth_callback.__qwenpaw_api_capability__
        is RouteCapability.PUBLIC
    )
    assert (
        mcp_oauth.oauth_status.__qwenpaw_api_capability__
        is RouteCapability.READ
    )
    assert (
        mcp_oauth.oauth_revoke.__qwenpaw_api_capability__
        is RouteCapability.MUTATE
    )


def test_mcp_callback_state_is_one_time_and_required_before_persisting(
    monkeypatch,
) -> None:
    persisted = []

    async def exchange(_session, code):
        return {"access_token": f"token-for-{code}"}

    async def persist(_request, session, tokens):
        persisted.append((session.client_key, tokens["access_token"]))

    monkeypatch.setattr(mcp_oauth, "_exchange_code_for_tokens", exchange)
    monkeypatch.setattr(mcp_oauth, "_persist_tokens", persist)
    mcp_oauth._state_store.clear()
    session = mcp_oauth.OAuthSession(
        agent_id="agent-1",
        client_key="client-1",
        code_verifier="verifier",
        client_id="client-id",
        auth_endpoint="https://auth.example/authorize",
        token_endpoint="https://auth.example/token",
        redirect_uri="http://testserver/api/mcp/oauth/callback",
        scope="",
    )
    mcp_oauth._state_store["delegated-state"] = session
    app = FastAPI()
    app.state.multi_agent_manager = SimpleNamespace()
    app.include_router(mcp_oauth.router, prefix="/api")
    client = TestClient(app)

    missing = client.get(
        "/api/mcp/oauth/callback",
        params={"code": "attacker-code"},
    )
    valid = client.get(
        "/api/mcp/oauth/callback",
        params={"code": "valid-code", "state": "delegated-state"},
    )
    replay = client.get(
        "/api/mcp/oauth/callback",
        params={"code": "replay-code", "state": "delegated-state"},
    )

    assert missing.status_code == 400
    assert valid.status_code == 200
    assert replay.status_code == 400
    assert persisted == [("client-1", "token-for-valid-code")]
