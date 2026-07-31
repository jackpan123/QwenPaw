# -*- coding: utf-8 -*-
# pylint: disable=protected-access,unused-argument
"""Login/verify/status routes in the NocoBase-only auth world."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qwenpaw.app import auth as auth_mod
from qwenpaw.app.auth import (
    ExternalLogin,
    ExternalLoginDenied,
    ResolvedIdentity,
    register_external_identity_resolver,
    register_external_login_authenticator,
)
from qwenpaw.app.routers import auth as auth_router_mod
from qwenpaw.config.config import MutationGuardConfig


@pytest.fixture(autouse=True)
def _clear_authenticators():
    auth_mod._external_login_authenticators.clear()
    auth_mod._external_identity_resolvers.clear()
    yield
    auth_mod._external_login_authenticators.clear()
    auth_mod._external_identity_resolvers.clear()


class _FakeRateLimiter:
    def __init__(self) -> None:
        self.attempts: list[tuple[str, str, bool]] = []

    def is_user_locked(self, _username: str) -> bool:
        return False

    def is_ip_locked(self, _ip: str) -> bool:
        return False

    def is_ip_rate_limited(self, _ip: str) -> bool:
        return False

    def record_login_attempt(self, ip, username, success) -> None:
        self.attempts.append((ip, username, success))


class _FakeSecurity:
    def __init__(
        self,
        allow_no_auth_hosts: list[str] | None = None,
    ) -> None:
        self.allow_no_auth_hosts = allow_no_auth_hosts or []
        self.mutation_guard = MutationGuardConfig()


class _FakeConfig:
    def __init__(
        self,
        allow_no_auth_hosts: list[str] | None = None,
    ) -> None:
        self.security = _FakeSecurity(allow_no_auth_hosts)


def _build_client(
    monkeypatch,
    *,
    with_auth_middleware: bool = False,
    allow_no_auth_hosts: list[str] | None = None,
):
    limiter = _FakeRateLimiter()
    monkeypatch.setattr(auth_router_mod, "rate_limiter", limiter)
    monkeypatch.setattr(auth_router_mod, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(auth_mod, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "_get_config_cached",
        lambda: (_FakeConfig(allow_no_auth_hosts), []),
    )
    app = FastAPI()
    app.include_router(auth_router_mod.router, prefix="/api")
    if with_auth_middleware:
        app.add_middleware(auth_mod.AuthMiddleware)
    return TestClient(app), limiter


@pytest.mark.p0
def test_login_returns_403_when_external_acl_denies(monkeypatch):
    async def denies(_username, _password):
        raise ExternalLoginDenied("account blocked by console ACL")

    register_external_login_authenticator(denies)
    client, limiter = _build_client(monkeypatch)
    resp = client.post(
        "/api/auth/login",
        json={"username": "blocked@example.com", "password": "correct-pw"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "account blocked by console ACL"
    assert limiter.attempts == [
        ("testclient", "blocked@example.com", False),
    ]


@pytest.mark.p0
def test_login_returns_401_when_no_authenticator_accepts(monkeypatch):
    async def rejects(_username, _password):
        return None

    register_external_login_authenticator(rejects)
    client, _limiter = _build_client(monkeypatch)
    resp = client.post(
        "/api/auth/login",
        json={"username": "nobody@example.com", "password": "wrong"},
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid username or password"


@pytest.mark.p0
def test_login_returns_provider_token(monkeypatch):
    async def nb_login(_username, _password):
        return ExternalLogin(
            identity="admin@nocobase.com",
            token="nb-jwt-token",
        )

    register_external_login_authenticator(nb_login)
    client, _limiter = _build_client(monkeypatch)
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin@nocobase.com", "password": "pw"},
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "token": "nb-jwt-token",
        "username": "admin@nocobase.com",
    }


@pytest.mark.p0
def test_login_401_when_provider_returns_no_token(monkeypatch):
    async def legacy_login(_username, _password):
        return "someone@example.com"  # identity only, no token

    register_external_login_authenticator(legacy_login)
    client, _limiter = _build_client(monkeypatch)
    resp = client.post(
        "/api/auth/login",
        json={"username": "someone@example.com", "password": "pw"},
    )
    assert resp.status_code == 401


@pytest.mark.p0
def test_register_route_removed(monkeypatch):
    client, _limiter = _build_client(monkeypatch)
    resp = client.post(
        "/api/auth/register",
        json={"username": "new@example.com", "password": "pw"},
    )
    assert resp.status_code == 404


@pytest.mark.p0
def test_status_reports_nocobase_mode(monkeypatch):
    client, _limiter = _build_client(monkeypatch)
    resp = client.get("/api/auth/status")
    assert resp.status_code == 200
    assert resp.json() == {"enabled": True, "mode": "nocobase"}


@pytest.mark.p0
def test_verify_exposes_root_mutation_capability(monkeypatch):
    async def resolver(request):
        if request.headers.get("Authorization") == "Bearer nb-token":
            return ResolvedIdentity(
                sender_id="root-user",
                roles=["Root"],
                source="nocobase",
            )
        return None

    register_external_identity_resolver(resolver)
    client, _limiter = _build_client(monkeypatch)

    resp = client.get(
        "/api/auth/verify",
        headers={"Authorization": "Bearer nb-token"},
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "valid": True,
        "username": "root-user",
        "roles": ["Root"],
        "can_mutate": True,
    }

    resp = client.get(
        "/api/auth/verify",
        headers={"Authorization": "Bearer other"},
    )
    assert resp.status_code == 401


@pytest.mark.p0
def test_verify_uses_live_member_roles_and_ignores_client_claims(monkeypatch):
    async def resolver(request):
        if request.headers.get("Authorization") == "Bearer member-token":
            return ResolvedIdentity(
                sender_id="member-user",
                roles=["member"],
                source="nocobase",
            )
        return None

    register_external_identity_resolver(resolver)
    client, _limiter = _build_client(monkeypatch)
    resp = client.get(
        "/api/auth/verify",
        headers={
            "Authorization": "Bearer member-token",
            "X-User-Roles": "Root",
            "X-Can-Mutate": "true",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "valid": True,
        "username": "member-user",
        "roles": ["member"],
        "can_mutate": False,
    }


@pytest.mark.p0
def test_verify_reuses_middleware_principal_without_identity_drift(
    monkeypatch,
):
    calls = 0

    async def drifting_resolver(_request):
        nonlocal calls
        calls += 1
        if calls == 1:
            return ResolvedIdentity(
                sender_id="member-user",
                roles=["member"],
                source="nocobase",
            )
        return ResolvedIdentity(
            sender_id="root-user",
            roles=["Root"],
            source="nocobase",
        )

    register_external_identity_resolver(drifting_resolver)
    client, _limiter = _build_client(
        monkeypatch,
        with_auth_middleware=True,
    )
    resp = client.get(
        "/api/auth/verify",
        headers={"Authorization": "Bearer nb-token"},
    )

    assert calls == 1
    assert resp.status_code == 200
    assert resp.json() == {
        "valid": True,
        "username": "member-user",
        "roles": ["member"],
        "can_mutate": False,
    }


@pytest.mark.p0
def test_verify_resolves_once_when_allowlist_skips_middleware(monkeypatch):
    calls = 0

    async def resolver(_request):
        nonlocal calls
        calls += 1
        return ResolvedIdentity(
            sender_id="root-user",
            roles=["Root"],
            source="nocobase",
        )

    register_external_identity_resolver(resolver)
    client, _limiter = _build_client(
        monkeypatch,
        with_auth_middleware=True,
        allow_no_auth_hosts=["testclient"],
    )
    resp = client.get("/api/auth/verify")

    assert calls == 1
    assert resp.status_code == 200
    assert resp.json() == {
        "valid": True,
        "username": "root-user",
        "roles": ["Root"],
        "can_mutate": True,
    }


@pytest.mark.p0
def test_verify_when_auth_disabled_allows_mutation(monkeypatch):
    client, _limiter = _build_client(monkeypatch)
    monkeypatch.setattr(auth_router_mod, "is_auth_enabled", lambda: False)
    resp = client.get("/api/auth/verify")
    assert resp.status_code == 200
    assert resp.json() == {
        "valid": True,
        "username": "",
        "roles": [],
        "can_mutate": True,
    }
