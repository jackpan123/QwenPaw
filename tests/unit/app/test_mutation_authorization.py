# -*- coding: utf-8 -*-
"""HTTP mutation authorization middleware tests."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from qwenpaw.app import auth as auth_mod
from qwenpaw.app import mutation_authorization as authorization_mod
from qwenpaw.app.mutation_authorization import (
    MutationAuthorizationMiddleware,
    api_capability,
    default_capability_for_method,
)
from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.security.mutation_guard import (
    RequestPrincipal,
    RouteCapability,
    build_request_principal,
)


MEMBER = RequestPrincipal(
    user_id="member@example.com",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)
LEGACY_EXTERNAL = RequestPrincipal(
    user_id="legacy@example.com",
    roles=("member",),
    source="external",
    guarded=False,
    can_mutate=True,
)


def _build_client(
    principal: RequestPrincipal,
    *,
    enabled: bool = True,
    deny_message: str = (
        "Mutation denied.\nRead-only access remains available."
    ),
    on_write: Callable[[], None] | None = None,
) -> TestClient:
    app = FastAPI()

    @app.get("/default-read")
    async def default_read():
        return {"entered": True}

    @app.post("/chat")
    @api_capability(RouteCapability.CHAT)
    async def chat():
        return {"entered": True}

    @app.post("/explicit-read")
    @api_capability(RouteCapability.READ)
    async def explicit_read():
        return {"entered": True}

    @app.api_route(
        "/default-write",
        methods=["POST", "PUT", "PATCH", "DELETE"],
    )
    async def default_write():
        if on_write is not None:
            on_write()
        return {"entered": True}

    @app.api_route("/safe-method", methods=["HEAD", "OPTIONS"])
    async def safe_method():
        return {"entered": True}

    config = MutationGuardConfig(
        enabled=enabled,
        deny_message=deny_message,
    )
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=lambda: config,
        principal_loader=lambda _request: principal,
    )
    return TestClient(app)


@pytest.mark.p0
def test_get_without_declaration_defaults_to_read_for_member():
    response = _build_client(MEMBER).get("/default-read")

    assert response.status_code == 200
    assert response.json() == {"entered": True}


@pytest.mark.p0
def test_explicit_chat_post_is_available_to_member():
    response = _build_client(MEMBER).post("/chat")

    assert response.status_code == 200
    assert response.json() == {"entered": True}


@pytest.mark.p0
def test_explicit_read_post_is_available_to_member():
    response = _build_client(MEMBER).post("/explicit-read")

    assert response.status_code == 200
    assert response.json() == {"entered": True}


@pytest.mark.p0
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_undeclared_write_methods_default_to_mutate_and_deny_member(method):
    entered = False

    def on_write() -> None:
        nonlocal entered
        entered = True

    response = _build_client(MEMBER, on_write=on_write).request(
        method,
        "/default-write",
    )

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Mutation denied.",
        "code": "mutation_permission_denied",
    }
    assert entered is False


@pytest.mark.p0
@pytest.mark.parametrize("role", ["admin", "RoOt"])
def test_privileged_roles_enter_write_handler(role):
    config = MutationGuardConfig()
    principal = build_request_principal(
        user_id=f"{role}@example.com",
        roles=[role],
        source="nocobase",
        auth_enabled=True,
        config=config,
    )

    response = _build_client(principal).post("/default-write")

    assert principal.can_mutate is True
    assert response.status_code == 200
    assert response.json() == {"entered": True}


@pytest.mark.p0
def test_unguarded_legacy_principal_enters_write_handler():
    response = _build_client(LEGACY_EXTERNAL).post("/default-write")

    assert response.status_code == 200
    assert response.json() == {"entered": True}


@pytest.mark.p0
def test_unmatched_write_route_fails_closed_for_member():
    response = _build_client(MEMBER).post("/route-that-does-not-exist")

    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"


@pytest.mark.p0
@pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
def test_safe_methods_default_to_read(method):
    response = _build_client(MEMBER).request(method, "/safe-method")

    assert response.status_code == 200


@pytest.mark.p0
def test_disabled_mutation_guard_allows_member_write():
    response = _build_client(MEMBER, enabled=False).post("/default-write")

    assert response.status_code == 200
    assert response.json() == {"entered": True}


@pytest.mark.p0
def test_default_chinese_deny_message_returns_only_first_sentence():
    config = MutationGuardConfig()

    response = _build_client(
        MEMBER,
        deny_message=config.deny_message,
    ).post("/default-write")

    assert response.status_code == 403
    assert response.json() == {
        "detail": "当前账号没有执行变更操作的权限",
        "code": "mutation_permission_denied",
    }


@pytest.mark.p0
def test_denied_write_emits_safe_route_audit(monkeypatch):
    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        authorization_mod,
        "emit_mutation_audit",
        lambda event, **fields: events.append((event, fields)),
    )

    response = _build_client(MEMBER).post(
        "/default-write",
        json={"token": "must-not-be-audited"},
        headers={"Authorization": "Bearer must-not-be-audited"},
    )

    assert response.status_code == 403
    assert events == [
        (
            "api_mutation_denied",
            {
                "user_id": "member@example.com",
                "roles": ("member",),
                "source": "nocobase",
                "route": "POST /default-write",
                "decision": "deny",
                "reason": "mutation_permission_denied",
            },
        ),
    ]


@pytest.mark.p0
def test_auth_middleware_runs_before_mutation_authorization(monkeypatch):
    class FakeSecurity:
        allow_no_auth_hosts: list[str] = []
        mutation_guard = MutationGuardConfig()

    class FakeConfig:
        security = FakeSecurity()

    monkeypatch.setattr(auth_mod, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "_get_config_cached",
        lambda: (FakeConfig(), []),
    )

    async def resolver(_request):
        return auth_mod.ResolvedIdentity(
            sender_id="member@example.com",
            roles=["member"],
            source="nocobase",
        )

    auth_mod.register_external_identity_resolver(resolver)
    try:
        app = FastAPI()

        @app.post("/api/write")
        async def write():
            return {"entered": True}

        app.add_middleware(
            MutationAuthorizationMiddleware,
            config_loader=MutationGuardConfig,
        )
        app.add_middleware(auth_mod.AuthMiddleware)
        response = TestClient(app).post("/api/write")
    finally:
        auth_mod.unregister_external_identity_resolver(resolver)

    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"


def test_default_capability_is_fail_closed_by_method():
    assert default_capability_for_method("GET") is RouteCapability.READ
    assert default_capability_for_method("head") is RouteCapability.READ
    assert default_capability_for_method("OPTIONS") is RouteCapability.READ
    assert default_capability_for_method("POST") is RouteCapability.MUTATE
    assert default_capability_for_method("CUSTOM") is RouteCapability.MUTATE


def test_api_capability_normalizes_valid_strings_and_rejects_invalid_values():
    @api_capability("chat")
    async def chat_endpoint():
        return None

    assert (
        chat_endpoint.__qwenpaw_api_capability__  # type: ignore[attr-defined]
        is RouteCapability.CHAT
    )

    with pytest.raises(ValueError, match="unknown API capability"):
        api_capability("unknown")
    with pytest.raises(TypeError, match="RouteCapability or str"):
        api_capability(object())  # type: ignore[arg-type]
