# -*- coding: utf-8 -*-
"""HTTP mutation authorization middleware tests."""

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import patch

import pytest
from fastapi import APIRouter, FastAPI, Request
from fastapi.testclient import TestClient

from qwenpaw.app import auth as auth_mod
from qwenpaw.app import mutation_authorization as authorization_mod
from qwenpaw.app.mutation_authorization import (
    MutationAuthorizationMiddleware,
    api_capability,
    default_capability_for_method,
    guarded_mutation_denial,
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
_MISSING = object()


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


def _build_included_router_client() -> TestClient:
    app = FastAPI()
    router = APIRouter()

    @router.post("/chat")
    @api_capability(RouteCapability.CHAT)
    async def chat():
        return {"entered": True}

    @router.post("/explicit-read")
    @api_capability(RouteCapability.READ)
    async def explicit_read():
        return {"entered": True}

    @router.post("/default-write")
    async def default_write():
        return {"entered": True}

    @router.get("/read-only")
    @api_capability(RouteCapability.READ)
    async def read_only():
        return {"entered": True}

    @router.post("/invalid-declaration")
    async def invalid_declaration():
        return {"entered": True}

    setattr(
        invalid_declaration,
        "__qwenpaw_api_capability__",
        "read",
    )

    app.include_router(router, prefix="/included")
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=MutationGuardConfig,
        principal_loader=lambda _request: MEMBER,
    )
    return TestClient(app)


def _build_default_loader_client(
    state_value: object = _MISSING,
) -> TestClient:
    app = FastAPI()

    @app.post("/default-write")
    async def default_write():
        return {"entered": True}

    router = APIRouter(prefix="/api/mcp")

    @router.post("/oauth/{client_key:path}")
    async def oauth(client_key: str):
        return {"entered": True, "client_key": client_key}

    app.include_router(router)
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=MutationGuardConfig,
    )
    if state_value is not _MISSING:

        @app.middleware("http")
        async def inject_principal(request: Request, call_next):
            request.state.request_principal = state_value
            return await call_next(request)

    return TestClient(app)


def test_dynamic_mutation_denial_respects_disabled_guard(monkeypatch):
    app = FastAPI()

    @app.get("/probe")
    async def probe(request: Request):
        request.state.request_principal = MEMBER
        denial = guarded_mutation_denial(
            request,
            route="POST /mixed",
            reason="test",
        )
        return {"denied": denial is not None}

    monkeypatch.setattr(
        authorization_mod,
        "_load_config",
        lambda: MutationGuardConfig(enabled=False),
    )

    response = TestClient(app).get("/probe")

    assert response.json() == {"denied": False}


def _build_dynamic_cron_client(monkeypatch):
    from qwenpaw.api_action import ManagerRegistry
    from qwenpaw.app._api_action_routes import register_http_routes
    from qwenpaw.app.crons.manager import CronManager

    calls: list[tuple[str, str | None]] = []

    class FakeCronManager:
        async def list_jobs(self):
            calls.append(("list", None))
            return []

        async def create_or_replace_job(self, spec):
            calls.append(("create", spec.name))

        async def delete_job(self, job_id):
            calls.append(("delete", job_id))
            return True

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

    async def resolver(request):
        token = request.headers.get("Authorization", "").removeprefix(
            "Bearer ",
        )
        if token not in {"member", "admin", "root"}:
            return None
        return auth_mod.ResolvedIdentity(
            sender_id=f"{token}@example.com",
            roles=[token],
            source="nocobase",
        )

    auth_mod.register_external_identity_resolver(resolver)
    app = FastAPI()
    registry = ManagerRegistry()
    manager = FakeCronManager()
    registry.register(CronManager, lambda _app: manager)
    register_http_routes(app, registry)
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=MutationGuardConfig,
    )
    app.add_middleware(auth_mod.AuthMiddleware)
    return TestClient(app), calls, resolver


_CRON_JOB_BODY = {
    "name": "daily-summary",
    "schedule": {"type": "cron", "cron": "0 9 * * *"},
    "task_type": "text",
    "text": "summary",
    "dispatch": {
        "channel": "console",
        "target": {"user_id": "user", "session_id": "session"},
    },
}


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
@pytest.mark.parametrize(
    ("path", "expected_status"),
    [
        ("/included/chat", 200),
        ("/included/explicit-read", 200),
        ("/included/default-write", 403),
    ],
)
def test_included_router_resolves_effective_endpoint_capability(
    path,
    expected_status,
):
    response = _build_included_router_client().post(path)

    assert response.status_code == expected_status
    if expected_status == 200:
        assert response.json() == {"entered": True}
    else:
        assert response.json()["code"] == "mutation_permission_denied"


@pytest.mark.p0
@pytest.mark.parametrize(
    "path",
    ["/included/read-only", "/included/invalid-declaration"],
)
def test_partial_or_invalid_included_route_defaults_post_to_mutate(path):
    response = _build_included_router_client().post(path)

    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"


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
@pytest.mark.parametrize(
    "state_value",
    [
        _MISSING,
        {"guarded": False, "can_mutate": True},
        "invalid",
    ],
)
def test_missing_or_invalid_state_principal_denies_write(state_value):
    response = _build_default_loader_client(state_value).post(
        "/default-write",
    )

    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"


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
def test_denied_dynamic_route_audits_template_without_secret(monkeypatch):
    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        authorization_mod,
        "emit_mutation_audit",
        lambda event, **fields: events.append((event, fields)),
    )
    secret = "client-secret/actual-id"

    response = _build_default_loader_client(MEMBER).post(
        f"/api/mcp/oauth/{secret}",
    )

    assert response.status_code == 403
    assert len(events) == 1
    assert events[0][1]["route"] == "POST /api/mcp/oauth/{client_key:path}"
    assert secret not in str(events)


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


@pytest.mark.p0
def test_dynamic_cron_routes_require_authentication(monkeypatch):
    client, calls, resolver = _build_dynamic_cron_client(monkeypatch)
    try:
        assert client.get("/crons/jobs").status_code == 401
        assert (
            client.post("/crons/jobs", json=_CRON_JOB_BODY).status_code == 401
        )
    finally:
        auth_mod.unregister_external_identity_resolver(resolver)

    assert not calls


@pytest.mark.p0
@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/crons/jobs", _CRON_JOB_BODY),
        ("PUT", "/crons/jobs", _CRON_JOB_BODY),
        ("DELETE", "/crons/jobs/job-1", None),
        ("POST", "/crons/jobs/job-1/pause", None),
    ],
)
def test_member_cannot_mutate_dynamic_cron_routes(
    monkeypatch,
    method,
    path,
    body,
):
    client, calls, resolver = _build_dynamic_cron_client(monkeypatch)
    try:
        response = client.request(
            method,
            path,
            json=body,
            headers={"Authorization": "Bearer member"},
        )
    finally:
        auth_mod.unregister_external_identity_resolver(resolver)

    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"
    assert not calls


@pytest.mark.p0
def test_member_can_read_authenticated_dynamic_cron_route(monkeypatch):
    client, calls, resolver = _build_dynamic_cron_client(monkeypatch)
    try:
        response = client.get(
            "/crons/jobs",
            headers={"Authorization": "Bearer member"},
        )
    finally:
        auth_mod.unregister_external_identity_resolver(resolver)

    assert response.status_code == 200
    assert response.json() == []
    assert calls == [("list", None)]


@pytest.mark.p0
@pytest.mark.parametrize("role", ["admin", "root"])
def test_privileged_roles_can_use_dynamic_cron_routes(monkeypatch, role):
    client, calls, resolver = _build_dynamic_cron_client(monkeypatch)
    headers = {"Authorization": f"Bearer {role}"}
    try:
        listed = client.get("/crons/jobs", headers=headers)
        created = client.post(
            "/crons/jobs",
            json=_CRON_JOB_BODY,
            headers=headers,
        )
        deleted = client.delete("/crons/jobs/job-1", headers=headers)
    finally:
        auth_mod.unregister_external_identity_resolver(resolver)

    assert listed.status_code == 200
    assert created.status_code == 200
    assert deleted.status_code == 200
    assert calls == [
        ("list", None),
        ("create", "daily-summary"),
        ("delete", "job-1"),
    ]


@pytest.mark.p0
def test_auth_disabled_sets_unguarded_principal_before_mutation_guard(
    monkeypatch,
):
    monkeypatch.setattr(auth_mod, "is_auth_enabled", lambda: False)
    app = FastAPI()

    @app.post("/api/write")
    async def write(request: Request):
        principal = request.state.request_principal
        return {
            "principal": isinstance(principal, RequestPrincipal),
            "guarded": principal.guarded,
            "can_mutate": principal.can_mutate,
        }

    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=MutationGuardConfig,
    )
    app.add_middleware(auth_mod.AuthMiddleware)

    response = TestClient(app).post("/api/write")

    assert response.status_code == 200
    assert response.json() == {
        "principal": True,
        "guarded": False,
        "can_mutate": True,
    }


@pytest.mark.p0
@pytest.mark.parametrize(
    ("path", "allowed_hosts"),
    [
        ("/api/write", ["testclient"]),
        ("/api/desktop/shutdown", []),
    ],
)
def test_auth_skip_paths_set_principal_and_allow_write(
    monkeypatch,
    path,
    allowed_hosts,
):
    class FakeSecurity:
        allow_no_auth_hosts = allowed_hosts

    class FakeConfig:
        security = FakeSecurity()

    monkeypatch.setattr(auth_mod, "is_auth_enabled", lambda: True)
    monkeypatch.setattr(
        auth_mod,
        "_get_config_cached",
        lambda: (FakeConfig(), []),
    )
    app = FastAPI()

    @app.post(path)
    async def write(request: Request):
        principal = request.state.request_principal
        return {
            "principal": isinstance(principal, RequestPrincipal),
            "guarded": principal.guarded,
            "can_mutate": principal.can_mutate,
        }

    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=MutationGuardConfig,
    )
    app.add_middleware(auth_mod.AuthMiddleware)

    response = TestClient(app).post(path)

    assert response.status_code == 200
    assert response.json() == {
        "principal": True,
        "guarded": False,
        "can_mutate": True,
    }


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


@pytest.mark.p0
def test_member_cannot_update_mutation_guard_config():
    from qwenpaw.app.routers.config import router as config_router

    app = FastAPI()
    app.include_router(config_router, prefix="/api")
    app.add_middleware(
        MutationAuthorizationMiddleware,
        config_loader=MutationGuardConfig,
        principal_loader=lambda _request: MEMBER,
    )

    events = []
    with (
        patch(
            "qwenpaw.app.routers.config.mutate_config",
        ) as update_mock,
        patch(
            "qwenpaw.app.mutation_authorization.emit_mutation_audit",
            side_effect=lambda event, **fields: events.append(
                (event, fields),
            ),
        ),
    ):
        response = TestClient(app).put(
            "/api/config/security/mutation-guard",
            json={
                "enabled": False,
                "privileged_roles": ["admin", "root"],
                "intent_precheck_enabled": False,
                "classifier_timeout_seconds": 8,
                "deny_message": "disabled by member",
            },
        )

    assert response.status_code == 403
    assert response.json()["code"] == "mutation_permission_denied"
    assert events[0][1]["route"] == ("PUT /api/config/security/mutation-guard")
    update_mock.assert_not_called()
