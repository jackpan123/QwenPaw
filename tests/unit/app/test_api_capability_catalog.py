# -*- coding: utf-8 -*-
"""Audit the capabilities exposed by the real API route catalog."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRoute

from qwenpaw.app.mutation_authorization import (
    default_capability_for_method,
)
from qwenpaw.app.routers import router as api_router
from qwenpaw.security.mutation_guard import RouteCapability


def _route_catalog() -> dict[tuple[str, str], APIRoute]:
    app = FastAPI()
    app.include_router(api_router, prefix="/api")
    return {
        (route.path, method): route
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods
    }


def test_real_api_catalog_has_no_unknown_allow_state():
    catalog = _route_catalog()

    for (_path, method), route in catalog.items():
        declared = getattr(
            route.endpoint,
            "__qwenpaw_api_capability__",
            None,
        )
        if declared is not None:
            assert isinstance(declared, RouteCapability)
        elif method not in {"GET", "HEAD", "OPTIONS"}:
            assert (
                default_capability_for_method(method) is RouteCapability.MUTATE
            )


def test_required_non_mutating_routes_are_explicitly_cataloged():
    catalog = _route_catalog()
    expected = {
        ("/api/auth/login", "POST"): RouteCapability.PUBLIC,
        ("/api/auth/status", "GET"): RouteCapability.READ,
        ("/api/auth/verify", "GET"): RouteCapability.READ,
        ("/api/console/chat", "POST"): RouteCapability.CHAT,
        ("/api/console/chat/task", "POST"): RouteCapability.CHAT,
        ("/api/console/chat/stop", "POST"): RouteCapability.CHAT,
        ("/api/console/inbox/read", "POST"): RouteCapability.CHAT,
        ("/api/market/search", "POST"): RouteCapability.READ,
        (
            "/api/skills/ai/optimize/stream",
            "POST",
        ): RouteCapability.READ,
    }

    assert expected.keys() <= catalog.keys()
    for route_key, capability in expected.items():
        route = catalog[route_key]
        declared = getattr(route.endpoint, "__qwenpaw_api_capability__")
        assert declared is capability


def test_production_middleware_order_provides_principal_before_guard():
    from qwenpaw.app._app import app as production_app

    middleware_names = [
        middleware.cls.__name__
        for middleware in production_app.user_middleware
    ]
    assert middleware_names.index("AuthMiddleware") < middleware_names.index(
        "MutationAuthorizationMiddleware",
    )
    assert middleware_names.index(
        "MutationAuthorizationMiddleware",
    ) < middleware_names.index("AgentContextMiddleware")
