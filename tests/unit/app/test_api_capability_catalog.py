# -*- coding: utf-8 -*-
"""Audit the capabilities exposed by the real API route catalog."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from starlette.routing import BaseRoute

from qwenpaw.app.mutation_authorization import (
    default_capability_for_method,
)
from qwenpaw.security.mutation_guard import RouteCapability


def _iter_route_methods(
    routes: Iterable[BaseRoute],
    *,
    prefix: str = "",
) -> Iterator[tuple[str, str, BaseRoute]]:
    for route in routes:
        route_path = getattr(route, "path", "")
        full_path = f"{prefix}{route_path}"
        methods = getattr(route, "methods", None) or ()
        for method in methods:
            yield full_path, method, route

        child_routes = getattr(route, "routes", None)
        if child_routes is not None:
            yield from _iter_route_methods(
                child_routes,
                prefix=full_path.rstrip("/"),
            )


def _production_app():
    # Importing the module builds routes but does not enter the lifespan,
    # so no workspace or other external service is started.
    from qwenpaw.app._app import app

    return app


def _route_catalog() -> dict[tuple[str, str], BaseRoute]:
    app = _production_app()
    return {
        (path, method): route
        for path, method, route in _iter_route_methods(app.routes)
    }


def test_catalog_covers_every_production_route_method():
    production_app = _production_app()

    production_keys = {
        (path, method)
        for path, method, _route in _iter_route_methods(
            production_app.routes,
        )
    }
    catalog_keys = set(_route_catalog())

    assert production_keys <= catalog_keys
    assert {
        ("/api/desktop/shutdown", "POST"),
        ("/api/agents/{agentId}/console/chat", "POST"),
        ("/voice/incoming", "POST"),
    } <= catalog_keys


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
    production_app = _production_app()

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
