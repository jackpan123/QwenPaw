# -*- coding: utf-8 -*-
"""Audit the capabilities exposed by the real API route catalog."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator

import pytest

from qwenpaw.app.mutation_authorization import (
    default_capability_for_method,
)
from qwenpaw.security.mutation_guard import RouteCapability


def _iter_route_methods(
    routes: Iterable[object],
    *,
    prefix: str = "",
) -> Iterator[tuple[str, str, object]]:
    for route in routes:
        effective_contexts = getattr(
            route,
            "effective_route_contexts",
            None,
        )
        if callable(effective_contexts):
            for context in effective_contexts():
                path = getattr(context, "path", "")
                methods = getattr(context, "methods", None) or ()
                for method in methods:
                    yield path, method, context
            continue

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
    from qwenpaw.app._app import app

    return app


@pytest.fixture(scope="module", autouse=True)
def _materialize_lifespan_api_action_routes():
    """Register the production routes normally added inside lifespan."""
    from qwenpaw.api_action import ManagerRegistry
    from qwenpaw.app._api_action_routes import register_http_routes
    from qwenpaw.app.crons.manager import CronManager

    production_app = _production_app()
    original_routes = list(production_app.routes)
    original_middleware_stack = production_app.middleware_stack
    existing_cron_paths = {
        getattr(route, "path", "")
        for route in production_app.routes
        if getattr(route, "path", "").startswith("/crons/")
    }
    expected_cron_paths = {"/crons/jobs", "/crons/jobs/{job_id}"}
    if not existing_cron_paths:
        registry = ManagerRegistry()
        registry.register(CronManager, lambda _app: None)
        register_http_routes(production_app, registry)
    else:
        assert existing_cron_paths == expected_cron_paths
    try:
        yield
    finally:
        production_app.router.routes[:] = original_routes
        production_app.middleware_stack = original_middleware_stack


def _route_records() -> list[tuple[str, str, object]]:
    app = _production_app()
    return list(_iter_route_methods(app.routes))


def _route_catalog() -> dict[tuple[str, str], object]:
    return {(path, method): route for path, method, route in _route_records()}


def test_catalog_covers_every_production_route_method():
    production_app = _production_app()
    catalog_keys = set(_route_catalog())

    runtime_effective_keys: set[tuple[str, str]] = set()
    for route in production_app.routes:
        effective_contexts = getattr(
            route,
            "effective_route_contexts",
            None,
        )
        if not callable(effective_contexts):
            continue
        for context in effective_contexts():
            path = getattr(context, "path", "")
            methods = getattr(context, "methods", None) or ()
            runtime_effective_keys.update((path, method) for method in methods)

    if runtime_effective_keys:
        assert runtime_effective_keys <= catalog_keys
    assert len(catalog_keys) >= 100
    assert {
        ("/api/auth/login", "POST"),
        ("/api/desktop/shutdown", "POST"),
        ("/api/agents/{agentId}/console/chat", "POST"),
        ("/voice/incoming", "POST"),
        ("/crons/jobs", "GET"),
        ("/crons/jobs", "POST"),
        ("/crons/jobs/{job_id}", "DELETE"),
    } <= catalog_keys


def test_lifespan_cron_routes_are_present_in_production_catalog():
    """Use a direct route scan independent of the catalog walker."""
    cron_routes: set[tuple[str, str]] = set()
    for route in _production_app().routes:
        path = getattr(route, "path", "")
        if not path.startswith("/crons/"):
            continue
        methods = getattr(route, "methods", None) or ()
        cron_routes.update((path, method) for method in methods)

    assert cron_routes == {
        ("/crons/jobs", "GET"),
        ("/crons/jobs", "POST"),
        ("/crons/jobs/{job_id}", "DELETE"),
    }


def test_lifespan_route_fixture_restores_existing_middleware_stack():
    production_app = _production_app()
    previous_stack = production_app.middleware_stack
    sentinel_stack = object()
    production_app.middleware_stack = sentinel_stack
    fixture_body = _materialize_lifespan_api_action_routes.__wrapped__()
    restored_stack = None
    try:
        next(fixture_body)
        with pytest.raises(StopIteration):
            next(fixture_body)
        restored_stack = production_app.middleware_stack
    finally:
        production_app.middleware_stack = previous_stack

    assert restored_stack is sentinel_stack


def test_catalog_has_no_duplicate_path_method_registrations():
    counts = Counter(
        (path, method) for path, method, _route in _route_records()
    )
    duplicates = sorted(key for key, count in counts.items() if count > 1)

    assert duplicates == []


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
        ("/api/console/inbox/read", "POST"): RouteCapability.MUTATE,
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
