# -*- coding: utf-8 -*-
"""Route capability authorization for guarded HTTP requests."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from typing import TypeVar

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Match

from ..config import load_config
from ..config.config import MutationGuardConfig
from ..security.mutation_guard import (
    RequestPrincipal,
    RouteCapability,
    emit_mutation_audit,
)

_Endpoint = TypeVar("_Endpoint", bound=Callable)
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def api_capability(
    capability: RouteCapability | str,
) -> Callable[[_Endpoint], _Endpoint]:
    """Declare the capability exposed by one API endpoint."""
    if not isinstance(capability, (RouteCapability, str)):
        raise TypeError("capability must be a RouteCapability or str")
    try:
        normalized = RouteCapability(capability)
    except ValueError as exc:
        raise ValueError(f"unknown API capability: {capability!r}") from exc

    def decorate(endpoint: _Endpoint) -> _Endpoint:
        setattr(endpoint, "__qwenpaw_api_capability__", normalized)
        return endpoint

    return decorate


def default_capability_for_method(method: str) -> RouteCapability:
    """Return the fail-closed capability for an HTTP method."""
    if method.upper() in _READ_METHODS:
        return RouteCapability.READ
    return RouteCapability.MUTATE


def _iter_effective_routes(routes: Iterable[object]) -> Iterator[object]:
    """Yield matchable routes across flat and deferred FastAPI catalogs."""
    for route in routes:
        effective_contexts = getattr(
            route,
            "effective_route_contexts",
            None,
        )
        if callable(effective_contexts):
            yield from effective_contexts()
        else:
            yield route


def _route_template(route: object, fallback: str) -> str:
    path = getattr(route, "path", None)
    return path if isinstance(path, str) and path else fallback


def _resolve_route_capability(
    request: Request,
) -> tuple[RouteCapability, str]:
    """Resolve capability and safe route template for one request."""
    partial_template: str | None = None
    for route in _iter_effective_routes(request.app.routes):
        matches = getattr(route, "matches", None)
        if not callable(matches):
            continue
        match, _ = matches(request.scope)
        if match is Match.PARTIAL:
            if partial_template is None:
                partial_template = _route_template(route, "<matched>")
            continue
        if match is not Match.FULL:
            continue

        route_template = _route_template(route, "<matched>")
        endpoint = getattr(route, "endpoint", None)
        declared = getattr(
            endpoint,
            "__qwenpaw_api_capability__",
            None,
        )
        if isinstance(declared, RouteCapability):
            return declared, route_template
        return default_capability_for_method(request.method), route_template

    return (
        default_capability_for_method(request.method),
        partial_template or "<unmatched>",
    )


def resolve_route_capability(request: Request) -> RouteCapability:
    """Resolve a route declaration, falling back safely by HTTP method."""
    capability, _ = _resolve_route_capability(request)
    return capability


def _load_config() -> MutationGuardConfig:
    return load_config().security.mutation_guard


def _load_principal(request: Request) -> RequestPrincipal:
    principal = getattr(request.state, "request_principal", None)
    if isinstance(principal, RequestPrincipal):
        return principal
    return RequestPrincipal(guarded=True, can_mutate=False)


def _deny_detail(config: MutationGuardConfig) -> str:
    first_sentence = config.deny_message.strip().split("。", 1)[0]
    lines = first_sentence.splitlines()
    detail = lines[0].strip() if lines else ""
    return detail or "Mutation permission denied."


def guarded_mutation_denial(
    request: Request,
    *,
    route: str,
    reason: str,
) -> JSONResponse | None:
    """Return a consistent denial for a mixed-capability handler.

    Static route declarations remain the primary HTTP boundary. A route that
    normally provides chat infrastructure can call this before handler side
    effects when optional request fields upgrade that invocation to a
    mutation.
    """
    config = _load_config()
    principal = _load_principal(request)
    if not config.enabled or not principal.guarded or principal.can_mutate:
        return None

    emit_mutation_audit(
        "api_mutation_denied",
        user_id=principal.user_id,
        roles=principal.roles,
        source=principal.source,
        route=route,
        decision="deny",
        reason=reason,
    )
    return JSONResponse(
        status_code=403,
        content={
            "detail": _deny_detail(config),
            "code": "mutation_permission_denied",
        },
    )


# pylint: disable-next=too-few-public-methods
class MutationAuthorizationMiddleware(BaseHTTPMiddleware):
    """Deny mutating API routes to guarded read-only principals."""

    def __init__(
        self,
        app,
        *,
        config_loader: Callable[[], MutationGuardConfig] | None = None,
        principal_loader: Callable[[Request], RequestPrincipal] | None = None,
    ) -> None:
        super().__init__(app)
        self._config_loader = config_loader or _load_config
        self._principal_loader = principal_loader or _load_principal

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:
        """Authorize the resolved route capability before handler entry."""
        config = self._config_loader()
        principal = self._principal_loader(request)
        if not config.enabled or not principal.guarded or principal.can_mutate:
            return await call_next(request)

        capability, route_template = _resolve_route_capability(request)
        if capability is not RouteCapability.MUTATE:
            return await call_next(request)

        emit_mutation_audit(
            "api_mutation_denied",
            user_id=principal.user_id,
            roles=principal.roles,
            source=principal.source,
            route=f"{request.method} {route_template}",
            decision="deny",
            reason="mutation_permission_denied",
        )
        return JSONResponse(
            status_code=403,
            content={
                "detail": _deny_detail(config),
                "code": "mutation_permission_denied",
            },
        )
