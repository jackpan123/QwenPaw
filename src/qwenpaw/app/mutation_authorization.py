# -*- coding: utf-8 -*-
"""Route capability authorization for guarded HTTP requests."""

from __future__ import annotations

from collections.abc import Callable
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


def resolve_route_capability(request: Request) -> RouteCapability:
    """Resolve a route declaration, falling back safely by HTTP method."""
    for route in request.app.routes:
        match, _ = route.matches(request.scope)
        if match is not Match.FULL:
            continue
        endpoint = getattr(route, "endpoint", None)
        declared = getattr(
            endpoint,
            "__qwenpaw_api_capability__",
            None,
        )
        if isinstance(declared, RouteCapability):
            return declared
        break
    return default_capability_for_method(request.method)


def _load_config() -> MutationGuardConfig:
    return load_config().security.mutation_guard


def _load_principal(request: Request) -> RequestPrincipal:
    principal = getattr(request.state, "request_principal", None)
    if isinstance(principal, RequestPrincipal):
        return principal
    return RequestPrincipal()


def _deny_detail(config: MutationGuardConfig) -> str:
    paragraphs = config.deny_message.strip().splitlines()
    first_paragraph = paragraphs[0].strip() if paragraphs else ""
    return first_paragraph or "Mutation permission denied."


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

        capability = resolve_route_capability(request)
        if capability is not RouteCapability.MUTATE:
            return await call_next(request)

        emit_mutation_audit(
            "api_mutation_denied",
            user_id=principal.user_id,
            roles=principal.roles,
            source=principal.source,
            route=f"{request.method} {request.url.path}",
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
