# -*- coding: utf-8 -*-
"""Pure authorization types and decisions for mutation guarding."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from qwenpaw.config.config import MutationGuardConfig


class ActionEffect(str, Enum):
    """Effect produced by an agent action."""

    READ = "read"
    MUTATE = "mutate"
    EXTERNAL_SIDE_EFFECT = "external_side_effect"
    UNKNOWN = "unknown"
    CHAT_INFRASTRUCTURE = "chat_infrastructure"


class RouteCapability(str, Enum):
    """Maximum capability exposed by an HTTP route."""

    PUBLIC = "public"
    READ = "read"
    CHAT = "chat"
    MUTATE = "mutate"


@dataclass(frozen=True)
class RequestPrincipal:
    """Trusted authorization identity carried with one request."""

    user_id: str = ""
    roles: tuple[str, ...] = ()
    source: str = ""
    guarded: bool = False
    can_mutate: bool = True

    def to_context(self) -> dict[str, Any]:
        """Return a JSON-compatible request context."""
        return {
            "user_id": self.user_id,
            "roles": list(self.roles),
            "source": self.source,
            "guarded": self.guarded,
            "can_mutate": self.can_mutate,
        }

    @classmethod
    def from_context(
        cls,
        context: object | None,
    ) -> "RequestPrincipal":
        """Build a principal from trusted context without broad coercion."""
        if context is None:
            return cls()
        if type(context) is not dict:
            return cls(guarded=True, can_mutate=False)

        context_dict = cast(dict[str, Any], context)
        raw_roles = context_dict.get("roles")
        if isinstance(raw_roles, (list, tuple)):
            roles = tuple(role for role in raw_roles if isinstance(role, str))
        else:
            roles = ()

        user_id = context_dict.get("user_id")
        source = context_dict.get("source")
        guarded = context_dict.get("guarded")
        can_mutate = context_dict.get("can_mutate")
        valid_flags = isinstance(guarded, bool) and isinstance(
            can_mutate,
            bool,
        )
        normalized_guarded = guarded is True if valid_flags else True
        normalized_can_mutate = can_mutate is True if valid_flags else False
        return cls(
            user_id=user_id if isinstance(user_id, str) else "",
            roles=roles,
            source=source if isinstance(source, str) else "",
            guarded=normalized_guarded,
            can_mutate=normalized_can_mutate,
        )


@dataclass(frozen=True)
class MutationDecision:
    """Authorization decision for one action effect."""

    allowed: bool
    reason: str


def _normalized(values: Iterable[str]) -> frozenset[str]:
    """Normalize role values for exact, case-insensitive matching."""
    return frozenset(
        value.strip().casefold()
        for value in values
        if isinstance(value, str) and value.strip()
    )


def build_request_principal(
    *,
    user_id: str,
    roles: Iterable[str],
    source: str,
    auth_enabled: bool,
    config: "MutationGuardConfig",
) -> RequestPrincipal:
    """Build the guarded principal for an authenticated request."""
    materialized_roles = tuple(roles) if not isinstance(roles, str) else ()
    guarded = bool(
        config.enabled
        and auth_enabled
        and user_id
        and source.strip().casefold() == "nocobase"
    )
    privileged = bool(
        _normalized(materialized_roles) & _normalized(config.privileged_roles)
    )
    return RequestPrincipal(
        user_id=user_id,
        roles=materialized_roles,
        source=source,
        guarded=guarded,
        can_mutate=not guarded or privileged,
    )


def authorize_effect(
    principal: RequestPrincipal,
    effect: ActionEffect,
    config: "MutationGuardConfig",
) -> MutationDecision:
    """Authorize an action effect under the mutation guard."""
    if not config.enabled:
        return MutationDecision(True, "mutation_guard_disabled")
    if not principal.guarded and principal.can_mutate:
        return MutationDecision(True, "principal_not_guarded")
    if principal.can_mutate:
        return MutationDecision(True, "principal_can_mutate")
    if effect in {
        ActionEffect.READ,
        ActionEffect.CHAT_INFRASTRUCTURE,
    }:
        return MutationDecision(True, "non_mutating_effect")
    return MutationDecision(
        False,
        f"effect_{effect.value}_requires_privileged_role",
    )
