# -*- coding: utf-8 -*-
"""Authoritative role-based mutation gate for tool execution.

``authorize_tool_call`` is the FIRST gate in the tool execution path — it
runs before approval_level / governance / sandbox / tool-guard. A
non-privileged member denied by the mutation guard is rejected even when
``approval_level=off`` so closing approval can never bypass role
restrictions.

The gate is a no-op for local / unauthenticated operation: with no
``request_principal`` in the request context, or ``principal.guarded`` is
False, or ``principal.can_mutate`` is True, :func:`authorize_effect` already
returns ``allowed`` — see :mod:`qwenpaw.security.mutation_guard.policy`.
This keeps the gate invisible to local governance tests.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ...config.utils import load_config
from . import MutationDecision, RequestPrincipal, authorize_effect

if TYPE_CHECKING:
    from ...runtime.tool_registry import ToolEffectSpec

_MUTATION_PERMISSION_DENIED = "mutation_permission_denied"


def authorize_tool_call(
    *,
    request_context: dict[str, Any] | None,
    effect_spec: "ToolEffectSpec",
    input_data: dict[str, Any] | None,
) -> MutationDecision:
    """Authorize one tool call under the role-based mutation guard.

    Resolves the trusted principal from the request context, resolves the
    action effect from the tool's :class:`ToolEffectSpec` against the
    actual call params, and delegates to :func:`authorize_effect`.
    """
    config = load_config().security.mutation_guard
    principal = RequestPrincipal.from_context(
        (request_context or {}).get("request_principal"),
    )
    effect = effect_spec.resolve(input_data)
    return authorize_effect(principal, effect, config)
