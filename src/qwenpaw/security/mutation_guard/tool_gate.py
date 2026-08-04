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

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Any, cast

from ...config.utils import load_config
from . import MutationDecision, RequestPrincipal, authorize_effect

if TYPE_CHECKING:
    from ...runtime.tool_registry import ToolEffectSpec

_MUTATION_PERMISSION_DENIED = "mutation_permission_denied"


def _context_dict(value: object | None) -> dict[str, Any]:
    """Return only a real request-context dict."""
    if type(value) is dict:
        return cast(dict[str, Any], value)
    return {}


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
    context = _context_dict(request_context)
    principal = RequestPrincipal.from_context(context.get("request_principal"))
    effect = effect_spec.resolve(input_data)
    return authorize_effect(principal, effect, config)


def authorize_tool_call_and_audit(
    *,
    request_context: dict[str, Any] | None,
    effect_spec: "ToolEffectSpec",
    input_data: dict[str, Any] | None,
    tool_name: str,
) -> MutationDecision:
    """Authorize a call and emit a parameter-free denial audit event."""
    decision = authorize_tool_call(
        request_context=request_context,
        effect_spec=effect_spec,
        input_data=input_data,
    )
    if decision.allowed:
        return decision

    from .audit import emit_mutation_audit

    context = _context_dict(request_context)
    principal = RequestPrincipal.from_context(context.get("request_principal"))
    emit_mutation_audit(
        "tool_denied",
        tool=tool_name,
        decision="deny",
        reason=decision.reason,
        user_id=principal.user_id,
        roles=list(principal.roles),
        source=principal.source,
        agent_id=str(context.get("agent_id") or ""),
        session_id=str(context.get("session_id") or ""),
        channel=str(context.get("channel") or ""),
    )
    return decision


def mutation_denial_message(decision: MutationDecision) -> str:
    """Return the stable user-facing tool denial message."""
    config = load_config().security.mutation_guard
    return (
        f"{config.deny_message} {_MUTATION_PERMISSION_DENIED} "
        f"({decision.reason})"
    )


def mutation_denied_tool_chunk(decision: MutationDecision) -> Any:
    """Build the terminal tool result used by every execution caller."""
    from agentscope.message import TextBlock, ToolResultState
    from agentscope.tool import ToolChunk

    return ToolChunk(
        is_last=True,
        state=ToolResultState.DENIED,
        content=[
            TextBlock(type="text", text=mutation_denial_message(decision))
        ],
        metadata={"mutation_guard_denied": True},
    )


async def execute_authorized_function_tool_call(
    tool: Any,
    input_data: dict[str, Any],
) -> Any:
    """Execute after middleware using real params and stream-time recheck."""
    from agentscope.tool import FunctionTool

    from ...runtime.tool_registry import ToolEffectSpec

    def authorize() -> MutationDecision:
        request_context = getattr(tool, "_qp_request_context", None) or {}
        effect_spec = (
            getattr(tool, "_qp_effect_spec", None) or ToolEffectSpec()
        )
        return authorize_tool_call_and_audit(
            request_context=request_context,
            effect_spec=effect_spec,
            input_data=input_data,
            tool_name=getattr(tool, "name", ""),
        )

    decision = authorize()
    if not decision.allowed:
        return mutation_denied_tool_chunk(decision)

    result = await FunctionTool.call(tool, **input_data)
    if not isinstance(result, AsyncGenerator):
        return result

    async def authorized_stream() -> AsyncGenerator[Any, None]:
        stream_decision = authorize()
        if not stream_decision.allowed:
            yield mutation_denied_tool_chunk(stream_decision)
            return
        async for chunk in result:
            yield chunk

    return authorized_stream()
