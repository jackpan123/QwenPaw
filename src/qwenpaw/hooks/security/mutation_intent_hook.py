# -*- coding: utf-8 -*-
"""Early mutation-intent guard for NocoBase member conversations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from agentscope.message import Msg, TextBlock

from ...app.agent_context import get_current_request_principal
from ...config.utils import load_config
from ...runtime.hooks import HookAction, HookContext, HookResult
from ...runtime.phases import Phase
from ...security.mutation_guard import RequestPrincipal, emit_mutation_audit
from ...security.mutation_guard.intent import (
    MAX_CURRENT_MESSAGE_CHARS,
    IntentKind,
    IntentResult,
    bound_recent_context,
    classify_mutation_intent,
    parse_intent_result,
)
from ..base import LifecycleHook

Classifier = Callable[..., Awaitable[IntentResult | str]]

_READ_ONLY_CONSTRAINT = """安全权限约束：本轮意图无法被可靠确认为只读请求。
你可以解释、分析和提供示例，但不得执行变更，不得调用会写入持久状态或产生
外部副作用的工具；如用户确需执行变更，请说明需要 admin 或 root 权限。"""


def _value(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _message_text(message: Any) -> str:
    getter = getattr(message, "get_text_content", None)
    if callable(getter):
        try:
            text = getter()
            if isinstance(text, str):
                return text
        except (AttributeError, KeyError, TypeError):
            pass

    content = _value(message, "content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""

    fragments: list[str] = []
    for block in content:
        block_type = _value(block, "type")
        text = _value(block, "text")
        if (block_type in {None, "text"}) and isinstance(text, str):
            fragments.append(text)
    return "\n".join(fragments)


def _current_user_text(ctx: HookContext) -> str:
    for message in reversed(ctx.input_msgs or []):
        if _value(message, "role") == "user":
            return _message_text(message)

    request_input = _value(ctx.request, "input", [])
    if isinstance(request_input, list):
        for message in reversed(request_input):
            if _value(message, "role") == "user":
                return _message_text(message)
    return ""


def _session_context_messages(ctx: HookContext) -> list[Any]:
    session_state = ctx.session_state
    if not isinstance(session_state, dict):
        return []
    nested_state = session_state.get("state")
    if isinstance(nested_state, dict):
        context = nested_state.get("context")
    else:
        context = session_state.get("context")
    return context if isinstance(context, list) else []


def _recent_context(ctx: HookContext) -> list[str]:
    rendered: list[str] = []
    for message in _session_context_messages(ctx):
        role = _value(message, "role")
        if role not in {"user", "assistant"}:
            continue
        text = _message_text(message).strip()
        if text:
            rendered.append(f"{role}: {text}")
    return bound_recent_context(rendered)


def _coerce_result(value: IntentResult | str) -> IntentResult:
    if isinstance(value, IntentResult):
        return value
    if isinstance(value, str):
        return parse_intent_result(value)
    raise ValueError("classifier returned an unsupported result")


def _audit(
    event: str,
    *,
    ctx: HookContext,
    principal: RequestPrincipal,
    decision: str,
    reason: str,
) -> None:
    emit_mutation_audit(
        event,
        user_id=principal.user_id,
        roles=principal.roles,
        source=principal.source,
        agent_id=ctx.agent_id,
        session_id=ctx.session_id,
        channel=_value(ctx.request, "channel", "") or "",
        decision=decision,
        reason=reason,
    )


class MutationIntentHook(LifecycleHook):
    """Classify guarded member turns before building the main agent."""

    phase = Phase.PRE_AGENT_BUILD
    name = "mutation_intent"
    priority = 20
    after = ("session_load",)

    def __init__(self, classifier: Classifier | None = None) -> None:
        self._classifier = classifier or classify_mutation_intent

    # pylint: disable-next=too-many-return-statements
    async def run(self, ctx: HookContext) -> HookResult:
        config = load_config().security.mutation_guard
        if not config.enabled or not config.intent_precheck_enabled:
            return HookResult()

        principal = get_current_request_principal()
        if principal is None or not principal.guarded or principal.can_mutate:
            return HookResult()

        current_text = _current_user_text(ctx)
        if not current_text.strip():
            return HookResult()
        if len(current_text) > MAX_CURRENT_MESSAGE_CHARS:
            return self._degrade(
                ctx,
                principal,
                reason="message_too_long",
            )
        current_text = current_text.strip()

        try:
            raw_result = await asyncio.wait_for(
                self._classifier(
                    current_text=current_text,
                    recent_context=_recent_context(ctx),
                    agent_id=ctx.agent_id,
                ),
                timeout=config.classifier_timeout_seconds,
            )
            result = _coerce_result(raw_result)
        except asyncio.TimeoutError:
            return self._degrade(
                ctx,
                principal,
                reason="classifier_timeout",
            )
        except asyncio.CancelledError:  # pylint: disable=try-except-raise
            raise
        except Exception:
            return self._degrade(
                ctx,
                principal,
                reason="classifier_error",
            )

        if result.intent is IntentKind.MUTATION_REQUEST:
            _audit(
                "mutation_intent_denied",
                ctx=ctx,
                principal=principal,
                decision="deny",
                reason="classified_mutation_request",
            )
            return HookResult(
                action=HookAction.SHORT_CIRCUIT,
                payload=Msg(
                    name="assistant",
                    role="assistant",
                    content=[
                        TextBlock(
                            type="text",
                            text=config.deny_message,
                        ),
                    ],
                ),
            )
        if result.intent is IntentKind.AMBIGUOUS:
            return self._degrade(
                ctx,
                principal,
                reason="ambiguous_intent",
            )
        return HookResult()

    @staticmethod
    def _degrade(
        ctx: HookContext,
        principal: RequestPrincipal,
        *,
        reason: str,
    ) -> HookResult:
        ctx.inject_context(
            _READ_ONLY_CONSTRAINT,
            priority=20,
            source="mutation_intent",
        )
        _audit(
            "mutation_intent_degraded",
            ctx=ctx,
            principal=principal,
            decision="read_only",
            reason=reason,
        )
        return HookResult()


__all__ = ["MutationIntentHook"]
