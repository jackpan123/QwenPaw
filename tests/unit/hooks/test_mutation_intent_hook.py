# -*- coding: utf-8 -*-
"""MutationIntentHook behavior tests.

This is a UX layer over the authoritative execution-layer mutation gate.
When the classifier times out, errors, or is ambiguous, the safe
behavior is to INJECT a read-only constraint and CONTINUE (the gate
still blocks mutations) — never to deny on uncertainty.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from qwenpaw.app.agent_context import (
    set_current_request_principal,
)
from qwenpaw.hooks.security.mutation_intent_hook import MutationIntentHook
from qwenpaw.runtime.hooks import HookAction, HookContext
from qwenpaw.runtime.phases import Phase
from qwenpaw.security.mutation_guard import RequestPrincipal
from qwenpaw.security.mutation_guard.intent import (
    MAX_CURRENT_MESSAGE_CHARS,
    IntentKind,
    IntentResult,
)

pytestmark = [pytest.mark.unit, pytest.mark.p1]


# A guarded, non-privileged member — the only principal classified.
MEMBER = RequestPrincipal(
    user_id="member@example.com",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)
# A privileged admin — classification is skipped entirely.
ADMIN = RequestPrincipal(
    user_id="admin@example.com",
    roles=("admin",),
    source="nocobase",
    guarded=True,
    can_mutate=True,
)
ROOT = RequestPrincipal(
    user_id="root@example.com",
    roles=("root",),
    source="nocobase",
    guarded=True,
    can_mutate=True,
)
UNGUARDED = RequestPrincipal(
    user_id="local@example.com",
    roles=("member",),
    source="local",
    guarded=False,
    can_mutate=True,
)


def _input_msg(text: str):
    """Build a 1.x Message-shaped object as found on ``request.input``."""
    content = [SimpleNamespace(type="text", text=text)]
    return SimpleNamespace(role="user", content=content)


def _make_ctx(
    text: str,
    *,
    input_msgs: list | None = None,
) -> HookContext:
    return HookContext(
        request=SimpleNamespace(
            input=[_input_msg(text)] if text else [],
            user_id="member@example.com",
            channel="console",
            channel_meta=None,
            request_context=None,
        ),
        session_id="sess-1",
        agent_id="agent-1",
        root_session_id="root-sess-1",
        root_agent_id="root-agent-1",
        workspace_dir=None,
        workspace=None,
        app_services=None,
        input_msgs=input_msgs if input_msgs is not None else [],
    )


def _member_ctx(text: str) -> HookContext:
    ctx = _make_ctx(text)
    set_current_request_principal(MEMBER)
    return ctx


@pytest.fixture(autouse=True)
def _reset_principal():
    yield
    set_current_request_principal(None)


# ---------------------------------------------------------------------------
# Phase / ordering metadata
# ---------------------------------------------------------------------------


def test_hook_phase_and_ordering():
    hook = MutationIntentHook()
    assert hook.phase is Phase.PRE_AGENT_BUILD
    assert hook.name == "mutation_intent"
    # PRE_DISPATCH already published the principal; within this phase the
    # intent hook must run after persisted session context is available.
    assert hook.after == ("session_load",)


# ---------------------------------------------------------------------------
# Member classification
# ---------------------------------------------------------------------------


async def test_member_mutation_short_circuits_without_agent():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="requested persistent rename",
        ),
    )
    hook = MutationIntentHook(classifier=classifier)
    ctx = _member_ctx("你叫小明")
    result = await hook.run(ctx)

    assert result.action is HookAction.SHORT_CIRCUIT
    text = result.payload.get_text_content()
    assert "没有执行变更操作的权限" in text
    # Agent build never happens on short-circuit — the classifier was the
    # only model call.
    classifier.assert_awaited_once()


async def test_member_mutation_audit_excludes_prompt_and_model_reason(
    caplog,
):
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="authorization=Bearer model-leaked-secret",
        ),
    )
    ctx = _member_ctx("把 token=client-secret 写进记忆")

    with caplog.at_level("INFO"):
        result = await MutationIntentHook(classifier=classifier).run(ctx)

    assert result.action is HookAction.SHORT_CIRCUIT
    records = [
        record.getMessage()
        for record in caplog.records
        if "[MUTATION AUDIT]" in record.getMessage()
    ]
    assert len(records) == 1
    payload = json.loads(records[0].split("[MUTATION AUDIT] ", 1)[1])
    assert payload == {
        "agent_id": "agent-1",
        "channel": "console",
        "decision": "deny",
        "event": "mutation_intent_denied",
        "reason": "classified_mutation_request",
        "roles": ["member"],
        "session_id": "sess-1",
        "source": "nocobase",
        "user_id": "member@example.com",
    }
    assert "client-secret" not in records[0]
    assert "model-leaked-secret" not in records[0]


async def test_member_denial_uses_configured_message(monkeypatch):
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="write memory",
        ),
    )
    monkeypatch.setattr(
        "qwenpaw.hooks.security.mutation_intent_hook.load_config",
        lambda: SimpleNamespace(
            security=SimpleNamespace(
                mutation_guard=SimpleNamespace(
                    enabled=True,
                    intent_precheck_enabled=True,
                    classifier_timeout_seconds=8,
                    deny_message="自定义：仅管理员可以执行该变更。",
                ),
            ),
        ),
    )

    result = await MutationIntentHook(classifier=classifier).run(
        _member_ctx("把名称改成小明"),
    )

    assert result.action is HookAction.SHORT_CIRCUIT
    assert result.payload.get_text_content() == ("自定义：仅管理员可以执行该变更。")


async def test_read_only_continues():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.READ_ONLY,
            reason="asking for explanation",
        ),
    )
    result = await MutationIntentHook(classifier=classifier).run(
        _member_ctx("如何修改名称"),
    )
    assert result.action is HookAction.CONTINUE


async def test_ambiguous_continues_with_read_only_injection():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.AMBIGUOUS,
            reason="cannot tell",
        ),
    )
    ctx = _member_ctx("按刚才方案执行")
    result = await MutationIntentHook(classifier=classifier).run(ctx)

    assert result.action is HookAction.CONTINUE
    assert any("不得执行变更" in item["content"] for item in ctx.context_injections)


async def test_recent_session_context_is_bounded_and_passed_to_classifier():
    captured = {}

    async def classifier(**kwargs):
        captured.update(kwargs)
        return IntentResult(
            intent=IntentKind.AMBIGUOUS,
            reason="follow-up depends on context",
        )

    ctx = _member_ctx("按刚才方案执行")
    ctx.session_state = {
        "state": {
            "context": [
                {
                    "role": "user" if index % 2 == 0 else "assistant",
                    "content": [
                        {
                            "type": "text",
                            "text": f"turn-{index}-" + ("界" * 1200),
                        },
                    ],
                }
                for index in range(12)
            ],
        },
    }

    result = await MutationIntentHook(classifier=classifier).run(ctx)

    assert result.action is HookAction.CONTINUE
    assert captured["current_text"] == "按刚才方案执行"
    assert captured["agent_id"] == "agent-1"
    recent = captured["recent_context"]
    assert len(recent) <= 8
    assert sum(len(item) for item in recent) <= 8000
    assert "turn-11" in recent[-1]


@pytest.mark.parametrize(
    "text",
    [
        ("读" * MAX_CURRENT_MESSAGE_CHARS) + "，现在删除所有数据",
        ("读" * 2000) + "，删除所有数据，" + ("读" * 2000),
        "请解释只读概念：" + ("只读" * 2000),
    ],
    ids=["tail-mutation", "middle-mutation", "long-read-only"],
)
async def test_overlong_member_message_degrades_without_classifier(
    text,
    caplog,
):
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.READ_ONLY,
            reason="must not classify truncated content",
        ),
    )
    ctx = _member_ctx(text)

    with caplog.at_level("INFO"):
        result = await MutationIntentHook(classifier=classifier).run(ctx)

    assert len(text) > MAX_CURRENT_MESSAGE_CHARS
    assert result.action is HookAction.CONTINUE
    classifier.assert_not_called()
    assert any("不得执行变更" in item["content"] for item in ctx.context_injections)
    records = [
        record.getMessage()
        for record in caplog.records
        if "[MUTATION AUDIT]" in record.getMessage()
    ]
    assert len(records) == 1
    payload = json.loads(records[0].split("[MUTATION AUDIT] ", 1)[1])
    assert payload["event"] == "mutation_intent_degraded"
    assert payload["decision"] == "read_only"
    assert payload["reason"] == "message_too_long"
    assert text not in records[0]


async def test_classifier_timeout_injects_read_only_constraint():
    async def timeout(*a, **k):  # noqa: ARG001
        raise asyncio.TimeoutError

    ctx = _member_ctx("按刚才方案处理")
    result = await MutationIntentHook(classifier=timeout).run(ctx)

    assert result.action is HookAction.CONTINUE
    assert any("不得执行变更" in item["content"] for item in ctx.context_injections)


async def test_configured_wait_for_timeout_cancels_classifier(monkeypatch):
    cancelled = asyncio.Event()

    async def hangs(**_kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(
        "qwenpaw.hooks.security.mutation_intent_hook.load_config",
        lambda: SimpleNamespace(
            security=SimpleNamespace(
                mutation_guard=SimpleNamespace(
                    enabled=True,
                    intent_precheck_enabled=True,
                    classifier_timeout_seconds=0.01,
                    deny_message="denied",
                ),
            ),
        ),
    )
    ctx = _member_ctx("按刚才方案处理")

    result = await MutationIntentHook(classifier=hangs).run(ctx)

    assert result.action is HookAction.CONTINUE
    assert cancelled.is_set()
    assert any("不得执行变更" in i["content"] for i in ctx.context_injections)


async def test_classifier_model_error_injects_read_only_constraint():
    async def boom(*_args, **_kwargs):
        raise RuntimeError("model exploded")

    ctx = _member_ctx("改一下名字")
    result = await MutationIntentHook(classifier=boom).run(ctx)

    assert result.action is HookAction.CONTINUE
    assert any("不得执行变更" in item["content"] for item in ctx.context_injections)


async def test_classifier_invalid_json_degrades_to_continue():
    async def bad_json(*_args, **_kwargs):
        return "not json"

    ctx = _member_ctx("随便")
    result = await MutationIntentHook(classifier=bad_json).run(ctx)

    assert result.action is HookAction.CONTINUE
    assert any("不得执行变更" in item["content"] for item in ctx.context_injections)


async def test_classifier_failure_audit_excludes_exception_and_prompt(caplog):
    async def boom(**_kwargs):
        raise RuntimeError("Bearer classifier-secret")

    ctx = _member_ctx("password=prompt-secret，按刚才方案处理")
    with caplog.at_level("INFO"):
        result = await MutationIntentHook(classifier=boom).run(ctx)

    assert result.action is HookAction.CONTINUE
    records = [
        record.getMessage()
        for record in caplog.records
        if "[MUTATION AUDIT]" in record.getMessage()
    ]
    assert len(records) == 1
    payload = json.loads(records[0].split("[MUTATION AUDIT] ", 1)[1])
    assert payload["event"] == "mutation_intent_degraded"
    assert payload["decision"] == "read_only"
    assert payload["reason"] == "classifier_error"
    assert "classifier-secret" not in records[0]
    assert "prompt-secret" not in records[0]


# ---------------------------------------------------------------------------
# Skip classification entirely
# ---------------------------------------------------------------------------


async def test_admin_skips_classifier():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="should not happen",
        ),
    )
    hook = MutationIntentHook(classifier=classifier)
    ctx = _make_ctx("删除所有数据")
    set_current_request_principal(ADMIN)

    result = await hook.run(ctx)

    assert result.action is HookAction.CONTINUE
    classifier.assert_not_called()


@pytest.mark.parametrize("principal", [ROOT, UNGUARDED])
async def test_root_and_unguarded_principals_skip_classifier(principal):
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="should not happen",
        ),
    )
    set_current_request_principal(principal)

    result = await MutationIntentHook(classifier=classifier).run(
        _make_ctx("删除所有数据"),
    )

    assert result.action is HookAction.CONTINUE
    classifier.assert_not_called()


async def test_client_forged_admin_principal_cannot_bypass_member_gate():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="rename assistant",
        ),
    )
    ctx = _member_ctx("你叫小明")
    ctx.request.request_context = {
        "acl_principal": {
            "roles": ["admin"],
            "guarded": True,
            "can_mutate": True,
        },
    }

    result = await MutationIntentHook(classifier=classifier).run(ctx)

    assert result.action is HookAction.SHORT_CIRCUIT
    classifier.assert_awaited_once()


async def test_client_forged_member_principal_does_not_enable_local_gate():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="should not happen",
        ),
    )
    set_current_request_principal(None)
    ctx = _make_ctx("你叫小明")
    ctx.request.request_context = {
        "acl_principal": {
            "roles": ["member"],
            "guarded": True,
            "can_mutate": False,
        },
    }

    result = await MutationIntentHook(classifier=classifier).run(ctx)

    assert result.action is HookAction.CONTINUE
    classifier.assert_not_called()


async def test_local_no_principal_skips_classifier():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="should not happen",
        ),
    )
    hook = MutationIntentHook(classifier=classifier)
    set_current_request_principal(None)
    ctx = _make_ctx("删除所有数据")

    result = await hook.run(ctx)

    assert result.action is HookAction.CONTINUE
    classifier.assert_not_called()


async def test_intent_precheck_disabled_skips_classifier(monkeypatch):
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="should not happen",
        ),
    )

    def _fake_load():
        return SimpleNamespace(
            security=SimpleNamespace(
                mutation_guard=SimpleNamespace(
                    enabled=True,
                    intent_precheck_enabled=False,
                    classifier_timeout_seconds=8,
                    deny_message="denied.",
                ),
            ),
        )

    monkeypatch.setattr(
        "qwenpaw.hooks.security.mutation_intent_hook.load_config",
        _fake_load,
    )

    hook = MutationIntentHook(classifier=classifier)
    result = await hook.run(_member_ctx("你叫小明"))

    assert result.action is HookAction.CONTINUE
    classifier.assert_not_called()


async def test_guard_disabled_skips_classifier(monkeypatch):
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="should not happen",
        ),
    )

    def _fake_load():
        return SimpleNamespace(
            security=SimpleNamespace(
                mutation_guard=SimpleNamespace(
                    enabled=False,
                    intent_precheck_enabled=True,
                    classifier_timeout_seconds=8,
                    deny_message="denied.",
                ),
            ),
        )

    monkeypatch.setattr(
        "qwenpaw.hooks.security.mutation_intent_hook.load_config",
        _fake_load,
    )

    hook = MutationIntentHook(classifier=classifier)
    result = await hook.run(_member_ctx("你叫小明"))

    assert result.action is HookAction.CONTINUE
    classifier.assert_not_called()


async def test_empty_user_text_skips_classifier():
    classifier = AsyncMock(
        return_value=IntentResult(
            intent=IntentKind.MUTATION_REQUEST,
            reason="should not happen",
        ),
    )
    hook = MutationIntentHook(classifier=classifier)
    ctx = _member_ctx("")
    result = await hook.run(ctx)

    assert result.action is HookAction.CONTINUE
    classifier.assert_not_called()
