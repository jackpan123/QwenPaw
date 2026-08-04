# -*- coding: utf-8 -*-
"""UT for the authoritative mutation gate in the tool execution path.

The role-based mutation gate must run FIRST in ``check_permissions``, before
approval_level / governance / sandbox / tool-guard. A non-privileged member
denied by the mutation guard must be rejected even when ``approval_level=off``
so closing approval can never bypass role restrictions.

The gate is a no-op for local / unauthenticated operation: with no
``request_principal`` in the request context, or ``principal.guarded`` is
False, or ``principal.can_mutate`` is True, the gate allows and falls through
to the rest of governance.
"""

from __future__ import annotations

# pylint: disable=protected-access

import asyncio
import json
import logging
from types import SimpleNamespace

import pytest
from agentscope.message import TextBlock, ToolCallBlock, ToolResultState
from agentscope.state import AgentState
from agentscope.tool import ToolChunk, Toolkit

from qwenpaw.governance import PolicyGuardedTool
from qwenpaw.governance import tool_adapter
from qwenpaw.runtime.tool_guard import GuardedFunctionTool
from qwenpaw.runtime.tool_registry import ToolEffectSpec
from qwenpaw.security.mutation_guard import (
    ActionEffect,
    MutationDecision,
    RequestPrincipal,
    authorize_effect,
)
from qwenpaw.security.mutation_guard import tool_gate

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_DENY_MESSAGE = "Permission denied."


def _mutation_guard_config(*, enabled: bool = True):
    """A ``MutationGuardConfig``-shaped namespace for ``authorize_effect``."""
    return SimpleNamespace(
        enabled=enabled,
        privileged_roles=["admin", "root"],
        intent_precheck_enabled=True,
        classifier_timeout_seconds=8,
        deny_message=_DENY_MESSAGE,
    )


def _patch_mutation_guard(monkeypatch, *, enabled: bool = True):
    """Make ``tool_gate.load_config`` return a config whose mutation guard
    is enabled (or not). Avoids touching disk."""

    fake_config = SimpleNamespace(
        security=SimpleNamespace(
            mutation_guard=_mutation_guard_config(enabled=enabled),
        ),
    )
    monkeypatch.setattr(
        tool_gate,
        "load_config",
        lambda *a, **k: fake_config,
    )


def _member_request_context() -> dict:
    return {
        "request_principal": {
            "user_id": "member",
            "roles": ["member"],
            "source": "nocobase",
            "guarded": True,
            "can_mutate": False,
        },
    }


def _admin_request_context() -> dict:
    return {
        "request_principal": {
            "user_id": "admin",
            "roles": ["admin"],
            "source": "nocobase",
            "guarded": True,
            "can_mutate": True,
        },
    }


def _root_request_context() -> dict:
    return {
        "request_principal": {
            "user_id": "root",
            "roles": ["root"],
            "source": "nocobase",
            "guarded": True,
            "can_mutate": True,
        },
    }


def _unguarded_request_context() -> dict:
    return {
        "request_principal": {
            "user_id": "legacy-user",
            "roles": ["member"],
            "source": "legacy",
            "guarded": False,
            "can_mutate": True,
        },
    }


async def _noop():
    """Placeholder mutating tool fn — never reached in deny tests."""


def _tool_text(result: ToolChunk) -> str:
    return "\n".join(
        block.text
        for block in result.content or []
        if isinstance(block, TextBlock)
    )


# ---------------------------------------------------------------------------
# authorize_tool_call unit tests
# ---------------------------------------------------------------------------


class TestAuthorizeToolCall:
    def test_member_mutate_is_denied(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is False

    def test_member_read_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.READ),
            input_data={},
        )
        assert decision.allowed is True

    def test_admin_mutate_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_admin_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is True

    def test_no_principal_is_allowed_local_mode(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=None,
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is True

    def test_request_context_without_principal_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context={},
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is True

    def test_disabled_guard_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch, enabled=False)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            input_data={},
        )
        assert decision.allowed is True

    def test_member_unknown_effect_is_denied_fail_closed(self, monkeypatch):
        # UNKNOWN is not READ/CHAT_INFRASTRUCTURE → denied for members.
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.UNKNOWN),
            input_data={},
        )
        assert decision.allowed is False

    def test_member_chat_infrastructure_is_allowed(self, monkeypatch):
        _patch_mutation_guard(monkeypatch)
        decision = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(
                default=ActionEffect.CHAT_INFRASTRUCTURE,
            ),
            input_data={},
        )
        assert decision.allowed is True

    def test_resolves_effect_from_input(self, monkeypatch):
        """A per-action spec must read the param value from input_data."""
        _patch_mutation_guard(monkeypatch)
        spec = ToolEffectSpec(
            default=ActionEffect.MUTATE,
            selector_param="action",
            read_values=("snapshot",),
        )
        allowed = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=spec,
            input_data={"action": "snapshot"},
        )
        assert allowed.allowed is True

        denied = tool_gate.authorize_tool_call(
            request_context=_member_request_context(),
            effect_spec=spec,
            input_data={"action": "click"},
        )
        assert denied.allowed is False


# ---------------------------------------------------------------------------
# PolicyGuardedTool integration — gate runs BEFORE the OFF check
# ---------------------------------------------------------------------------


class TestGateShortCircuitsBeforeGovernance:
    @pytest.mark.asyncio
    async def test_member_denied_before_governance_off(self, monkeypatch):
        """A member+MUTATE call must DENY even when approval_level=off.

        Without the mutation gate the OFF short-circuit would ALLOW this
        call. The gate must run first and deny it.
        """
        _patch_mutation_guard(monkeypatch)
        # Make governance think approval is off (the OFF short-circuit).
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )

        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.DENY
        assert "mutation_permission_denied" in decision.message

    @pytest.mark.asyncio
    async def test_member_read_falls_through_off(self, monkeypatch):
        """READ member calls pass the role gate into governance."""
        _patch_mutation_guard(monkeypatch)
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )
        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context=_member_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.READ),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.ALLOW

    @pytest.mark.asyncio
    async def test_admin_mutate_falls_through_off(self, monkeypatch):
        """Admin mutation calls pass the role gate into governance."""
        _patch_mutation_guard(monkeypatch)
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )
        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context=_admin_request_context(),
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.ALLOW

    @pytest.mark.asyncio
    async def test_local_no_principal_falls_through_off(self, monkeypatch):
        """Local mode keeps its legacy unguarded behavior."""
        _patch_mutation_guard(monkeypatch)
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )
        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context={},
            effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.ALLOW

    @pytest.mark.asyncio
    async def test_unannotated_tool_denied_for_member_off(self, monkeypatch):
        """UNKNOWN defaults fail closed for guarded members."""
        _patch_mutation_guard(monkeypatch)
        monkeypatch.setattr(
            tool_adapter,
            "_is_execution_level_off",
            lambda: True,
        )
        tool = PolicyGuardedTool(
            _noop,
            governor=None,
            request_context=_member_request_context(),
        )
        from agentscope.permission import PermissionBehavior

        decision = await tool.check_permissions({})
        assert decision.behavior is PermissionBehavior.DENY
        assert "mutation_permission_denied" in decision.message


# ---------------------------------------------------------------------------
# Final execution boundary — no caller may bypass the role gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "wrapper",
    [PolicyGuardedTool, GuardedFunctionTool],
)
@pytest.mark.parametrize(
    "effect",
    [
        ActionEffect.MUTATE,
        ActionEffect.EXTERNAL_SIDE_EFFECT,
        ActionEffect.UNKNOWN,
    ],
)
@pytest.mark.asyncio
async def test_direct_wrapper_call_cannot_bypass_member_denial(
    monkeypatch,
    wrapper,
    effect,
):
    _patch_mutation_guard(monkeypatch)
    calls = 0

    async def mutate() -> str:
        nonlocal calls
        calls += 1
        return "executed"

    tool = wrapper(
        mutate,
        request_context=_member_request_context(),
        effect_spec=ToolEffectSpec(default=effect),
    )

    result = await tool()

    assert calls == 0
    assert isinstance(result, ToolChunk)
    assert result.state is ToolResultState.DENIED
    assert "mutation_permission_denied" in _tool_text(result)


@pytest.mark.parametrize(
    "wrapper",
    [PolicyGuardedTool, GuardedFunctionTool],
)
@pytest.mark.asyncio
async def test_final_gate_allows_member_read_execution(monkeypatch, wrapper):
    _patch_mutation_guard(monkeypatch)
    calls = 0

    async def read() -> str:
        nonlocal calls
        calls += 1
        return "read result"

    tool = wrapper(
        read,
        request_context=_member_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.READ),
    )

    result = await tool()

    assert calls == 1
    assert isinstance(result, ToolChunk)
    assert result.state is not ToolResultState.DENIED


@pytest.mark.parametrize(
    "request_context",
    [
        _admin_request_context(),
        _root_request_context(),
        _unguarded_request_context(),
        {},
    ],
)
@pytest.mark.parametrize(
    "wrapper",
    [PolicyGuardedTool, GuardedFunctionTool],
)
@pytest.mark.asyncio
async def test_final_gate_preserves_privileged_and_local_compatibility(
    monkeypatch,
    wrapper,
    request_context,
):
    _patch_mutation_guard(monkeypatch)
    calls = 0

    async def mutate() -> str:
        nonlocal calls
        calls += 1
        return "mutated"

    tool = wrapper(
        mutate,
        request_context=request_context,
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    result = await tool()

    assert calls == 1
    assert result.state is not ToolResultState.DENIED


@pytest.mark.asyncio
async def test_execution_gate_does_not_reenter_permission_engine(monkeypatch):
    _patch_mutation_guard(monkeypatch)

    async def read() -> str:
        return "read"

    tool = GuardedFunctionTool(
        read,
        request_context=_member_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.READ),
    )

    async def unexpected_permission_check(*_args, **_kwargs):
        raise AssertionError("execution must not re-run approval checks")

    tool.check_permissions = unexpected_permission_check

    result = await tool()

    assert result.state is not ToolResultState.DENIED


@pytest.mark.asyncio
async def test_streaming_tool_is_denied_before_generator_runs(monkeypatch):
    _patch_mutation_guard(monkeypatch)
    calls = 0

    async def mutate_stream():
        nonlocal calls
        calls += 1
        yield ToolChunk(content=[TextBlock(text="executed")])

    tool = PolicyGuardedTool(
        mutate_stream,
        request_context=_member_request_context(),
        effect_spec=ToolEffectSpec(
            default=ActionEffect.EXTERNAL_SIDE_EFFECT,
        ),
    )

    result = await tool()

    assert calls == 0
    assert isinstance(result, ToolChunk)
    assert result.state is ToolResultState.DENIED


@pytest.mark.parametrize(
    "wrapper",
    [PolicyGuardedTool, GuardedFunctionTool],
)
@pytest.mark.asyncio
async def test_final_gate_authorizes_middleware_rewritten_arguments(
    monkeypatch,
    wrapper,
) -> None:
    _patch_mutation_guard(monkeypatch)
    calls = 0

    class RewriteSnapshotToDelete:
        async def on_tool_call(
            self,
            tool,
            input_kwargs,
            next_handler,
        ):
            del tool, input_kwargs
            async for chunk in next_handler(action="delete"):
                yield chunk

    async def browser(action: str) -> str:
        nonlocal calls
        calls += 1
        return action

    tool = wrapper(
        browser,
        request_context=_member_request_context(),
        effect_spec=ToolEffectSpec(
            default=ActionEffect.MUTATE,
            selector_param="action",
            read_values=("snapshot",),
        ),
        middlewares=[RewriteSnapshotToDelete()],
    )

    stream = await tool(action="snapshot")
    chunks = [chunk async for chunk in stream]

    assert calls == 0
    assert any(chunk.state is ToolResultState.DENIED for chunk in chunks)


@pytest.mark.parametrize(
    "wrapper",
    [PolicyGuardedTool, GuardedFunctionTool],
)
@pytest.mark.asyncio
async def test_stream_reauthorizes_when_iteration_actually_starts(
    monkeypatch,
    wrapper,
) -> None:
    _patch_mutation_guard(monkeypatch)
    calls = 0
    request_context = _admin_request_context()

    async def mutate_stream():
        nonlocal calls
        calls += 1
        yield ToolChunk(content=[TextBlock(text="executed")])

    tool = wrapper(
        mutate_stream,
        request_context=request_context,
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    stream = await tool()
    tool._qp_request_context = _member_request_context()
    chunks = [chunk async for chunk in stream]

    assert calls == 0
    assert any(chunk.state is ToolResultState.DENIED for chunk in chunks)


@pytest.mark.asyncio
async def test_policy_invocation_state_is_isolated_between_concurrent_calls(
    monkeypatch,
) -> None:
    from qwenpaw.governance.policy import (
        GovernanceAction,
        GovernanceDecision,
    )

    _patch_mutation_guard(monkeypatch)
    sandbox = object()
    received: dict[str, object | None] = {}

    class Governor:
        workspace_dir = "/tmp"

        @staticmethod
        def assert_policy(spec):
            if spec.raw_params["kind"] == "sandbox":
                return GovernanceDecision(
                    GovernanceAction.SANDBOX_FALLBACK,
                    "sandbox",
                    sandbox_config=sandbox,
                )
            return GovernanceDecision(GovernanceAction.ALLOW, "safe")

        @staticmethod
        def audit(*_args, **_kwargs):
            return None

    async def operation(kind: str, sandbox_config=None) -> str:
        received[kind] = sandbox_config
        return kind

    tool = PolicyGuardedTool(
        operation,
        governor=Governor(),
        request_context=_admin_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )
    sandbox_checked = asyncio.Event()
    safe_finished = asyncio.Event()

    async def invoke_sandbox():
        await tool.check_permissions({"kind": "sandbox"})
        sandbox_checked.set()
        await safe_finished.wait()
        return await tool(kind="sandbox")

    async def invoke_safe():
        await sandbox_checked.wait()
        await tool.check_permissions({"kind": "safe"})
        result = await tool(kind="safe")
        safe_finished.set()
        return result

    await asyncio.gather(invoke_sandbox(), invoke_safe())

    assert received == {"safe": None, "sandbox": sandbox}


@pytest.mark.asyncio
async def test_policy_stream_yields_first_chunk_without_waiting_for_second(
    monkeypatch,
) -> None:
    _patch_mutation_guard(monkeypatch)
    continue_stream = asyncio.Event()

    async def operation():
        yield ToolChunk(content=[TextBlock(text="first")])
        await continue_stream.wait()
        yield ToolChunk(content=[TextBlock(text="second")])

    tool = PolicyGuardedTool(
        operation,
        request_context=_admin_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.READ),
    )
    stream = await tool()

    first = await asyncio.wait_for(anext(stream), timeout=0.2)
    assert _tool_text(first) == "first"

    continue_stream.set()
    second = await asyncio.wait_for(anext(stream), timeout=0.2)
    assert _tool_text(second) == "second"
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


@pytest.mark.asyncio
async def test_policy_stream_does_not_read_ahead_or_buffer_long_stream(
    monkeypatch,
) -> None:
    _patch_mutation_guard(monkeypatch)
    produced = 0

    async def operation():
        nonlocal produced
        for index in range(10_000):
            produced += 1
            yield ToolChunk(content=[TextBlock(text=str(index))])

    tool = PolicyGuardedTool(
        operation,
        request_context=_admin_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.READ),
    )
    stream = await tool()

    first = await anext(stream)

    assert _tool_text(first) == "0"
    assert produced == 1
    await stream.aclose()


@pytest.mark.parametrize(
    ("sandbox_mode", "metadata"),
    [
        (True, {"business_denial": "quota"}),
        (False, {"sandbox_violation": "not from sandbox execution"}),
    ],
)
@pytest.mark.asyncio
async def test_stream_denial_without_active_explicit_sandbox_does_not_ask(
    monkeypatch,
    sandbox_mode,
    metadata,
) -> None:
    from agentscope.permission import PermissionBehavior, PermissionDecision
    from qwenpaw.governance.policy import (
        GovernanceAction,
        GovernanceDecision,
    )

    _patch_mutation_guard(monkeypatch)
    sandbox = object()
    approvals = 0
    calls = 0

    class Governor:
        workspace_dir = "/tmp"

        @staticmethod
        def assert_policy(_spec):
            if sandbox_mode:
                return GovernanceDecision(
                    GovernanceAction.SANDBOX_FALLBACK,
                    "sandbox",
                    sandbox_config=sandbox,
                )
            return GovernanceDecision(GovernanceAction.ALLOW, "allowed")

        @staticmethod
        def audit(*_args, **_kwargs):
            return None

    async def operation(sandbox_config=None):
        nonlocal calls
        calls += 1
        yield ToolChunk(
            state=ToolResultState.DENIED,
            metadata=metadata,
            content=[TextBlock(text="ordinary denial")],
        )

    async def approve(**_kwargs):
        nonlocal approvals
        approvals += 1
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="approved",
        )

    monkeypatch.setattr(tool_adapter, "_ask_user_approval", approve)
    tool = PolicyGuardedTool(
        operation,
        governor=Governor(),
        request_context=_admin_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )
    permission = await tool.check_permissions({})
    assert permission.behavior is PermissionBehavior.ALLOW

    stream = await tool()
    chunks = [chunk async for chunk in stream]

    assert approvals == 0
    assert calls == 1
    assert chunks[0].state is ToolResultState.DENIED


@pytest.mark.asyncio
async def test_late_streamed_sandbox_denial_never_retries_side_effects(
    monkeypatch,
) -> None:
    from qwenpaw.governance.policy import (
        GovernanceAction,
        GovernanceDecision,
    )

    _patch_mutation_guard(monkeypatch)
    sandbox = object()
    approvals = 0
    calls = 0
    audits = []

    class Governor:
        workspace_dir = "/tmp"

        @staticmethod
        def assert_policy(_spec):
            return GovernanceDecision(
                GovernanceAction.SANDBOX_FALLBACK,
                "sandbox",
                sandbox_config=sandbox,
            )

        @staticmethod
        def audit(spec, decision):
            audits.append((spec, decision))

    async def operation(sandbox_config=None):
        nonlocal calls
        calls += 1
        yield ToolChunk(content=[TextBlock(text="already emitted")])
        yield ToolChunk(
            state=ToolResultState.DENIED,
            metadata={"sandbox_violation": "late block"},
            content=[TextBlock(text="Sandbox violation: late block")],
        )

    async def unexpected_approval(**_kwargs):
        nonlocal approvals
        approvals += 1
        raise AssertionError("late sandbox denial must not ask or retry")

    monkeypatch.setattr(
        tool_adapter,
        "_ask_user_approval",
        unexpected_approval,
    )
    tool = PolicyGuardedTool(
        operation,
        governor=Governor(),
        request_context=_admin_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )
    await tool.check_permissions({})

    stream = await tool()
    first = await anext(stream)
    remaining = [chunk async for chunk in stream]

    assert _tool_text(first) == "already emitted"
    assert approvals == 0
    assert calls == 1
    assert len(remaining) == 1
    assert remaining[0].state is ToolResultState.DENIED
    assert audits[-1][1].action is GovernanceAction.DENY
    assert "retry suppressed" in audits[-1][1].reason


@pytest.mark.parametrize("approved", [True, False])
@pytest.mark.asyncio
async def test_middleware_stream_handles_sandbox_violation_and_retry(
    monkeypatch,
    approved,
) -> None:
    from agentscope.permission import PermissionBehavior, PermissionDecision
    from qwenpaw.governance.policy import (
        GovernanceAction,
        GovernanceDecision,
    )

    _patch_mutation_guard(monkeypatch)
    sandbox = object()
    received_configs: list[object | None] = []
    approvals = 0

    class PassThroughMiddleware:
        async def on_tool_call(
            self,
            tool,
            input_kwargs,
            next_handler,
        ):
            del tool
            async for chunk in next_handler(**input_kwargs):
                yield chunk

    class Governor:
        workspace_dir = "/tmp"

        @staticmethod
        def assert_policy(_spec):
            return GovernanceDecision(
                GovernanceAction.SANDBOX_FALLBACK,
                "sandbox",
                sandbox_config=sandbox,
            )

        @staticmethod
        def audit(*_args, **_kwargs):
            return None

    async def operation(sandbox_config=None):
        received_configs.append(sandbox_config)
        if sandbox_config is sandbox:
            yield ToolChunk(
                state=ToolResultState.DENIED,
                metadata={"sandbox_violation": "blocked"},
                content=[TextBlock(text="Sandbox violation: blocked")],
            )
            return
        yield ToolChunk(content=[TextBlock(text="retry-one")])
        yield ToolChunk(content=[TextBlock(text="retry-two")])

    async def decide(**_kwargs):
        nonlocal approvals
        approvals += 1
        return PermissionDecision(
            behavior=(
                PermissionBehavior.ALLOW
                if approved
                else PermissionBehavior.DENY
            ),
            message="decision",
        )

    monkeypatch.setattr(tool_adapter, "_ask_user_approval", decide)
    tool = PolicyGuardedTool(
        operation,
        governor=Governor(),
        request_context=_admin_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        middlewares=[PassThroughMiddleware()],
    )
    permission = await tool.check_permissions({})
    assert permission.behavior is PermissionBehavior.ALLOW

    stream = await tool()
    chunks = [chunk async for chunk in stream]

    assert approvals == 1
    if approved:
        assert received_configs == [sandbox, None]
        assert [_tool_text(chunk) for chunk in chunks] == [
            "retry-one",
            "retry-two",
        ]
    else:
        assert received_configs == [sandbox]
        assert len(chunks) == 1
        assert chunks[0].state is ToolResultState.DENIED


@pytest.mark.asyncio
async def test_middleware_stream_retry_rechecks_role_before_execution(
    monkeypatch,
) -> None:
    from agentscope.permission import PermissionBehavior, PermissionDecision
    from qwenpaw.governance.policy import (
        GovernanceAction,
        GovernanceDecision,
    )

    _patch_mutation_guard(monkeypatch)
    sandbox = object()
    request_context = _admin_request_context()
    calls = 0

    class PassThroughMiddleware:
        async def on_tool_call(
            self,
            tool,
            input_kwargs,
            next_handler,
        ):
            del tool
            async for chunk in next_handler(**input_kwargs):
                yield chunk

    class Governor:
        workspace_dir = "/tmp"

        @staticmethod
        def assert_policy(_spec):
            return GovernanceDecision(
                GovernanceAction.SANDBOX_FALLBACK,
                "sandbox",
                sandbox_config=sandbox,
            )

        @staticmethod
        def audit(*_args, **_kwargs):
            return None

    async def operation(sandbox_config=None):
        nonlocal calls
        calls += 1
        if sandbox_config is sandbox:
            yield ToolChunk(
                state=ToolResultState.DENIED,
                metadata={"sandbox_violation": "blocked"},
                content=[TextBlock(text="Sandbox violation: blocked")],
            )
            return
        yield ToolChunk(content=[TextBlock(text="must not execute")])

    async def approve_then_remove_privilege(**_kwargs):
        request_context["request_principal"] = _member_request_context()[
            "request_principal"
        ]
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="approved",
        )

    monkeypatch.setattr(
        tool_adapter,
        "_ask_user_approval",
        approve_then_remove_privilege,
    )
    tool = PolicyGuardedTool(
        operation,
        governor=Governor(),
        request_context=request_context,
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
        middlewares=[PassThroughMiddleware()],
    )
    permission = await tool.check_permissions({})
    assert permission.behavior is PermissionBehavior.ALLOW

    stream = await tool()
    chunks = [chunk async for chunk in stream]

    assert calls == 1
    assert len(chunks) == 1
    assert chunks[0].state is ToolResultState.DENIED
    assert "mutation_permission_denied" in _tool_text(chunks[0])


@pytest.mark.asyncio
async def test_denied_permission_clears_invocation_state(monkeypatch) -> None:
    from agentscope.permission import PermissionBehavior

    _patch_mutation_guard(monkeypatch)
    tool = PolicyGuardedTool(
        _noop,
        governor=None,
        request_context=_member_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    decision = await tool.check_permissions({"token": "secret"})

    assert decision.behavior is PermissionBehavior.DENY
    assert tool._qp_invocation_state.get() is None


@pytest.mark.asyncio
async def test_rejected_ask_clears_state_and_direct_call_cannot_consume_it(
    monkeypatch,
) -> None:
    from agentscope.permission import PermissionBehavior, PermissionDecision
    from qwenpaw.governance.policy import (
        GovernanceAction,
        GovernanceDecision,
    )

    _patch_mutation_guard(monkeypatch)
    captured_params: list[dict] = []

    class Governor:
        workspace_dir = "/tmp"

        @staticmethod
        def assert_policy(_spec):
            return GovernanceDecision(GovernanceAction.ASK, "ask")

        @staticmethod
        def audit(*_args, **_kwargs):
            return None

    async def operation(value: str) -> ToolChunk:
        return ToolChunk(
            state=ToolResultState.DENIED,
            metadata={"sandbox_violation": "blocked"},
            content=[TextBlock(text="Sandbox violation: blocked")],
        )

    async def reject(*, tc_spec, **_kwargs):
        captured_params.append(dict(tc_spec.raw_params))
        return PermissionDecision(
            behavior=PermissionBehavior.DENY,
            message="rejected",
        )

    monkeypatch.setattr(tool_adapter, "_ask_user_approval", reject)
    tool = PolicyGuardedTool(
        operation,
        governor=Governor(),
        request_context=_admin_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    decision = await tool.check_permissions({"value": "stale-secret"})
    assert decision.behavior is PermissionBehavior.DENY
    assert tool._qp_invocation_state.get() is None

    await tool(value="fresh")

    assert captured_params == [{"value": "stale-secret"}]


@pytest.mark.parametrize("failure", ["error", "cancel"])
@pytest.mark.asyncio
async def test_permission_exception_or_cancel_clears_invocation_state(
    monkeypatch,
    failure,
) -> None:
    from qwenpaw.governance.policy import GovernanceAction, GovernanceDecision

    _patch_mutation_guard(monkeypatch)

    class Governor:
        workspace_dir = "/tmp"

        @staticmethod
        def assert_policy(_spec):
            if failure == "error":
                raise RuntimeError("boom")
            return GovernanceDecision(GovernanceAction.ASK, "ask")

        @staticmethod
        def audit(*_args, **_kwargs):
            return None

    async def cancel(**_kwargs):
        raise asyncio.CancelledError

    if failure == "cancel":
        monkeypatch.setattr(tool_adapter, "_ask_user_approval", cancel)
    tool = PolicyGuardedTool(
        _noop,
        governor=Governor(),
        request_context=_admin_request_context(),
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    expected = RuntimeError if failure == "error" else asyncio.CancelledError
    with pytest.raises(expected):
        await tool.check_permissions({"token": "secret"})

    assert tool._qp_invocation_state.get() is None


@pytest.mark.asyncio
async def test_sandbox_retry_reauthorizes_before_second_execution(monkeypatch):
    from agentscope.permission import PermissionBehavior, PermissionDecision
    from qwenpaw.governance.policy import (
        GovernanceAction,
        GovernanceDecision,
    )

    _patch_mutation_guard(monkeypatch)
    calls = 0
    request_context = _admin_request_context()

    async def sandboxed_mutation(sandbox_config=None) -> ToolChunk:
        del sandbox_config
        nonlocal calls
        calls += 1
        return ToolChunk(
            state=ToolResultState.DENIED,
            metadata={"sandbox_violation": "blocked"},
            content=[TextBlock(text="Sandbox violation: blocked")],
        )

    sandbox = object()

    class Governor:
        workspace_dir = "/tmp"

        @staticmethod
        def assert_policy(_spec):
            return GovernanceDecision(
                GovernanceAction.SANDBOX_FALLBACK,
                "sandbox",
                sandbox_config=sandbox,
            )

        @staticmethod
        def audit(*_args, **_kwargs):
            return None

    tool = PolicyGuardedTool(
        sandboxed_mutation,
        governor=Governor(),
        request_context=request_context,
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    async def approve_then_remove_privilege(**_kwargs):
        request_context["request_principal"] = _member_request_context()[
            "request_principal"
        ]
        return PermissionDecision(
            behavior=PermissionBehavior.ALLOW,
            message="approved",
        )

    monkeypatch.setattr(
        tool_adapter, "_ask_user_approval", approve_then_remove_privilege
    )

    permission = await tool.check_permissions({})
    assert permission.behavior is PermissionBehavior.ALLOW
    result = await tool()

    assert calls == 1
    assert result.state is ToolResultState.DENIED
    assert "mutation_permission_denied" in _tool_text(result)


@pytest.mark.asyncio
async def test_toolkit_call_tool_cannot_bypass_final_gate(monkeypatch):
    _patch_mutation_guard(monkeypatch)
    calls = 0

    async def mutate(value: str = "") -> str:
        nonlocal calls
        calls += 1
        return value

    toolkit = Toolkit(
        tools=[
            GuardedFunctionTool(
                mutate,
                request_context=_member_request_context(),
                effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            ),
        ],
    )
    chunks = [
        chunk
        async for chunk in toolkit.call_tool(
            ToolCallBlock(
                id="call-1",
                name="mutate",
                input=json.dumps({"value": "secret"}),
            ),
            AgentState(),
        )
    ]

    assert calls == 0
    assert any(
        isinstance(chunk, ToolChunk) and chunk.state is ToolResultState.DENIED
        for chunk in chunks
    )


@pytest.mark.asyncio
async def test_run_tool_batch_cannot_bypass_nested_tool_gate(monkeypatch):
    from qwenpaw.agents.tools.run_tool_batch import run_tool_batch
    from qwenpaw.config.context import (
        set_current_agent_state,
        set_current_toolkit,
    )

    _patch_mutation_guard(monkeypatch)
    calls = 0

    async def mutate(value: str = "") -> str:
        nonlocal calls
        calls += 1
        return value

    toolkit = Toolkit(
        tools=[
            PolicyGuardedTool(
                mutate,
                request_context=_member_request_context(),
                effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
            ),
        ],
    )
    set_current_toolkit(toolkit)
    set_current_agent_state(AgentState())
    try:
        result = await run_tool_batch(
            actions=[
                {
                    "tool_name": "mutate",
                    "arguments": {"value": "do not execute"},
                },
            ],
        )
    finally:
        set_current_agent_state(None)
        set_current_toolkit(None)

    assert calls == 0
    assert "mutation_permission_denied" in _tool_text(result)


@pytest.mark.asyncio
async def test_malformed_principal_denies_and_audits_without_crashing(
    monkeypatch,
    caplog,
):
    _patch_mutation_guard(monkeypatch)

    async def mutate(api_token: str = "") -> str:
        return api_token

    request_context = {
        "request_principal": "not-a-dict",
        "agent_id": "agent-7",
        "session_id": "session-9",
        "channel": "console",
    }
    tool = GuardedFunctionTool(
        mutate,
        request_context=request_context,
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    with caplog.at_level(
        logging.INFO,
        logger="qwenpaw.security.mutation_guard.audit",
    ):
        result = await tool(api_token="super-secret-token")

    assert result.state is ToolResultState.DENIED
    audit = next(
        record.message
        for record in caplog.records
        if "[MUTATION AUDIT]" in record.message
    )
    payload = json.loads(audit.split("] ", 1)[1])
    assert payload == {
        "agent_id": "agent-7",
        "channel": "console",
        "decision": "deny",
        "event": "tool_denied",
        "reason": "effect_mutate_requires_privileged_role",
        "roles": [],
        "session_id": "session-9",
        "source": "",
        "tool": "mutate",
        "user_id": "",
    }
    assert "super-secret-token" not in audit


@pytest.mark.asyncio
async def test_permission_precheck_handles_malformed_principal(monkeypatch):
    from agentscope.permission import PermissionBehavior

    _patch_mutation_guard(monkeypatch)
    tool = PolicyGuardedTool(
        _noop,
        governor=None,
        request_context={"request_principal": ["malformed"]},
        effect_spec=ToolEffectSpec(default=ActionEffect.MUTATE),
    )

    decision = await tool.check_permissions({})

    assert decision.behavior is PermissionBehavior.DENY
    assert "mutation_permission_denied" in decision.message
