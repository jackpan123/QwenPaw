# -*- coding: utf-8 -*-
"""Tests for mutation authorization policy and audit logging."""

from __future__ import annotations

import json
from collections import UserDict
from unittest.mock import patch

import pytest

from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.security.mutation_guard import (
    ActionEffect,
    RequestPrincipal,
    authorize_effect,
    build_request_principal,
    emit_mutation_audit,
)
from qwenpaw.security.mutation_guard.audit import logger as audit_logger


@pytest.mark.parametrize("role", ["admin", "ADMIN", "Root", " root "])
def test_privileged_roles_are_case_insensitive_and_trimmed(role):
    principal = build_request_principal(
        user_id="user-1",
        roles=[role],
        source="nocobase",
        auth_enabled=True,
        config=MutationGuardConfig(),
    )

    assert principal.guarded is True
    assert principal.can_mutate is True


@pytest.mark.parametrize(
    ("effect", "allowed"),
    [
        (ActionEffect.READ, True),
        (ActionEffect.MUTATE, False),
        (ActionEffect.EXTERNAL_SIDE_EFFECT, False),
        (ActionEffect.UNKNOWN, False),
    ],
)
def test_nocobase_member_can_only_read(effect, allowed):
    principal = build_request_principal(
        user_id="member-1",
        roles=["member"],
        source="nocobase",
        auth_enabled=True,
        config=MutationGuardConfig(),
    )

    decision = authorize_effect(
        principal,
        effect,
        MutationGuardConfig(),
    )

    assert decision.allowed is allowed
    assert isinstance(decision.reason, str)
    assert decision.reason


def test_nocobase_member_can_use_chat_infrastructure():
    principal = build_request_principal(
        user_id="member-1",
        roles=["member"],
        source="nocobase",
        auth_enabled=True,
        config=MutationGuardConfig(),
    )

    decision = authorize_effect(
        principal,
        ActionEffect.CHAT_INFRASTRUCTURE,
        MutationGuardConfig(),
    )

    assert decision.allowed is True


def test_disabled_auth_preserves_local_operator_mutation_access():
    principal = build_request_principal(
        user_id="local-operator",
        roles=[],
        source="console",
        auth_enabled=False,
        config=MutationGuardConfig(),
    )

    assert principal.guarded is False
    assert principal.can_mutate is True
    assert authorize_effect(
        principal,
        ActionEffect.MUTATE,
        MutationGuardConfig(),
    ).allowed


def test_generator_roles_are_materialized_once():
    roles = (role for role in ["member", " ADMIN "])

    principal = build_request_principal(
        user_id="user-1",
        roles=roles,
        source="nocobase",
        auth_enabled=True,
        config=MutationGuardConfig(),
    )

    assert principal.roles == ("member", " ADMIN ")
    assert principal.can_mutate is True


def test_context_roles_string_is_not_split_into_characters():
    principal = RequestPrincipal.from_context(
        {
            "user_id": "member-1",
            "roles": "admin",
            "source": "nocobase",
            "guarded": True,
            "can_mutate": False,
        },
    )

    assert principal.roles == ()
    assert principal.guarded is True
    assert principal.can_mutate is False


def test_context_rejects_non_builtin_dict_mapping():
    principal = RequestPrincipal.from_context(
        UserDict(
            {
                "user_id": "admin-1",
                "roles": ["admin"],
                "guarded": True,
                "can_mutate": True,
            },
        ),
    )

    assert principal == RequestPrincipal()


def test_guarded_context_missing_can_mutate_fails_closed():
    principal = RequestPrincipal.from_context(
        {
            "user_id": "member",
            "roles": ["member"],
            "guarded": True,
        },
    )

    assert principal.can_mutate is False


@pytest.mark.parametrize("can_mutate", ["true", 1])
def test_context_invalid_can_mutate_fails_closed(can_mutate):
    principal = RequestPrincipal.from_context(
        {
            "user_id": "member",
            "roles": ["member"],
            "guarded": True,
            "can_mutate": can_mutate,
        },
    )

    assert principal.can_mutate is False


@pytest.mark.parametrize("roles", [["member", "admin"], ("member", "admin")])
def test_context_roles_accept_only_list_or_tuple(roles):
    principal = RequestPrincipal.from_context(
        {
            "user_id": "member-1",
            "roles": roles,
            "source": "nocobase",
            "guarded": True,
            "can_mutate": True,
        },
    )

    assert principal.roles == ("member", "admin")


def test_missing_context_preserves_current_unguarded_behavior():
    principal = RequestPrincipal.from_context(None)

    assert principal == RequestPrincipal()
    assert principal.guarded is False
    assert principal.can_mutate is True
    assert authorize_effect(
        principal,
        ActionEffect.MUTATE,
        MutationGuardConfig(),
    ).allowed


def _audit_payload(mock_info) -> dict:
    fmt, *args = mock_info.call_args.args
    rendered = fmt % tuple(args)
    _, _, payload = rendered.partition("] ")
    return json.loads(payload)


def test_audit_allows_known_fields_and_drops_unknown_fields():
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit(
            "authorization",
            user_id="member-1",
            roles=["member"],
            source="nocobase",
            route="/api/orders",
            decision="deny",
            unknown_field="must-not-appear",
        )

    payload = _audit_payload(mock_info)
    assert payload == {
        "event": "authorization",
        "user_id": "member-1",
        "roles": ["member"],
        "source": "nocobase",
        "route": "/api/orders",
        "decision": "deny",
    }


def test_audit_truncates_summary():
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit("authorization", summary="x" * 1000)

    summary = _audit_payload(mock_info)["summary"]
    assert len(summary) <= 256
    assert summary.endswith("...")


def test_audit_redacts_sensitive_fields_without_leaking_values():
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit(
            "authorization",
            summary={
                "access_token": "token-value",
                "client_secret": "secret-value",
                "Authorization": "Bearer credential-value",
                "safe": "visible",
            },
        )

    rendered = json.dumps(_audit_payload(mock_info), ensure_ascii=False)
    assert rendered.count("[REDACTED]") == 3
    assert "token-value" not in rendered
    assert "secret-value" not in rendered
    assert "credential-value" not in rendered
    assert "visible" in rendered
