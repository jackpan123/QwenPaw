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
    ("source", "roles"),
    [
        pytest.param("external", [], id="legacy-default"),
        pytest.param(" External ", ["member"], id="external-member"),
        pytest.param("custom-sso", ["admin"], id="custom-admin"),
    ],
)
def test_non_nocobase_sources_preserve_legacy_mutation_access(source, roles):
    principal = build_request_principal(
        user_id="legacy-user",
        roles=roles,
        source=source,
        auth_enabled=True,
        config=MutationGuardConfig(),
    )

    assert principal.guarded is False
    assert principal.can_mutate is True


def test_nocobase_source_is_case_insensitive_and_trimmed():
    principal = build_request_principal(
        user_id="member-1",
        roles=["member"],
        source=" NoCoBaSe ",
        auth_enabled=True,
        config=MutationGuardConfig(),
    )

    assert principal.guarded is True
    assert principal.can_mutate is False


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


@pytest.mark.parametrize(
    "effect",
    [
        ActionEffect.MUTATE,
        ActionEffect.EXTERNAL_SIDE_EFFECT,
        ActionEffect.UNKNOWN,
    ],
)
def test_denied_effect_reason_identifies_effect(effect):
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

    assert decision.reason == (
        f"effect_{effect.value}_requires_privileged_role"
    )


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


@pytest.mark.parametrize(
    "context",
    [
        pytest.param(
            UserDict(
                {
                    "user_id": "admin-1",
                    "roles": ["admin"],
                    "guarded": True,
                    "can_mutate": True,
                },
            ),
            id="user-dict",
        ),
        pytest.param("invalid-context", id="string"),
        pytest.param([], id="list"),
        pytest.param(object(), id="object"),
    ],
)
def test_non_builtin_dict_context_denies_mutation(context):
    principal = RequestPrincipal.from_context(context)

    decision = authorize_effect(
        principal,
        ActionEffect.MUTATE,
        MutationGuardConfig(),
    )

    assert principal == RequestPrincipal(
        guarded=True,
        can_mutate=False,
    )
    assert decision.allowed is False


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


@pytest.mark.parametrize(
    "context",
    [
        {},
        {
            "user_id": "member",
            "roles": ["member"],
            "can_mutate": False,
        },
        {
            "user_id": "member",
            "roles": ["member"],
            "guarded": "true",
            "can_mutate": True,
        },
        {
            "user_id": "member",
            "roles": ["member"],
            "guarded": 1,
            "can_mutate": True,
        },
    ],
)
def test_malformed_context_denies_mutation(context):
    principal = RequestPrincipal.from_context(context)

    decision = authorize_effect(
        principal,
        ActionEffect.MUTATE,
        MutationGuardConfig(),
    )

    assert principal.guarded is True
    assert principal.can_mutate is False
    assert decision.allowed is False


def test_inconsistent_unguarded_principal_denies_mutation():
    principal = RequestPrincipal(guarded=False, can_mutate=False)

    decision = authorize_effect(
        principal,
        ActionEffect.MUTATE,
        MutationGuardConfig(),
    )

    assert decision.allowed is False


def test_explicit_unguarded_local_context_can_mutate():
    principal = RequestPrincipal.from_context(
        {
            "guarded": False,
            "can_mutate": True,
        },
    )

    assert authorize_effect(
        principal,
        ActionEffect.MUTATE,
        MutationGuardConfig(),
    ).allowed


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


def _rendered_audit(mock_info) -> str:
    fmt, *args = mock_info.call_args.args
    return fmt % tuple(args)


def _audit_payload(mock_info) -> dict:
    rendered = _rendered_audit(mock_info)
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


def test_audit_redacts_extended_sensitive_keys():
    secrets = {
        "api_key": "api-key-value",
        "apikey": "apikey-value",
        "password": "password-value",
        "passwd": "passwd-value",
        "credential": "credential-value",
    }
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit(
            "authorization",
            summary=secrets,
        )

    rendered = _rendered_audit(mock_info)
    assert rendered.count("[REDACTED]") == len(secrets)
    for secret in secrets.values():
        assert secret not in rendered


def test_audit_scrubs_credentials_from_all_free_text():
    secrets = {
        "event": "EVENTSECRET",
        "reason": "REASONSECRET",
        "api_key": "APISECRET",
        "password": "PASSWORDSECRET",
        "authorization": "AUTHSECRET",
    }
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit(
            f"access Bearer {secrets['event']}",
            reason=f"token={secrets['reason']} keep-reason",
            summary=[
                f"api_key: {secrets['api_key']}",
                {"note": f"password={secrets['password']}"},
                f"authorization: {secrets['authorization']}",
                "token documentation remains useful",
            ],
        )

    rendered = _rendered_audit(mock_info)
    for secret in secrets.values():
        assert secret not in rendered
    payload = _audit_payload(mock_info)
    assert payload["event"] == "[REDACTED]"
    assert payload["reason"] == "[REDACTED]"
    assert "token documentation remains useful" in rendered


@pytest.mark.parametrize(
    ("credential_text", "secret"),
    [
        ('token="QUOTED-TOKEN"', "QUOTED-TOKEN"),
        ("api_key='QUOTED-API-KEY'", "QUOTED-API-KEY"),
        (
            "authorization: Basic BASIC-CREDENTIAL",
            "BASIC-CREDENTIAL",
        ),
        ("access_token=ACCESS-TOKEN", "ACCESS-TOKEN"),
        ("client_secret=CLIENT-SECRET", "CLIENT-SECRET"),
    ],
)
def test_audit_scrubs_specific_credential_syntax(
    credential_text,
    secret,
):
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit(
            "authorization",
            reason=f"before {credential_text} after",
        )

    rendered = _rendered_audit(mock_info)
    assert secret not in rendered
    assert _audit_payload(mock_info)["reason"] == "[REDACTED]"


def test_audit_normalizes_hyphenated_sensitive_keys():
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit(
            "authorization",
            summary={
                "api-key": "STRUCTURED-API-KEY",
                "safe": "visible",
            },
        )

    rendered = _rendered_audit(mock_info)
    assert "STRUCTURED-API-KEY" not in rendered
    assert "[REDACTED]" in rendered
    assert "visible" in rendered


@pytest.mark.parametrize(
    ("credential_text", "secret"),
    [
        ('{"token": "JSON-TOKEN"}', "JSON-TOKEN"),
        ("{'api_key': 'JSON-API-KEY'}", "JSON-API-KEY"),
        (
            'authorization: Bearer "QUOTED-BEARER"',
            "QUOTED-BEARER",
        ),
    ],
)
def test_audit_redacts_entire_jsonish_credential_text(
    credential_text,
    secret,
):
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit(
            "authorization",
            reason=credential_text,
        )

    rendered = _rendered_audit(mock_info)
    assert secret not in rendered
    assert _audit_payload(mock_info)["reason"] == "[REDACTED]"


@pytest.mark.parametrize(
    "text",
    [
        "token expired",
        "how to rotate api keys safely",
    ],
)
def test_audit_preserves_non_sensitive_explanations(text):
    with patch.object(audit_logger, "info") as mock_info:
        emit_mutation_audit(
            "authorization",
            reason=text,
        )

    assert _audit_payload(mock_info)["reason"] == text
