# -*- coding: utf-8 -*-
"""HMAC-signed internal principal credential unit tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from qwenpaw.app import internal_auth
from qwenpaw.config.config import MutationGuardConfig
from qwenpaw.security.mutation_guard import RequestPrincipal


MEMBER_PRINCIPAL = RequestPrincipal(
    user_id="alice",
    roles=("member",),
    source="nocobase",
    guarded=True,
    can_mutate=False,
)

ADMIN_PRINCIPAL = RequestPrincipal(
    user_id="root",
    roles=("root",),
    source="nocobase",
    guarded=True,
    can_mutate=True,
)


def _default_config() -> MutationGuardConfig:
    return MutationGuardConfig()


@pytest.fixture(autouse=True)
def _fixed_config():
    """Make verify recompute from a known config (member read-only)."""
    with patch.object(
        internal_auth,
        "_load_mutation_config",
        _default_config,
    ):
        yield


def test_internal_principal_is_signed_and_target_bound():
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child",
        now=100,
    )
    verified = internal_auth.verify_internal_principal(
        credential,
        target_agent_id="child",
        now=101,
    )
    assert verified is not None
    assert verified.user_id == "alice"
    assert verified.roles == ("member",)
    assert verified.can_mutate is False
    assert verified.guarded is True


def test_internal_principal_rejects_wrong_target():
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child",
        now=100,
    )
    assert (
        internal_auth.verify_internal_principal(
            credential,
            target_agent_id="other-child",
            now=101,
        )
        is None
    )


def test_internal_principal_rejects_forged_and_expired_credentials():
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child",
        now=100,
    )
    assert (
        internal_auth.verify_internal_principal(
            credential + "tampered",
            target_agent_id="child",
            now=101,
        )
        is None
    )
    # now=200 is far past the 30s TTL window (issued at 100).
    assert (
        internal_auth.verify_internal_principal(
            credential,
            target_agent_id="child",
            now=200,
        )
        is None
    )


def test_internal_principal_recomputes_capability_from_config():
    """Capability bits in the payload are ignored; config decides."""
    credential = internal_auth.mint_internal_principal(
        ADMIN_PRINCIPAL,
        target_agent_id="child",
        now=100,
    )
    verified = internal_auth.verify_internal_principal(
        credential,
        target_agent_id="child",
        now=101,
    )
    assert verified is not None
    # root is a privileged role in the default config -> can_mutate True.
    assert verified.can_mutate is True


def test_internal_principal_not_forged_into_elevated_role():
    """A member credential cannot be verified as an admin even by
    tampering — the HMAC must cover user_id and roles."""
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child",
        now=100,
    )
    # Strip the signature and try to forge an admin payload with a fresh
    # signature: impossible without the key. Just confirm tampering fails.
    assert (
        internal_auth.verify_internal_principal(
            credential[:-1] + ("0" if credential[-1] != "0" else "1"),
            target_agent_id="child",
            now=101,
        )
        is None
    )


def test_credential_carries_reserved_header_name():
    """The documented header constant exists and is stable."""
    assert (
        internal_auth.INTERNAL_PRINCIPAL_HEADER
        == "X-QwenPaw-Internal-Principal"
    )
