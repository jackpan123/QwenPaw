# -*- coding: utf-8 -*-
"""HMAC-signed internal principal credential unit tests."""

from __future__ import annotations

import json

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


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [("r", ["root"]), ("u", "root"), ("s", "local")],
)
def test_internal_principal_not_forged_into_elevated_role(
    field,
    forged_value,
):
    """A member credential cannot be verified as an admin even by
    tampering — the HMAC must cover user_id, roles and source.

    The payload is rewritten to claim elevation and re-attached to the
    original signature, which is what an attacker holding a member
    credential can actually do. (Flipping the credential's last character
    does NOT work as a tamper test: the signature is 32 bytes in 43
    base64 chars, so the final char carries 2 redundant bits and ~5% of
    flips decode to the very same signature.)
    """
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child",
        now=100,
    )
    encoded, signature = credential.split(".")
    body = json.loads(internal_auth._b64decode(encoded))
    body[field] = forged_value
    forged = (
        internal_auth._b64encode(
            json.dumps(body, sort_keys=True).encode("utf-8"),
        )
        + "."
        + signature
    )

    assert (
        internal_auth.verify_internal_principal(
            forged,
            target_agent_id="child",
            now=101,
        )
        is None
    )


def test_internal_principal_rejects_signature_tampering():
    """A modified signature must not verify.

    The first signature character is flipped: unlike the last one it has
    no redundant bits, so the decoded signature always changes.
    """
    credential = internal_auth.mint_internal_principal(
        MEMBER_PRINCIPAL,
        target_agent_id="child",
        now=100,
    )
    encoded, signature = credential.split(".")
    flipped = ("A" if signature[0] != "A" else "B") + signature[1:]

    assert (
        internal_auth.verify_internal_principal(
            f"{encoded}.{flipped}",
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
