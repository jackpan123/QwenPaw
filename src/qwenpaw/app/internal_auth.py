# -*- coding: utf-8 -*-
"""HMAC-signed, target-bound short-lived credential for in-process agent calls.

When a parent agent calls another agent's HTTP endpoint (subagent spawn,
background task, inter-agent chat) the request must carry the *original*
user's authorization identity — but NEVER the user's NocoBase bearer
token, which must not be forwarded to model/tool layers. This module
mints a short-lived, tamper-evident credential that carries only the
identity (user_id + roles + source) bound to one target agent, signed
with a process-local key.

Security properties
-------------------
* Target-bound: a credential minted for agent ``child-A`` is rejected
  when presented to agent ``child-B`` (verified against ``X-Agent-Id``).
* Short-lived: default TTL is 30 seconds.
* Tamper-evident: HMAC-SHA256 over the canonical payload, verified with
  :func:`hmac.compare_digest`.
* Capability bits are NEVER trusted: ``guarded``/``can_mutate`` are
  recomputed from the current ``MutationGuardConfig`` on verification.
* The credential and the NocoBase token are never logged.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Optional

from ..config.config import MutationGuardConfig
from ..security.mutation_guard import (
    RequestPrincipal,
    build_request_principal,
)

logger = logging.getLogger(__name__)

# Public header name. Stable; part of the wire contract.
INTERNAL_PRINCIPAL_HEADER = "X-QwenPaw-Internal-Principal"

_CREDENTIAL_VERSION = 1
_CREDENTIAL_PURPOSE = "qwenpaw.internal_principal.v1"
DEFAULT_TTL_SECONDS = 30

# A process-local 256-bit key. New on every process start, so a
# credential is useless after a restart (and is never shared with any
# other process or host). This is deliberate: the credential is only
# ever minted+verified inside one QwenPaw process.
_SECRET_KEY = secrets.token_bytes(32)


def _load_mutation_config() -> MutationGuardConfig:
    """Load the current MutationGuardConfig (cached on the hot path).

    Indirected through a module function so unit tests can pin it.
    """
    from .auth import _get_config_cached

    config, _ = _get_config_cached()
    return config.security.mutation_guard


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _canonical_message(
    *,
    version: int,
    purpose: str,
    user_id: str,
    roles: tuple[str, ...],
    source: str,
    target_agent_id: str,
    issued_at: int,
    expires_at: int,
    nonce: str,
) -> bytes:
    """Build the exact bytes the HMAC covers.

    JSON with sorted keys gives a stable canonical form; the target
    agent and expiry are included so a credential cannot be replayed on
    a different agent or past its TTL.
    """
    payload = {
        "v": version,
        "p": purpose,
        "u": user_id,
        "r": list(roles),
        "s": source,
        "t": target_agent_id,
        "iat": issued_at,
        "exp": expires_at,
        "n": nonce,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8",
    )


def _sign(message: bytes) -> bytes:
    return hmac.new(_SECRET_KEY, message, hashlib.sha256).digest()


def mint_internal_principal(
    principal: RequestPrincipal,
    *,
    target_agent_id: str,
    now: Optional[float] = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """Mint a signed, target-bound credential for *principal*.

    The credential carries ONLY identity fields (user_id, roles, source)
    plus the target agent and expiry. Capability bits (``guarded`` /
    ``can_mutate``) are intentionally omitted — they are recomputed from
    the current config at verification time, so they can never be
    elevated by a client.
    """
    issued_at = int(now if now is not None else time.time())
    expires_at = issued_at + int(ttl_seconds)
    nonce = _b64encode(os.urandom(12))
    message = _canonical_message(
        version=_CREDENTIAL_VERSION,
        purpose=_CREDENTIAL_PURPOSE,
        user_id=principal.user_id,
        roles=tuple(principal.roles),
        source=principal.source,
        target_agent_id=target_agent_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
    )
    signature = _sign(message)
    body = {
        "v": _CREDENTIAL_VERSION,
        "p": _CREDENTIAL_PURPOSE,
        "u": principal.user_id,
        "r": list(principal.roles),
        "s": principal.source,
        "t": target_agent_id,
        "iat": issued_at,
        "exp": expires_at,
        "n": nonce,
    }
    encoded = _b64encode(json.dumps(body, sort_keys=True).encode("utf-8"))
    return f"{encoded}.{_b64encode(signature)}"


def verify_internal_principal(
    credential: str,
    *,
    target_agent_id: str,
    now: Optional[float] = None,
) -> Optional[RequestPrincipal]:
    """Verify *credential* and return the recomputed principal.

    Returns ``None`` on any failure: bad format, wrong version, wrong
    target agent, expired TTL, or a signature mismatch. The returned
    principal has ``guarded``/``can_mutate`` recomputed from the current
    ``MutationGuardConfig`` — capability bits are never trusted.
    """
    if not isinstance(credential, str) or "." not in credential:
        return None
    encoded_body, encoded_sig = credential.rsplit(".", 1)
    try:
        body_bytes = _b64decode(encoded_body)
        provided_sig = _b64decode(encoded_sig)
    except (ValueError, TypeError):
        return None
    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(body, dict):
        return None
    if body.get("v") != _CREDENTIAL_VERSION:
        return None
    if body.get("p") != _CREDENTIAL_PURPOSE:
        return None

    issued_at = body.get("iat")
    expires_at = body.get("exp")
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        return None
    current = int(now if now is not None else time.time())
    if current < issued_at or current >= expires_at:
        return None

    cred_target = body.get("t")
    if not isinstance(cred_target, str) or cred_target != target_agent_id:
        return None

    user_id = body.get("u")
    source = body.get("s")
    raw_roles = body.get("r")
    nonce = body.get("n")
    if not isinstance(user_id, str) or not isinstance(source, str):
        return None
    if not isinstance(raw_roles, list) or not all(
        isinstance(r, str) for r in raw_roles
    ):
        return None
    if not isinstance(nonce, str) or not nonce:
        return None

    message = _canonical_message(
        version=_CREDENTIAL_VERSION,
        purpose=_CREDENTIAL_PURPOSE,
        user_id=user_id,
        roles=tuple(raw_roles),
        source=source,
        target_agent_id=target_agent_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
    )
    expected_sig = _sign(message)
    if not hmac.compare_digest(expected_sig, provided_sig):
        return None

    # Capability bits are recomputed from the CURRENT config: never
    # trust what was carried in the credential body. A member stays
    # read-only even if the signer was somehow compromised.
    config = _load_mutation_config()
    return build_request_principal(
        user_id=user_id,
        roles=tuple(raw_roles),
        source=source,
        auth_enabled=True,
        config=config,
    )


__all__ = [
    "DEFAULT_TTL_SECONDS",
    "INTERNAL_PRINCIPAL_HEADER",
    "mint_internal_principal",
    "verify_internal_principal",
]
